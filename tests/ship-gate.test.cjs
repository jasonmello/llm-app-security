'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { run } = require('../skills/jason/scripts/ship-gate.cjs');

// The gate treats a CI environment differently (no-git fallback); tests control it explicitly.
delete process.env.CI;

const EXAMPLE = path.join(__dirname, '..', 'examples', 'vulnerable-vibe-app');
const TODAY = '2026-11-15';
// Fake credentials are assembled at runtime so secret scanners do not flag this file.
const FAKE = {
  stripe: ['sk', 'live', 'Zq9Rt2Lm8Vb4Nc7Xw1Ks5Hd3'].join('_'),
  aws: 'AK' + 'IA' + 'QWERTYUIOPASDFGH',
  serviceRole: () => {
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    return `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', role: 'service' + '_role', iat: 1 })}.c2lnbmF0dXJlc2lnbmF0dXJl`;
  },
};

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'sg-')); }
function write(root, rel, text) {
  fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  fs.writeFileSync(path.join(root, rel), text);
}
const checks = (res) => res.items.filter((i) => i.level === 'block' && !i.waived).map((i) => i.check);

// A corrected copy of the example app: same features, blockers fixed.
function fixedApp() {
  const root = tmp();
  fs.cpSync(EXAMPLE, root, { recursive: true });
  write(root, '.gitignore', '.env*\n!.env.example\n');
  write(root, '.env', 'OPENAI_API_KEY=sk-EXAMPLE-NOT-A-REAL-KEY-0000\nDATABASE_URL=postgres://app:EXAMPLE_PASSWORD@db.example.invalid:5432/app\n');
  write(root, 'src/chat.jsx', "export async function ask(q) { return fetch('/api/chat', { method: 'POST', body: JSON.stringify({ q }) }); }\n");
  write(root, 'supabase/migrations/001_init.sql', [
    'create table profiles (id uuid primary key, email text);',
    'create table invoices (id uuid primary key, user_id uuid, total numeric);',
    'alter table profiles enable row level security;',
    'alter table invoices enable row level security;',
    'create policy "own invoices" on invoices for select using (auth.uid() = user_id);',
  ].join('\n'));
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  pkg.dependencies['express-rate-limit'] = '^7.0.0';
  delete pkg.dependencies['expresss-validator-pro'];
  write(root, 'package.json', JSON.stringify(pkg, null, 2));
  return root;
}

test('ship-gate blocks the vulnerable example app', () => {
  const res = run(EXAMPLE, { today: TODAY });
  assert.strictEqual(res.passed, false);
  const c = checks(res);
  for (const id of ['SG-SECRET-PUBLIC-ENV', 'SG-DB-NO-RLS', 'SG-DB-OPEN-POLICY', 'SG-RATE-LIMIT']) assert.ok(c.includes(id), id);
  assert.ok(!c.includes('SG-SECRET-VALUE'), 'placeholder values are not reported as live secrets');
});

test('ship-gate passes the fixed app', () => {
  const res = run(fixedApp(), { today: TODAY });
  assert.deepStrictEqual(checks(res), []);
  assert.strictEqual(res.passed, true);
});

test('live secrets block, including in build output and service_role JWTs; never printed in full', () => {
  const root = fixedApp();
  write(root, 'dist/assets/index.js', `const k="${FAKE.stripe}";`);
  write(root, 'src/admin.js', `const key = "${FAKE.serviceRole()}";\nconst aws = "${FAKE.aws}";`);
  const res = run(root, { today: TODAY });
  const secrets = res.items.filter((i) => i.check === 'SG-SECRET-VALUE');
  assert.ok(secrets.some((i) => /Stripe/.test(i.message) && /build output/.test(i.message)));
  assert.ok(secrets.some((i) => /service_role/.test(i.message)));
  assert.ok(secrets.some((i) => /AWS/.test(i.message)));
  const out = JSON.stringify(res);
  assert.ok(!out.includes(FAKE.stripe) && !out.includes(FAKE.aws), 'values are redacted');
});

test('honeytoken bait listed in the inventory is not reported', () => {
  const root = fixedApp();
  write(root, 'password.txt', `aws_access_key_id = ${FAKE.aws}\n`);
  write(root, 'security/honeytokens.md', '| ID | Type | Bait location | Scope |\n|---|---|---|---|\n| HT-01 | AWS | `password.txt` | local |\n');
  assert.deepStrictEqual(checks(run(root, { today: TODAY })), []);
});

test('Firebase open and test-mode rules block', () => {
  const root = fixedApp();
  write(root, 'firestore.rules', "rules_version = '2';\nservice cloud.firestore { match /databases/{db}/documents {\n  match /tips/{id} { allow read, write: if true; }\n  match /{document=**} { allow read, write: if request.time < timestamp.date(2027, 1, 31); }\n} }\n");
  write(root, 'database.rules.json', '{ "rules": { ".read": true } }');
  const c = checks(run(root, { today: TODAY }));
  assert.strictEqual(c.filter((x) => x === 'SG-DB-OPEN-RULES').length, 3);
});

test('public_tables and a declared edge rate limit are honored', () => {
  const root = fixedApp();
  write(root, 'supabase/migrations/002_products.sql', 'create table products (id int);\nalter table products enable row level security;\ncreate policy "catalog" on products for select using (true);\n');
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  delete pkg.dependencies['express-rate-limit'];
  write(root, 'package.json', JSON.stringify(pkg));
  let c = checks(run(root, { today: TODAY }));
  assert.ok(c.includes('SG-DB-OPEN-POLICY') && c.includes('SG-RATE-LIMIT'));
  write(root, 'security/ship-gate.json', JSON.stringify({ public_tables: ['products'], rate_limit: { where: 'Cloudflare WAF rule "auth-and-chat" (10 req/min/IP)' } }));
  c = checks(run(root, { today: TODAY }));
  assert.deepStrictEqual(c, []);
});

test('waivers: valid ones waive, expired and unwaivable ones block', () => {
  const root = fixedApp();
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  delete pkg.dependencies['express-rate-limit'];
  write(root, 'package.json', JSON.stringify(pkg));
  write(root, 'security/waivers.json', JSON.stringify({ schema_version: 1, waivers: [
    { check: 'SG-RATE-LIMIT', reason: 'beta behind invite-only access until launch', owner: 'jason', expires: '2026-12-01' },
  ] }));
  let res = run(root, { today: TODAY });
  assert.strictEqual(res.passed, true);
  assert.ok(res.items.some((i) => i.check === 'SG-RATE-LIMIT' && i.waived));

  res = run(root, { today: '2026-12-02' });
  assert.strictEqual(res.passed, false);
  assert.ok(res.items.some((i) => i.check === 'SG-WAIVERS' && /expired/.test(i.message)));

  write(root, 'src/leak.js', `const k = "${FAKE.stripe}";`);
  write(root, 'security/waivers.json', JSON.stringify({ schema_version: 1, waivers: [
    { check: 'SG-SECRET-VALUE', reason: 'later', owner: 'jason', expires: '2026-12-01' },
  ] }));
  res = run(root, { today: TODAY });
  assert.ok(res.items.some((i) => i.check === 'SG-WAIVERS' && /cannot be waived/.test(i.message)));
  assert.ok(checks(res).includes('SG-SECRET-VALUE'));
});

test('confirmed critical/high findings block until fixed or waived by fingerprint', () => {
  const root = fixedApp();
  write(root, 'security/findings.json', JSON.stringify({ schema_version: 2, findings: [
    { id: 'LAS-001', fingerprint: 'idor/server.js/api/orders/:id/GET', status: 'confirmed', severity: 'high', title: 'IDOR on orders', location: [{ file: 'server.js', line: 27 }], fix: 'filter by user_id' },
    { id: 'LAS-002', fingerprint: 'config/server.js/errors', status: 'confirmed', severity: 'medium', title: 'stack traces', location: [{ file: 'server.js' }] },
  ] }));
  let c = checks(run(root, { today: TODAY }));
  assert.deepStrictEqual(c, ['SG-FINDING']);
  write(root, 'security/waivers.json', JSON.stringify({ schema_version: 1, waivers: [
    { check: 'finding:idor/server.js/api/orders/:id/GET', reason: 'orders endpoint disabled behind feature flag', owner: 'jason', expires: '2026-11-30' },
  ] }));
  c = checks(run(root, { today: TODAY }));
  assert.deepStrictEqual(c, []);
});

test('CLI exit codes', () => {
  const { spawnSync } = require('node:child_process');
  const script = path.join(__dirname, '..', 'skills/jason/scripts/ship-gate.cjs');
  assert.strictEqual(spawnSync(process.execPath, [script, EXAMPLE], { encoding: 'utf8' }).status, 1);
  assert.strictEqual(spawnSync(process.execPath, [script, fixedApp()], { encoding: 'utf8' }).status, 0);
  assert.strictEqual(spawnSync(process.execPath, [script, '/nonexistent-dir-xyz'], { encoding: 'utf8' }).status, 2);
});

test('reviewer regressions: unconditional Firebase rule, LLM via helper, authenticated-only policy, view without security_invoker', () => {
  const root = fixedApp();
  write(root, 'storage.rules', "service firebase.storage { match /b/{bucket}/o { match /{all=**} { allow read, write; } } }\n");
  write(root, 'supabase/migrations/002.sql', [
    "create policy \"any user updates\" on invoices for update using (auth.role() = 'authenticated');",
    'create view public.team_usage as select 1;',
    'create view public.safe_view with (security_invoker = true) as select 1;',
  ].join('\n'));
  let res = run(root, { today: TODAY });
  const msgs = res.items.filter((i) => i.level === 'block').map((i) => `${i.check} ${i.message}`).join('\n');
  assert.match(msgs, /SG-DB-OPEN-RULES .*allow read, write;/);
  assert.match(msgs, /SG-DB-OPEN-POLICY .*any signed-in user/);
  assert.match(msgs, /SG-DB-NO-RLS view public\.team_usage/);
  assert.doesNotMatch(msgs, /safe_view/);

  const py = tmp();
  write(py, 'app/main.py', 'from fastapi import FastAPI\nfrom .agent import run_agent\napp = FastAPI()\n@app.post("/chat")\ndef chat(q: str):\n    return run_agent(q)\n');
  write(py, 'app/agent.py', 'from openai import OpenAI\nclient = OpenAI()\n');
  write(py, 'requirements.txt', 'fastapi\nopenai\n');
  res = run(py, { today: TODAY });
  assert.ok(res.items.some((i) => i.check === 'SG-RATE-LIMIT' && /LLM via app\/agent\.py/.test(i.message)));
});

test('no unwaivable false positives on local-dev values; bait env files skipped; ignore_paths still scans secrets', () => {
  const root = fixedApp();
  fs.copyFileSync(path.join(__dirname, '..', 'skills/jason/templates/pr-gates.yml'), path.join(root, 'pr-gates.yml'));
  write(root, 'docker-compose.yml', 'DATABASE_URL: postgres://app:s3cretpass@db:5432/app\n');
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  write(root, 'supabase/seed.env', `KEY=${b64({ alg: 'HS256' })}.${b64({ iss: 'supabase-demo', role: 'service' + '_role' })}.c2lnbmF0dXJlc2lnbmF0dXJl\n`);
  write(root, '.env.backup', 'NEXT_PUBLIC_OPENAI_API_KEY=bait-value-123\n');
  write(root, 'security/honeytokens.md', '| ID | Type | Bait location | Scope |\n|---|---|---|---|\n| HT-01 | URL | `.env.backup` | committed |\n');
  assert.deepStrictEqual(checks(run(root, { today: TODAY })), []);

  write(root, 'fixtures/leak.js', `const k = "${FAKE.stripe}";`);
  write(root, 'security/ship-gate.json', JSON.stringify({ ignore_paths: ['fixtures/'] }));
  const res = run(root, { today: TODAY });
  assert.ok(res.passed, 'ignored path does not block');
  assert.ok(res.items.some((i) => i.check === 'SG-SECRET-VALUE' && i.level === 'warn' && /ignore_paths/.test(i.message)), 'but is still reported');
});

test('rate limit: one item per route so a waiver target narrows it; a TODO comment is not a limiter', () => {
  const root = fixedApp();
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  delete pkg.dependencies['express-rate-limit'];
  write(root, 'package.json', JSON.stringify(pkg));
  write(root, 'app/api/chat/route.ts', "// TODO: add rate limit\nimport OpenAI from 'openai';\nexport async function POST(req: Request) { return new OpenAI().chat.completions.create({} as any); }\n");
  let res = run(root, { today: TODAY });
  const rl = res.items.filter((i) => i.check === 'SG-RATE-LIMIT');
  assert.deepStrictEqual(rl.map((i) => i.file).sort(), ['app/api/chat/route.ts', 'server.js']);
  write(root, 'security/waivers.json', JSON.stringify({ schema_version: 1, waivers: [
    { check: 'SG-RATE-LIMIT', target: 'app/api/chat', reason: 'invite-only beta', owner: 'jason', expires: '2026-12-01' },
  ] }));
  res = run(root, { today: TODAY });
  assert.deepStrictEqual(checks(res), ['SG-RATE-LIMIT'], 'login route still blocks');
  assert.ok(res.items.find((i) => i.file === 'app/api/chat/route.ts').waived);
});

test('waiver dates are validated; far-future waivers warn', () => {
  const root = fixedApp();
  write(root, 'security/waivers.json', JSON.stringify({ schema_version: 1, waivers: [
    { check: 'SG-RATE-LIMIT', reason: 'x', owner: 'y', expires: '2026-02-31' },
    { check: 'SG-DB-NO-RLS', reason: 'x', owner: 'y', expires: '2027-12-31' },
  ] }));
  const res = run(root, { today: TODAY });
  assert.ok(res.items.some((i) => /not a valid YYYY-MM-DD/.test(i.message) && i.level === 'block'));
  assert.ok(res.items.some((i) => /more than 90 days/.test(i.message) && i.level === 'warn'));
});

test('without git metadata in CI, a real .env blocks', () => {
  const root = fixedApp();
  process.env.CI = 'true';
  try {
    assert.ok(checks(run(root, { today: TODAY })).includes('SG-ENV-COMMITTED'));
  } finally {
    delete process.env.CI;
  }
});
