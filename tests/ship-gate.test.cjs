'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { run } = require('../skills/jason/scripts/ship-gate.cjs');
const crypto = require('node:crypto');
const sha = (v) => crypto.createHash('sha256').update(v).digest('hex');

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

test('registered honeytokens: only the exact bait value is exempt', () => {
  const root = fixedApp();
  write(root, 'password.txt', `aws_access_key_id = ${FAKE.aws}\n`);
  write(root, '.jason/gate.json', JSON.stringify({ honeytokens: [sha(FAKE.aws)] }));
  let res = run(root, { today: TODAY });
  assert.deepStrictEqual(checks(res), []);
  assert.ok(res.honeytokens.length === 1, 'exemption is reported');
  write(root, 'password.txt', `aws_access_key_id = ${FAKE.aws}\nstripe = ${FAKE.stripe}\n`);
  res = run(root, { today: TODAY });
  assert.ok(res.items.some((i) => i.check === 'SG-SECRET-VALUE' && /Stripe/.test(i.message)), 'other secrets in a bait file still block');
  write(root, 'security/honeytokens.md', '| ID | Type | Bait location |\n|---|---|---|\n| HT-01 | Stripe | `password.txt` |\n');
  assert.ok(checks(run(root, { today: TODAY })).includes('SG-SECRET-VALUE'), 'the inventory alone exempts nothing');
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
  write(root, '.jason/gate.json', JSON.stringify({ public_tables: ['products'], rate_limit: { where: 'Cloudflare WAF rule "auth-and-chat" (10 req/min/IP)' } }));
  c = checks(run(root, { today: TODAY }));
  assert.deepStrictEqual(c, []);
});

test('waivers: valid ones waive, expired and unwaivable ones block', () => {
  const root = fixedApp();
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  delete pkg.dependencies['express-rate-limit'];
  write(root, 'package.json', JSON.stringify(pkg));
  write(root, '.jason/waivers.json', JSON.stringify({ schema_version: 1, waivers: [
    { check: 'SG-RATE-LIMIT', reason: 'beta behind invite-only access until launch', owner: 'jason', expires: '2026-12-01' },
  ] }));
  let res = run(root, { today: TODAY });
  assert.strictEqual(res.passed, true);
  assert.ok(res.items.some((i) => i.check === 'SG-RATE-LIMIT' && i.waived));

  res = run(root, { today: '2026-12-02' });
  assert.strictEqual(res.passed, false);
  assert.ok(res.items.some((i) => i.check === 'SG-WAIVERS' && /expired/.test(i.message)));

  write(root, 'src/leak.js', `const k = "${FAKE.stripe}";`);
  write(root, '.jason/waivers.json', JSON.stringify({ schema_version: 1, waivers: [
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
  write(root, '.jason/waivers.json', JSON.stringify({ schema_version: 1, waivers: [
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
  write(root, '.jason/gate.json', JSON.stringify({ honeytokens: [sha('bait-value-123')] }));
  assert.deepStrictEqual(checks(run(root, { today: TODAY })), []);

  write(root, 'fixtures/leak.js', `const k = "${FAKE.stripe}";`);
  write(root, '.jason/gate.json', JSON.stringify({ ignore_paths: ['fixtures/'], honeytokens: [sha('bait-value-123')] }));
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
  write(root, '.jason/waivers.json', JSON.stringify({ schema_version: 1, waivers: [
    { check: 'SG-RATE-LIMIT', target: 'app/api/chat', reason: 'invite-only beta', owner: 'jason', expires: '2026-12-01' },
  ] }));
  res = run(root, { today: TODAY });
  assert.deepStrictEqual(checks(res), ['SG-RATE-LIMIT'], 'login route still blocks');
  assert.ok(res.items.find((i) => i.file === 'app/api/chat/route.ts').waived);
});

test('waiver dates are validated; far-future waivers warn', () => {
  const root = fixedApp();
  write(root, '.jason/waivers.json', JSON.stringify({ schema_version: 1, waivers: [
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

test('the gate copied into the app (as documented) does not silence its own checks', () => {
  const root = fixedApp();
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  delete pkg.dependencies['express-rate-limit'];
  write(root, 'package.json', JSON.stringify(pkg));
  const scripts = path.join(__dirname, '..', 'skills/jason/scripts');
  for (const f of ['ship-gate.cjs', 'rls-guard.sh', 'check-honeytokens.cjs', 'validate-findings.cjs']) {
    fs.mkdirSync(path.join(root, 'scripts/ci'), { recursive: true });
    fs.copyFileSync(path.join(scripts, f), path.join(root, 'scripts/ci', f));
  }
  const res = run(root, { today: TODAY });
  assert.deepStrictEqual(checks(res), ['SG-RATE-LIMIT'], 'rate-limit check still fires, nothing from the scripts themselves');
  assert.ok(!res.items.some((i) => (i.file || '').startsWith('scripts/ci/')), 'no findings in the copied scripts');
});

test('the self marker cannot be used to hide a file from the gate', () => {
  const root = fixedApp();
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  delete pkg.dependencies['express-rate-limit'];
  write(root, 'package.json', JSON.stringify(pkg));
  write(root, 'src/ship-gate.cjs', `// J.A.S.O.N. ship-gate\nconst k = "${FAKE.stripe}";\n`);
  const c = checks(run(root, { today: TODAY }));
  assert.ok(c.includes('SG-SECRET-VALUE'), 'secret still found');
  assert.ok(c.includes('SG-RATE-LIMIT'), 'rate-limit check still runs');
});


// ---- self-audit regressions (v0.5.0) ----
test('a placeholder word elsewhere on the line no longer hides a real secret', () => {
  const root = fixedApp();
  write(root, 'src/config.js', `const key = "${FAKE.stripe}"; // EXAMPLE: replace in prod\n`);
  write(root, 'dist/app.min.js', `var placeholder="your-key";var k="${FAKE.stripe}";`);
  const hits = run(root, { today: TODAY }).items.filter((i) => i.check === 'SG-SECRET-VALUE' && i.level === 'block');
  assert.strictEqual(hits.length, 2);
});

test('templates copied as-is never loosen the gate', () => {
  const root = fixedApp();
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  delete pkg.dependencies['express-rate-limit'];
  write(root, 'package.json', JSON.stringify(pkg));
  const tpl = path.join(__dirname, '..', 'skills/jason/templates');
  fs.mkdirSync(path.join(root, '.jason'), { recursive: true });
  fs.copyFileSync(path.join(tpl, 'gate.json'), path.join(root, '.jason/gate.json'));
  fs.copyFileSync(path.join(tpl, 'waivers.json'), path.join(root, '.jason/waivers.json'));
  const c = checks(run(root, { today: TODAY }));
  assert.ok(c.includes('SG-CONFIG'), 'placeholder rate_limit.where blocks');
  assert.ok(c.includes('SG-RATE-LIMIT'), 'and the rate-limit blocker stays');
});

test('rate_limit.covers narrows the declared edge limiter', () => {
  const root = fixedApp();
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  delete pkg.dependencies['express-rate-limit'];
  write(root, 'package.json', JSON.stringify(pkg));
  write(root, 'app/api/chat/route.ts', "import OpenAI from 'openai';\nexport async function POST() { return new OpenAI().chat.completions.create({} as any); }\n");
  write(root, '.jason/gate.json', JSON.stringify({ rate_limit: { where: 'Cloudflare WAF rule auth, 10 req/min per IP', covers: ['server.js'] } }));
  let res = run(root, { today: TODAY });
  assert.deepStrictEqual(res.items.filter((i) => i.check === 'SG-RATE-LIMIT' && i.level === 'block').map((i) => i.file), ['app/api/chat/route.ts']);
  write(root, '.jason/gate.json', JSON.stringify({ rate_limit: { where: 'Cloudflare WAF rule auth, 10 req/min per IP' } }));
  res = run(root, { today: TODAY });
  assert.ok(res.passed);
  assert.strictEqual(res.items.filter((i) => i.check === 'SG-RATE-LIMIT' && i.level === 'warn').length, 2, 'each assumed-covered route is listed');
  assert.ok(res.declarations.length === 1);
});

test('secret scan covers .claude/, vendor/, coverage/ and non-lockfiles named *.lock; NUL text files warn', () => {
  const root = fixedApp();
  for (const f of ['.claude/settings.local.json', 'vendor/lib.js', 'coverage/x.js', 'secrets.lock']) write(root, f, `k="${FAKE.stripe}"\n`);
  fs.writeFileSync(path.join(root, 'utf16.env'), Buffer.from(`﻿KEY=${FAKE.stripe}\n`, 'utf16le'));
  fs.writeFileSync(path.join(root, 'weird.json'), Buffer.from(`{"a":"\u0000","k":"${FAKE.stripe}"}`));
  const res = run(root, { today: TODAY });
  const files = res.items.filter((i) => i.check === 'SG-SECRET-VALUE' && i.level === 'block').map((i) => i.file).sort();
  assert.deepStrictEqual(files, ['.claude/settings.local.json', 'coverage/x.js', 'secrets.lock', 'utf16.env', 'vendor/lib.js', 'weird.json']);
  assert.ok(res.items.some((i) => i.file === 'weird.json' && /NUL bytes/.test(i.message)), 'NUL bytes no longer hide a file');
});

test('RLS: string-literal tricks, drop+recreate, unreadable migrations, materialized views', () => {
  const root = fixedApp();
  write(root, 'supabase/migrations/002.sql', [
    'create table a (id int);',
    "select 'alter table a enable row level security';",
    'create table b (id int); alter table b enable row level security; drop table b; create table b (id int);',
    'create materialized view public.stats as select 1;',
    'create or replace view public.v2 (x) with (security_invoker = true) as select 1;',
  ].join('\n'));
  fs.writeFileSync(path.join(root, 'supabase/migrations/003.sql'), Buffer.from('create table c (id int);\u0000'));
  const res = run(root, { today: TODAY });
  const msgs = res.items.filter((i) => i.check === 'SG-DB-NO-RLS').map((i) => i.message).join('\n');
  assert.match(msgs, /public\.a has no RLS/);
  assert.match(msgs, /public\.b has no RLS/);
  assert.match(msgs, /materialized view public\.stats/);
  assert.match(msgs, /public\.c has no RLS/, 'NUL bytes in a migration do not hide it');
  assert.doesNotMatch(msgs, /v2/);
});

test('waivers: placeholder or bot owners rejected; target is a path prefix, not a substring', () => {
  const root = fixedApp();
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  delete pkg.dependencies['express-rate-limit'];
  write(root, 'package.json', JSON.stringify(pkg));
  write(root, '.jason/waivers.json', JSON.stringify({ schema_version: 1, waivers: [
    { check: 'SG-RATE-LIMIT', reason: 'beta', owner: 'maintainer-name', expires: '2026-12-01' },
  ] }));
  assert.ok(run(root, { today: TODAY }).items.some((i) => /placeholder or a bot/.test(i.message)));
  write(root, '.jason/waivers.json', JSON.stringify({ schema_version: 1, waivers: [
    { check: 'SG-RATE-LIMIT', target: 'server', reason: 'beta', owner: 'jason', expires: '2026-12-01' },
  ] }));
  assert.ok(checks(run(root, { today: TODAY })).includes('SG-RATE-LIMIT'), '"server" does not match server.js');
});

test('legacy security/ config still works but warns to move to .jason/', () => {
  const root = fixedApp();
  write(root, 'security/ship-gate.json', JSON.stringify({ public_tables: [] }));
  const res = run(root, { today: TODAY });
  assert.ok(res.passed);
  assert.ok(res.items.some((i) => i.check === 'SG-CONFIG' && i.level === 'warn' && /old location/.test(i.message)));
});

test('crafted files cannot stall the gate (ReDoS guards)', () => {
  const root = fixedApp();
  write(root, 'src/jwt.txt', 'eyJ'.repeat(200000));
  write(root, 'supabase/migrations/004.sql', '$$'.repeat(100000) + '$a$'.repeat(50000));
  const t0 = Date.now();
  run(root, { today: TODAY });
  assert.ok(Date.now() - t0 < 8000, `took ${Date.now() - t0} ms`);
});


// ---- re-audit regressions (v0.5.0, round 2) ----
test('UTF-16 BOM tricks do not hide secrets (both decodings are scanned)', () => {
  const root = fixedApp();
  fs.writeFileSync(path.join(root, 'notes.txt'), Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`# cfg\nKEY=${FAKE.stripe}\n`)]));
  fs.writeFileSync(path.join(root, 'b.txt'), Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(`# cfg\nKEY=${FAKE.stripe}\n\n`)]));
  const files = run(root, { today: TODAY }).items.filter((i) => i.check === 'SG-SECRET-VALUE' && i.level === 'block').map((i) => i.file).sort();
  assert.deepStrictEqual(files, ['b.txt', 'notes.txt']);
});

test('RLS: rename, multi-table drop, multi-action alter, comment/string tricks, set schema, select into, nested true', () => {
  const cases = {
    rename: 'create table s (id int); alter table s enable row level security; alter table s rename to s_old; create table s (id int);',
    multidrop: 'create table o (id int); create table s (id int); alter table o enable row level security; alter table s enable row level security; drop table o, s; create table s (id int);',
    multiaction: 'create table s (id int); alter table s enable row level security; alter table s add column x int, disable row level security;',
    dashInString: "create table s (id int); alter table s enable row level security; select '--'; alter table s disable row level security; select 'x';",
    setSchema: 'create schema priv; create table priv.s (id int); alter table priv.s set schema public;',
    selectInto: 'create table base (id int); alter table base enable row level security; select * into public.s from base;',
  };
  for (const [k, sql] of Object.entries(cases)) {
    const root = fixedApp();
    write(root, 'supabase/migrations/009.sql', sql);
    assert.ok(run(root, { today: TODAY }).items.some((i) => i.check === 'SG-DB-NO-RLS' && /public\.s has no RLS/.test(i.message)), k);
  }
  const root = fixedApp();
  write(root, 'supabase/migrations/009.sql', [
    'create table s (id int); alter table s enable row level security;',
    'select 1 as "--"; create policy p on s for all using ((true));',
    'create policy p2 on s for select to anon using (true or false);',
  ].join('\n'));
  assert.strictEqual(run(root, { today: TODAY }).items.filter((i) => i.check === 'SG-DB-OPEN-POLICY').length, 2);
});

test('lockfile names are exempt only next to their manifest and outside public/build folders', () => {
  const root = fixedApp();
  write(root, 'public/package-lock.json', `{"k":"${FAKE.stripe}"}`);
  write(root, 'config/yarn.lock', `token: ${FAKE.stripe}`);
  write(root, 'package-lock.json', `{"k":"${FAKE.stripe}"}`); // real lockfile next to package.json: skipped
  const files = run(root, { today: TODAY }).items.filter((i) => i.check === 'SG-SECRET-VALUE' && i.level === 'block').map((i) => i.file).sort();
  assert.deepStrictEqual(files, ['config/yarn.lock', 'public/package-lock.json']);
});

test('legacy security/ waivers and config are ignored (with a warning)', () => {
  const root = fixedApp();
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  delete pkg.dependencies['express-rate-limit'];
  write(root, 'package.json', JSON.stringify(pkg));
  write(root, 'security/waivers.json', JSON.stringify({ schema_version: 1, waivers: [{ check: 'SG-RATE-LIMIT', reason: 'x', owner: 'jason', expires: '2026-12-01' }] }));
  const res = run(root, { today: TODAY });
  assert.ok(checks(res).includes('SG-RATE-LIMIT'), 'legacy waiver not honored');
  assert.ok(res.items.some((i) => i.check === 'SG-CONFIG' && /is ignored/.test(i.message)));
});

test('rate limit: routes under vendor-like subfolders are checked; devDependency or examples/ mention is not evidence; Fastify and Gemini detected', () => {
  const root = fixedApp();
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  delete pkg.dependencies['express-rate-limit'];
  pkg.devDependencies = { [['express', 'rate', 'limit'].join('-')]: '^7' };
  write(root, 'package.json', JSON.stringify(pkg));
  write(root, 'examples/limiter.js', "const rateLimit = require('express-" + "rate-limit'); rateLimit({});");
  write(root, 'app/api/target/route.ts', 'export async function POST() { return Response.json({}); } // /api/login');
  write(root, 'src/server.ts', "fastify.post('/api/signup', async () => ({}));");
  write(root, 'src/ai.ts', "import { GoogleGenAI } from '@google" + "/genai';\nfastify.post('/api/ask', async () => new GoogleGenAI({}).models.generateContent({}));");
  const files = run(root, { today: TODAY }).items.filter((i) => i.check === 'SG-RATE-LIMIT' && i.level === 'block').map((i) => i.file).sort();
  for (const f of ['server.js', 'src/server.ts', 'src/ai.ts']) assert.ok(files.includes(f), f);
});

test('the gate copied into an app with routes but no LLM adds no LLM item', () => {
  const root = fixedApp();
  fs.mkdirSync(path.join(root, 'scripts/ci'), { recursive: true });
  fs.copyFileSync(path.join(__dirname, '..', 'skills/jason/scripts/ship-gate.cjs'), path.join(root, 'scripts/ci/ship-gate.cjs'));
  const res = run(root, { today: TODAY });
  assert.ok(res.passed, JSON.stringify(res.items.filter((i) => i.level === 'block')));
});

test('Firebase: comment markers inside strings, parenthesized true, rules files named in firebase.json', () => {
  const root = fixedApp();
  write(root, 'firebase.json', JSON.stringify({ firestore: { rules: 'config/fs-rules.txt' } }));
  write(root, 'config/fs-rules.txt', "service cloud.firestore { match /databases/{d}/documents {\n match /a/{id} { allow read: if resource.data.url == 'http://x' ; allow write: if (true); }\n match /b/{id} { allow read, write: if ((true)); }\n} }\n");
  assert.ok(run(root, { today: TODAY }).items.filter((i) => i.check === 'SG-DB-OPEN-RULES' && i.level === 'block').length >= 2);
});

test('honeytokens: per-value exemption only; hashes name no files; --honeytoken-hashes prints hashes only', () => {
  const { spawnSync } = require('node:child_process');
  const root = fixedApp();
  write(root, '.env.backup', `AWS_ACCESS_KEY_ID=${FAKE.aws}\nNEXT_PUBLIC_OPENAI_API_KEY=realish-value\n`);
  write(root, '.jason/gate.json', JSON.stringify({ honeytokens: [sha(FAKE.aws)] }));
  const prev = process.env.CI; process.env.CI = 'true';
  try {
    const c = checks(run(root, { today: TODAY }));
    assert.ok(c.includes('SG-SECRET-PUBLIC-ENV'), 'unregistered line still blocks');
    assert.ok(c.includes('SG-ENV-COMMITTED'), 'file with non-bait values is not treated as bait');
  } finally { if (prev === undefined) delete process.env.CI; else process.env.CI = prev; }
  const out = spawnSync(process.execPath, [path.join(__dirname, '..', 'skills/jason/scripts/ship-gate.cjs'), '--honeytoken-hashes', path.join(root, '.env.backup')], { encoding: 'utf8' });
  const parsed = JSON.parse(out.stdout);
  assert.ok(parsed.honeytokens.includes(sha(FAKE.aws)));
  assert.ok(!out.stdout.includes('.env.backup') && !out.stdout.includes(FAKE.aws.slice(4)), 'no file names or values printed');
});

test('DB URL: placeholder words in a real password do not hide it; config symlinked outside is refused; empty waiver target rejected', () => {
  const root = fixedApp();
  write(root, 'src/db.js', 'const u = "postgres://admin:Example2024Prod@db.prod-host.net:5432/app";');
  assert.ok(run(root, { today: TODAY }).items.some((i) => i.check === 'SG-SECRET-VALUE' && /database URL/.test(i.message)));
  const outside = tmp();
  write(outside, 'gate.json', JSON.stringify({ ignore_paths: ['src/'] }));
  fs.mkdirSync(path.join(root, '.jason'), { recursive: true });
  fs.symlinkSync(path.join(outside, 'gate.json'), path.join(root, '.jason/gate.json'));
  let res = run(root, { today: TODAY });
  assert.ok(res.items.some((i) => i.check === 'SG-CONFIG' && /outside the repository/.test(i.message)));
  fs.unlinkSync(path.join(root, '.jason/gate.json'));
  write(root, '.jason/waivers.json', JSON.stringify({ schema_version: 1, waivers: [{ check: 'SG-RATE-LIMIT', target: '', reason: 'x', owner: 'jason', expires: '2026-12-01' }] }));
  res = run(root, { today: TODAY });
  assert.ok(res.items.some((i) => /target is empty/.test(i.message)));
});
