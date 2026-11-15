'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { checkFindings, checkLedger } = require('../skills/llm-app-security/scripts/validate-findings.cjs');
const { parseInventory, check } = require('../skills/llm-app-security/scripts/check-honeytokens.cjs');

const valid = () => ({
  schema_version: 2,
  target: { name: 'demo', commit: 'abc123', dirty: false },
  generated_at: '2026-11-15T12:00:00Z',
  profile: 'full',
  run_status: 'complete',
  findings: [
    {
      id: 'LAS-001', fingerprint: 'secrets/src/db.js/SERVICE_KEY', status: 'confirmed', severity: 'critical',
      confidence: 'observed', category: 'secrets', title: 'Service key in client bundle',
      location: [{ file: 'src/db.js', line: 3 }, { file: 'src/app.jsx', line: 9 }],
      trace: [
        { kind: 'entrypoint', file: 'src/app.jsx', line: 9, description: 'bundle shipped to browser' },
        { kind: 'sink', file: 'src/db.js', line: 3, description: 'service key inlined' },
      ],
      impact: 'Full database read/write', fix: 'Move to server env and rotate',
    },
    {
      id: 'LAS-002', fingerprint: 'data-isolation/supabase/invoices', status: 'needs_validation', category: 'data-isolation',
      title: 'Invoices RLS may be disabled in production', location: [{ file: 'supabase/migrations/001.sql' }],
      impact: 'Any visitor reads all invoices', blockers: ['live project state not visible in repo'],
      validation_plan: { owner_check: 'Supabase → Table editor → invoices → RLS shows Enabled' },
    },
    {
      id: 'LAS-003', fingerprint: 'injection/src/reports.ts/search', status: 'rejected', category: 'injection',
      title: 'SQL injection in reports search', location: [{ file: 'src/reports.ts', line: 12 }],
      rejection_reason: 'Query is parameterized ($1)',
    },
  ],
});

const ledger = () => ({
  schema_version: 2,
  units: [
    { id: 'u-db', kind: 'data-store', paths: ['supabase/migrations'], status: 'covered', classes_checked: ['data-isolation'], fingerprints: ['data-isolation/supabase/invoices'] },
    { id: 'u-client', kind: 'config', paths: ['src'], status: 'covered', classes_checked: ['secrets', 'injection'], fingerprints: ['secrets/src/db.js/SERVICE_KEY', 'injection/src/reports.ts/search'] },
  ],
});

test('valid findings and ledger pass', () => {
  assert.deepStrictEqual(checkFindings(valid()), []);
  assert.deepStrictEqual(checkLedger(ledger(), valid()), []);
});

test('schema errors: bad severity, unknown field, bad date', () => {
  const d = valid();
  d.findings[0].severity = 'urgent';
  d.findings[0].extra = 1;
  d.generated_at = 'yesterday';
  const errs = checkFindings(d).join('\n');
  assert.match(errs, /severity: must be one of/);
  assert.match(errs, /unexpected "extra"/);
  assert.match(errs, /not an RFC 3339 date-time/);
});

test('status rules', () => {
  const d = valid();
  delete d.findings[0].confidence;
  d.findings[1].severity = 'high';
  delete d.findings[1].blockers;
  d.findings[2].fix = 'n/a';
  delete d.findings[2].rejection_reason;
  const errs = checkFindings(d).join('\n');
  assert.match(errs, /LAS-001: confirmed requires confidence/);
  assert.match(errs, /LAS-002: needs_validation must not have severity/);
  assert.match(errs, /LAS-002: needs_validation requires blockers/);
  assert.match(errs, /LAS-003: rejected must not have fix/);
  assert.match(errs, /LAS-003: rejected requires rejection_reason/);
});

test('fingerprints, trace order, paths, blank text, incomplete run', () => {
  const d = valid();
  d.findings[2].fingerprint = 'secrets/src/db.js/SERVICE_KEY';
  d.findings[1].fingerprint = 'data-isolation/supabase/invoices:12';
  d.findings[0].trace.reverse();
  d.findings[0].location.push({ file: '/Users/me/app/x.js' });
  d.findings[0].fix = '   ';
  d.run_status = 'incomplete';
  const errs = checkFindings(d).join('\n');
  assert.match(errs, /duplicate fingerprint/);
  assert.match(errs, /must not end with a line number/);
  assert.match(errs, /must start at entrypoint/);
  assert.match(errs, /repo-relative: \/Users\/me/);
  assert.match(errs, /LAS-001: fix is blank/);
  assert.match(errs, /incomplete requires incomplete_reason/);
});

test('ledger cross-checks', () => {
  const l = ledger();
  l.units[0].fingerprints = [];
  l.units[1].fingerprints.push('ghost/fp');
  l.units.push({ id: 'u-client', kind: 'auth', paths: ['../outside'], status: 'pending' });
  l.units.push({ id: 'u-x', kind: 'auth', paths: ['a'], status: 'deferred' });
  l.units.push({ id: 'u-y', kind: 'auth', paths: ['b'], status: 'covered' });
  const errs = checkLedger(l, valid()).join('\n');
  assert.match(errs, /finding data-isolation\/supabase\/invoices is not referenced/);
  assert.match(errs, /unknown fingerprint ghost\/fp/);
  assert.match(errs, /duplicate unit id u-client/);
  assert.match(errs, /repo-relative: \.\.\/outside/);
  assert.match(errs, /complete but the ledger still has pending/);
  assert.match(errs, /u-x: deferred requires notes/);
  assert.match(errs, /u-y: covered requires classes_checked/);
  assert.match(checkLedger({ schema_version: 2, units: [] }).join(), /at least 1/);
});

test('mini-schema refuses unsupported keywords', () => {
  const { validate } = require('../skills/llm-app-security/scripts/lib/mini-schema.cjs');
  assert.throws(() => validate({ oneOf: [] }, {}), /unsupported keyword "oneOf"/);
});

test('01 class table matches the findings category enum', () => {
  const schema = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'skills/llm-app-security/templates/findings.schema.json'), 'utf8'));
  const enumCats = schema.properties.findings.items.properties.category.enum.filter((c) => c !== 'other').sort();
  const md = fs.readFileSync(path.join(__dirname, '..', 'skills/llm-app-security/01-AUDIT.md'), 'utf8');
  const table = md.slice(md.indexOf('| Class | Ask |'), md.indexOf('After each unit'));
  const classes = [...table.matchAll(/^\| ([^|]+)\|/gm)].flatMap((m) => [...m[1].matchAll(/`([a-z-]+)`/g)].map((x) => x[1])).sort();
  assert.deepStrictEqual(classes, enumCats);
});

test('rls-guard flags the example app', () => {
  const { spawnSync } = require('node:child_process');
  const script = path.join(__dirname, '..', 'skills/llm-app-security/scripts/rls-guard.sh');
  const r = spawnSync('bash', [script, path.join(__dirname, '..', 'examples/vulnerable-vibe-app')], { encoding: 'utf8' });
  assert.strictEqual(r.status, 1);
  assert.match(r.stdout, /public\.profiles has no RLS/);
  assert.match(r.stdout, /policy open to everyone: .*invoices/);
  const ok = spawnSync('bash', [script, os.tmpdir()], { encoding: 'utf8' });
  assert.strictEqual(ok.status, 0, 'no supabase/ folder → pass');
});

const { compileIgnore } = require('../skills/llm-app-security/scripts/check-honeytokens.cjs');

function sandbox() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'las-'));
  fs.mkdirSync(path.join(root, 'security'));
  return root;
}
const write = (root, rel, text = 'bait') => {
  fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  fs.writeFileSync(path.join(root, rel), text);
};
const inventory = (root, rows) => {
  write(root, 'security/honeytokens.md', [
    '| ID | Type | Bait location | Scope |',
    '|---|---|---|---|',
    ...rows,
  ].join('\n'));
  return path.join(root, 'security', 'honeytokens.md');
};

test('inventory: header-based columns and duplicate ids', () => {
  const { baits, problems } = parseInventory([
    '| Planted | ID | Scope | Bait location |',
    '|---|---|---|---|',
    '| 2026 | HT-01 | local | `a.txt` |',
    '| 2026 | HT-01 | committed | `b.txt` |',
  ].join('\n'));
  assert.deepStrictEqual(baits.map((b) => [b.id, b.file, b.scope]), [['HT-01', 'a.txt', 'local'], ['HT-01', 'b.txt', 'committed']]);
  assert.match(problems.join(), /duplicate id HT-01/);
});

test('gitignore-style matcher', () => {
  const git = compileIgnore('*.txt\n!keep.txt\nconfig/\n/root-only.env\n', false);
  assert.ok(git('password.txt'));
  assert.ok(git('deep/nested/password.txt'));
  assert.ok(!git('keep.txt'));
  assert.ok(git('config/replica.env'));
  assert.ok(git('root-only.env'));
  assert.ok(!git('sub/root-only.env'));
  const docker = compileIgnore('password.txt\n**/*.bak\n', true);
  assert.ok(docker('password.txt'));
  assert.ok(!docker('sub/password.txt'), 'dockerignore is anchored at the root');
  assert.ok(docker('a/b/c.bak'));
});

test('honeytokens: missing exclusion, build copy, missing file, outside repo', () => {
  const root = sandbox();
  write(root, 'password.txt');
  write(root, '.dockerignore', 'node_modules\n');
  write(root, 'dist/assets/password.txt');
  const inv = inventory(root, [
    '| HT-01 | AWS | `password.txt` | committed |',
    '| HT-02 | DNS | `missing.env` | committed |',
    '| HT-03 | AWS | `~/.aws/credentials` | local |',
  ]);
  let r = check(root, inv);
  const p = r.problems.join('\n');
  assert.match(p, /HT-01: password.txt is not excluded by .dockerignore/);
  assert.match(p, /HT-01: copy found in build output dist\/assets\/password.txt/);
  assert.match(p, /HT-02: missing.env not found/);
  assert.match(r.notes.join('\n'), /HT-03: .* outside the repo/);

  write(root, '.dockerignore', '*.txt\nmissing.env\n');
  fs.rmSync(path.join(root, 'dist'), { recursive: true });
  write(root, 'missing.env');
  r = check(root, inv);
  assert.deepStrictEqual(r.problems, []);
});

test('honeytokens: served folders, COPY . . without .dockerignore, package files', () => {
  const root = sandbox();
  write(root, 'apps/web/public/creds.txt');
  write(root, 'Dockerfile', 'FROM node:24\nCOPY . .\n');
  write(root, 'package.json', JSON.stringify({ files: ['apps'] }));
  const r = check(root, inventory(root, ['| HT-01 | AWS | `apps/web/public/creds.txt` | committed |']));
  const p = r.problems.join('\n');
  assert.match(p, /served as-is \(public\/\)/);
  assert.match(p, /no \.dockerignore/);
  assert.match(p, /package.json "files"/);
});
