#!/usr/bin/env node
'use strict';
// J.A.S.O.N. ship-gate: deterministic pre-deploy checks that BLOCK a deploy.
// Single file, zero dependencies: copy it to scripts/ci/ship-gate.cjs in the
// target repo and run it before every deploy (and before the first one).
//
// Usage:
//   node ship-gate.cjs [repo-root] [--json] [--today YYYY-MM-DD]
//   node ship-gate.cjs --honeytoken-hashes <file>   (prints .jason/gate.json entries for bait)
// Exit 0 = pass, 1 = blocked, 2 = usage error.
//
// Threat model: catches mistakes by people and coding agents (including a
// hijacked agent whose edits get merged). It is not a defense against someone
// with commit rights who deliberately writes code to dodge it: CODEOWNERS on
// .jason/ and scripts/ci/, human review and the database-level db-rules job
// cover that.
//
// Read-only. Never runs target code (the only subprocess is `git ls-files`,
// started outside the repo with fsmonitor disabled). Never follows symlinks out
// of the repo. Prints secret types and at most 4 characters of a value.
//
// Committed inputs (safe to commit; put under CODEOWNERS):
//   .jason/gate.json     { "ignore_paths", "public_tables", "rate_limit": { "where", "covers" }, "honeytokens": ["<sha256>"] }
//   .jason/waivers.json  { "schema_version": 1, "waivers": [{ "check", "target"?, "reason", "owner", "expires" }] }
// Optional findings (full audit output; local, or committed in private repos):
//   security/findings.json or .jason/findings.json
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

// ---------- constants ----------
const SKIP_ANYWHERE = new Set(['node_modules', '.git', '__pycache__', '.venv', 'venv', '.pnpm-store', '.turbo', '.cache', '.gradle', 'Pods']);
const SKIP_AT_ROOT = new Set(['vendor', 'target', 'coverage', '.skills', '.claude', '.yarn']); // tool dirs, only at the repo root
const SECRET_SKIP = new Set(['node_modules', '.git', '.pnpm-store', '__pycache__']);
const LOCKFILES = new Map([['package-lock.json', 'package.json'], ['npm-shrinkwrap.json', 'package.json'], ['pnpm-lock.yaml', 'package.json'],
  ['yarn.lock', 'package.json'], ['bun.lockb', 'package.json'], ['bun.lock', 'package.json'], ['Cargo.lock', 'Cargo.toml'],
  ['poetry.lock', 'pyproject.toml'], ['uv.lock', 'pyproject.toml'], ['Pipfile.lock', 'Pipfile'], ['Gemfile.lock', 'Gemfile'],
  ['composer.lock', 'composer.json'], ['go.sum', 'go.mod']]);
const TEXTY = /\.(c?m?[jt]sx?|json|env|ya?ml|md|txt|py|rb|go|php|sql|toml|ini|cfg|conf|html?|css|sh|map|vue|svelte|astro|xml|properties|gradle|plist|rules|lock)$|^\.env/;
const MAX_TEXT = 2 * 1024 * 1024;
const MAX_SECRET_SCAN = 50 * 1024 * 1024;
const MAX_MATCHES_PER_FILE = 50;
const MAX_WAIVER_DAYS = 90;
const PUBLIC_PREFIX = /^(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_|GATSBY_|VUE_APP_)/;
const SECRET_NAME = /(SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE_KEY|PASSWORD|PASSWD|OPENAI|ANTHROPIC|CLAUDE_API|GROQ|MISTRAL|COHERE|DEEPSEEK|REPLICATE|ELEVENLABS|GEMINI_API|DATABASE_URL|DB_URL|POSTGRES_URL|MONGO(DB)?_URI|STRIPE_SK|SK_LIVE|AWS_SECRET|ADMIN_KEY|RESEND_API|SENDGRID_API|TWILIO_AUTH)/;
const NOT_SECRET_NAME = /(PUBLISHABLE|ANON_KEY|_ANON\b|PUBLIC_KEY|SITE_KEY)/;
// Placeholder markers are judged on the matched value only, never the line.
const PLACEHOLDER = /(EXAMPLE|NOTREAL|NOT_REAL|x{6,}|changeme|change_me|your[-_]|placeholder|replace[-_]?me|dummy|0{12,})/i;
const CONFIG_PLACEHOLDER = /(<[^>]*>|describe your|your[-_ ]|example|placeholder|todo|changeme)/i;
const OWNER_PLACEHOLDER = /(maintainer-name|your[-_ ]|<[^>]*>|example|placeholder|\[bot\]|dependabot|github-actions)/i;
const SOURCE_EXT = /\.(c?m?[jt]sx?|vue|svelte|astro)$/;
const SERVER_EXT = /\.(c?m?[jt]sx?|py|rb|go|php)$/;
const CLIENT_BUILD = /^(dist|build|out|public|static|\.next\/static|\.output\/public|\.vercel\/output\/static)\//;
const SERVER_BUILD = /^(\.next|\.output|\.vercel\/output)\//;

// ---------- helpers ----------
const redact = (v) => (v.length <= 4 ? '****' : `${v.slice(0, 4)}…`);
const rel = (root, p) => path.relative(root, p).split(path.sep).join('/');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const isEnvFile = (name) => /^\.env(\..+)?$/.test(name);
const isEnvTemplate = (name) => /\.(example|sample|template|dist|defaults)$/.test(name);
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const underPrefix = (r, prefix) => { const p = prefix.replace(/^\.\//, '').replace(/\/$/, ''); return p !== '' && (r === p || r.startsWith(`${p}/`)); };
const underIgnored = (r, ignore) => ignore.some((i) => underPrefix(r, i));

function lineIndex(text) {
  const starts = [0];
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) starts.push(i + 1);
  return (idx) => { let lo = 0, hi = starts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= idx) lo = mid; else hi = mid - 1; } return lo + 1; };
}

function walk(root, anywhere, atRoot = new Set()) {
  const files = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) { // Dirent types do not follow symlinks
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        const r = rel(root, p);
        if (anywhere.has(e.name) || (dir === root && atRoot.has(e.name)) || r === '.next/cache' || r === '.yarn/cache') continue;
        stack.push(p);
      } else if (e.isFile()) files.push(p);
    }
  }
  return files;
}

// An input file of the gate itself: must be a regular file inside the repo.
function insideRepo(root, p) {
  try {
    const real = fs.realpathSync(p);
    const realRoot = fs.realpathSync(root);
    return real === realRoot || real.startsWith(realRoot + path.sep);
  } catch { return false; }
}

// Returns { texts: [..], text } or { text: null, why }. Files that start with a
// UTF-16 BOM are decoded both ways, and NUL bytes in text-like files are
// stripped, so neither trick hides content.
function readText(p, max = MAX_TEXT) {
  try {
    const st = fs.statSync(p);
    if (st.size > max) return { text: null, texts: [], why: 'large' };
    const buf = fs.readFileSync(p);
    const utf8 = buf.toString('utf8');
    if (buf.length >= 2 && ((buf[0] === 0xff && buf[1] === 0xfe) || (buf[0] === 0xfe && buf[1] === 0xff))) {
      const body = buf.subarray(2, 2 + ((buf.length - 2) & ~1));
      const le = buf[0] === 0xff ? Buffer.from(body).toString('utf16le') : Buffer.from(body).swap16().toString('utf16le');
      return { text: le.replace(/\0/g, ''), texts: [le.replace(/\0/g, ''), utf8.replace(/\0/g, '')] };
    }
    if (buf.subarray(0, 8000).includes(0)) {
      if (TEXTY.test(path.basename(p))) { const t = utf8.replace(/\0/g, ''); return { text: t, texts: [t], nul: true }; }
      return { text: null, texts: [], why: 'binary' };
    }
    return { text: utf8, texts: [utf8] };
  } catch { return { text: null, texts: [], why: 'error' }; }
}
const textOf = (p, max) => readText(p, max).text;

function readJson(root, rp) {
  const p = path.join(root, rp);
  if (!insideRepo(root, p)) return { __error: 'is a symlink pointing outside the repository (refused)' };
  try {
    const v = JSON.parse(fs.readFileSync(p, 'utf8'));
    return isObject(v) ? v : { __error: 'must be a JSON object' };
  } catch (err) { return { __error: err instanceof SyntaxError ? 'not valid JSON' : 'unreadable' }; }
}

// One-pass lexer for JS-like rules/code: removes // and /* */ comments while
// respecting '...', "..." and `...` strings.
function stripCodeComments(t, hashComments = false) {
  let out = '';
  let i = 0;
  while (i < t.length) {
    const c = t[i];
    const n = t[i + 1];
    if (c === '/' && n === '/') { const e = t.indexOf('\n', i); i = e === -1 ? t.length : e; continue; }
    if (c === '/' && n === '*') { const e = t.indexOf('*/', i + 2); out += ' '; i = e === -1 ? t.length : e + 2; continue; }
    if (hashComments && c === '#') { const e = t.indexOf('\n', i); i = e === -1 ? t.length : e; continue; }
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < t.length && t[j] !== c) { if (t[j] === '\\') j++; if (c !== '`' && t[j] === '\n') break; j++; }
      out += t.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

// One-pass SQL lexer. Returns { code, noStrings }: comments and dollar-quoted
// bodies removed; quoted identifiers kept whole; `noStrings` also blanks
// '...' / E'...' literals so text inside them cannot look like a statement.
function lexSql(t) {
  let code = '';
  let bare = '';
  let i = 0;
  const tagRe = /\$([A-Za-z_][A-Za-z0-9_]*)?\$/y;
  while (i < t.length) {
    const c = t[i];
    const n = t[i + 1];
    if (c === '-' && n === '-') { const e = t.indexOf('\n', i); i = e === -1 ? t.length : e; code += ' '; bare += ' '; continue; }
    if (c === '/' && n === '*') { // nested block comments
      let depth = 1; let j = i + 2;
      while (j < t.length && depth) { if (t[j] === '/' && t[j + 1] === '*') { depth++; j += 2; } else if (t[j] === '*' && t[j + 1] === '/') { depth--; j += 2; } else j++; }
      i = j; code += ' '; bare += ' '; continue;
    }
    if (c === '$') {
      tagRe.lastIndex = i;
      const m = tagRe.exec(t);
      if (m) { const e = t.indexOf(m[0], i + m[0].length); i = e === -1 ? t.length : e + m[0].length; code += " '' "; bare += " '' "; continue; }
    }
    if (c === "'" || ((c === 'E' || c === 'e') && n === "'" && !/[A-Za-z0-9_]/.test(t[i - 1] || ''))) {
      const start = i;
      const escapes = c !== "'";
      let j = escapes ? i + 2 : i + 1;
      while (j < t.length) {
        if (escapes && t[j] === '\\') { j += 2; continue; }
        if (t[j] === "'") { if (t[j + 1] === "'") { j += 2; continue; } break; }
        j++;
      }
      code += t.slice(start, j + 1); bare += "''"; i = j + 1; continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < t.length) { if (t[j] === '"') { if (t[j + 1] === '"') { j += 2; continue; } break; } j++; }
      const ident = t.slice(i, j + 1); code += ident; bare += ident; i = j + 1; continue;
    }
    code += c; bare += c; i++;
  }
  return { code: code.replace(/\s+/g, ' '), noStrings: bare.replace(/\s+/g, ' ') };
}

// Splits on ';' outside quoted identifiers (strings are already blanked).
function sqlStatements(noStrings) {
  const out = [];
  let cur = '';
  let inId = false;
  for (const ch of noStrings) {
    if (ch === '"') inId = !inId;
    if (ch === ';' && !inId) { out.push(cur.trim()); cur = ''; } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

// ---------- checks ----------
function checkPublicSecretEnv(ctx) {
  const { root, files, items, skip } = ctx;
  for (const f of files) {
    const name = path.basename(f);
    const r = rel(root, f);
    if (!isEnvFile(name) || skip(r)) continue;
    const text = textOf(f);
    if (!text) continue;
    text.split('\n').forEach((line, i) => {
      const m = line.match(/^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*['"]?([^'"\s#]*)/);
      if (!m) return;
      const [, key, value] = m;
      if (value && ctx.isBait(value)) return; // registered honeytoken value
      if (PUBLIC_PREFIX.test(key) && SECRET_NAME.test(key) && !NOT_SECRET_NAME.test(key)) {
        items.push({ check: 'SG-SECRET-PUBLIC-ENV', level: 'block', file: r, line: i + 1,
          message: `${key} is a secret-type variable with a public prefix: it ships to every visitor`,
          fix: 'Rename it without the public prefix, use it only on the server, rotate the key if a real one was ever set' });
      }
    });
  }
  const re = /(import\.meta\.env|process\.env)\.((?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_|GATSBY_|VUE_APP_)[A-Z0-9_]+)/g;
  for (const f of files) {
    const r = rel(root, f);
    if (!SOURCE_EXT.test(f) || skip(r)) continue;
    const text = textOf(f);
    if (!text) continue;
    const lineAt = lineIndex(text);
    const clientish = /^\s*['"]use client['"]/m.test(text) || /(^|\/)(components|pages(?!\/api))\//.test(r) || /\.(jsx|tsx|vue|svelte|astro)$/.test(r);
    for (const m of text.matchAll(re)) {
      const key = m[2];
      if (SECRET_NAME.test(key) && !NOT_SECRET_NAME.test(key)) {
        items.push({ check: 'SG-SECRET-PUBLIC-ENV', level: 'block', file: r, line: lineAt(m.index),
          message: clientish
            ? `client code reads ${key}: a secret in the browser bundle`
            : `${key} is read here and has a public prefix: bundlers inline it into any client bundle that references it`,
          fix: 'Move the call to a server route; keep the key in a server-only variable without a public prefix' });
      }
    }
  }
}

const SECRET_PATTERNS = [
  ['Stripe live secret key', /\b(?:sk|rk)_live_[A-Za-z0-9]{20,256}/g],
  ['Supabase secret key', /\bsb_secret_[A-Za-z0-9_-]{20,256}/g],
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,256}/g],
  ['OpenAI API key', /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,256}/g],
  ['AWS access key id', /\bAKIA[0-9A-Z]{16}\b/g],
  ['GitHub token', /\b(?:github_pat_[A-Za-z0-9_]{22,256}|ghp_[A-Za-z0-9]{36})\b/g],
  ['private key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g],
  ['database URL with password', /\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|rediss?):\/\/([^\s:@/'"`]{1,128}):([^\s@/'"`]{1,256})@([^\s/:'"`]{1,253})/g],
];

function isLocalDbUrl(m) {
  const [, user, pass, host] = m;
  if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1|host\.docker\.internal)$/i.test(host)) return true;
  if (!host.includes('.')) return true; // single-label host: docker-compose service or local name
  return user === pass && /^(postgres|root|mysql|mongo|admin|user|test)$/i.test(user);
}
// For DB URLs the placeholder test looks at the password and host only.
function isPlaceholderDbUrl(m) {
  const [, , pass, host] = m;
  return /^(password|changeme|change_me|secret|pass|your[-_]?password|x{3,}|\*+|EXAMPLE[A-Z_]*|<[^>]+>)$/i.test(pass)
    || /(\.invalid|\.example|example\.(com|org|net))$/i.test(host);
}

// Linear JWT scan: no backtracking regex over long runs.
function* jwtCandidates(text) {
  const isB64 = (ch) => /[A-Za-z0-9_-]/.test(ch);
  let pos = 0;
  while (true) {
    const start = text.indexOf('eyJ', pos);
    if (start === -1) return;
    if (start > 0 && isB64(text[start - 1])) { pos = start + 3; continue; }
    const seg = [start];
    let i = start;
    let ok = true;
    for (let s = 0; s < 3; s++) {
      let j = i;
      while (j < text.length && j - i < 4096 && isB64(text[j])) j++;
      if (j - i < 10) { ok = false; i = j; break; }
      if (s < 2) { if (text[j] !== '.') { ok = false; i = j; break; } seg.push(j + 1); i = j + 1; } else i = j;
    }
    if (ok && text.startsWith('eyJ', seg[1])) yield { value: text.slice(start, i), index: start };
    pos = Math.max(i, start + 3);
  }
}
function jwtPayload(token) {
  try { return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')); } catch { return null; }
}

function checkSecretValues(ctx) {
  const { root, items, ignore } = ctx;
  for (const f of ctx.allFiles) {
    const r = rel(root, f);
    const name = path.basename(f);
    const manifest = LOCKFILES.get(name);
    if (manifest && !CLIENT_BUILD.test(r) && fs.existsSync(path.join(path.dirname(f), manifest))) continue; // a real lockfile
    const read = readText(f, MAX_SECRET_SCAN);
    if (read.text === null) {
      if (read.why === 'large') items.push({ check: 'SG-SECRET-VALUE', level: 'warn', file: r, message: 'file too large to scan for secrets', fix: 'Check it by other means or exclude it from the deploy' });
      else if (read.why === 'error') items.push({ check: 'SG-SECRET-VALUE', level: 'warn', file: r, message: 'file could not be read for the secret scan', fix: 'Check permissions and encoding' });
      continue;
    }
    const ignored = underIgnored(r, ignore);
    const level = ignored ? 'warn' : 'block';
    const where = CLIENT_BUILD.test(r) ? ' in client build output or a public folder (shipped to browsers)' : SERVER_BUILD.test(r) ? ' in server build output' : '';
    const suffix = `${read.nul ? ' (file contains NUL bytes)' : ''}${ignored ? ' (path is in ignore_paths: reported as a warning, still rotate it)' : ''}`;
    let count = 0;
    const seen = new Set();
    for (const text of read.texts) {
      const lineAt = lineIndex(text);
      const report = (label, value, idx, extra = '') => {
        const key = `${label}:${value}`;
        if (seen.has(key)) return;
        seen.add(key);
        if (ctx.isBait(value)) { ctx.baitHits.push(`${r}:${lineAt(idx)}`); return; }
        if (++count > MAX_MATCHES_PER_FILE) return;
        items.push({ check: 'SG-SECRET-VALUE', level, file: r, line: lineAt(idx),
          message: `real-looking ${label} (${redact(value)})${where}${extra}${suffix}`,
          fix: 'Rotate it now (deleting it is not enough once committed or deployed), then load it from the host secret store' });
      };
      for (const [label, re] of SECRET_PATTERNS) {
        re.lastIndex = 0;
        for (const m of text.matchAll(re)) {
          if (label === 'database URL with password') {
            if (isLocalDbUrl(m) || isPlaceholderDbUrl(m)) continue;
          } else if (PLACEHOLDER.test(m[0])) continue;
          report(label, m[0], m.index);
        }
      }
      for (const { value, index } of jwtCandidates(text)) {
        const p = jwtPayload(value);
        if (!p || p.role !== 'service_role') continue;
        if (p.iss === 'supabase-demo') continue; // public Supabase CLI local default
        report('Supabase service_role key', value, index, ': bypasses every RLS policy');
      }
    }
  }
}

function gitTracked(root) {
  try {
    return execFileSync('git', ['-c', 'core.fsmonitor=false', '-C', root, 'ls-files', '-z'], {
      cwd: os.tmpdir(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 256 * 1024 * 1024,
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1' },
    }).split('\0').filter(Boolean);
  } catch { return null; }
}

// An env file is treated as bait only when every value in it is a registered honeytoken.
function envFileIsBait(ctx, absPath) {
  if (!ctx.baitHashes.size) return false;
  const text = textOf(absPath);
  if (!text) return false;
  const values = text.split('\n').map((l) => l.match(/^\s*(?:export\s+)?[A-Za-z0-9_]+\s*=\s*['"]?([^'"\s#]*)/)).filter(Boolean).map((m) => m[1]).filter(Boolean);
  return values.length > 0 && values.every((v) => ctx.isBait(v));
}

function checkEnvTracked(ctx) {
  const { root, files, items, skip } = ctx;
  const tracked = gitTracked(root);
  if (tracked) {
    for (const t of tracked) {
      const name = path.posix.basename(t);
      if (isEnvFile(name) && !isEnvTemplate(name) && !skip(t) && !envFileIsBait(ctx, path.join(root, t))) {
        items.push({ check: 'SG-ENV-COMMITTED', level: 'block', file: t, message: `${t} is committed to git`,
          fix: 'git rm --cached it, add .env* to .gitignore (keep .env.example), rotate any real value it held' });
      }
    }
    return;
  }
  const gi = textOf(path.join(root, '.gitignore')) || '';
  const ignoresEnv = /^\s*\/?\.env(\*|\.\*|\s*$)/m.test(gi);
  for (const f of files) {
    const name = path.basename(f);
    const r = rel(root, f);
    if (!isEnvFile(name) || isEnvTemplate(name) || skip(r) || envFileIsBait(ctx, f)) continue;
    if (process.env.CI) {
      items.push({ check: 'SG-ENV-COMMITTED', level: 'block', file: r,
        message: 'a real .env file is present in a CI checkout, so it was committed',
        fix: 'git rm --cached it, add .env* to .gitignore, rotate any real value it held' });
    } else if (!ignoresEnv) {
      items.push({ check: 'SG-ENV-COMMITTED', level: 'warn', file: r,
        message: 'not a git repo and .env is not in .gitignore: it will be committed or copied with the code',
        fix: 'Add .env* to .gitignore and keep only a sanitized .env.example' });
    }
  }
}

// Supabase migrations (heuristic; the db-rules job querying pg_class after
// `supabase db start` is the authoritative check).
function checkRls(ctx) {
  const { root, items, config } = ctx;
  const dir = path.join(root, 'supabase', 'migrations');
  if (!fs.existsSync(dir)) return;
  if (!insideRepo(root, dir)) {
    items.push({ check: 'SG-DB-NO-RLS', level: 'block', file: 'supabase/migrations', message: 'migrations folder is a symlink pointing outside the repository: unchecked', fix: 'Keep migrations inside the repository' });
    return;
  }
  let files;
  try { files = fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort(); } catch { return; }
  const publicTables = new Set((Array.isArray(config.public_tables) ? config.public_tables : []).filter((t) => typeof t === 'string').map((t) => t.toLowerCase()));
  const ID = String.raw`(?:"(?:[^"]|""){1,128}"|[A-Za-z_][A-Za-z0-9_$]{0,127})`;
  const QNAME = String.raw`(?:(${ID})\.)?(${ID})`;
  const norm = (n) => (n.startsWith('"') ? n.slice(1, -1).replace(/""/g, '"') : n.toLowerCase());
  const isPublic = (schema) => !schema || norm(schema) === 'public';
  const rls = new Map();
  const src = new Map();
  const create = (name, f) => { rls.set(name, false); src.set(name, f); };
  for (const f of files) {
    const fp = path.join(dir, f);
    const read = insideRepo(root, fp) ? readText(fp, 200 * 1024 * 1024) : { text: null, why: 'symlink outside the repository' };
    if (read.text === null) {
      items.push({ check: 'SG-DB-NO-RLS', level: 'block', file: `supabase/migrations/${f}`,
        message: `migration could not be read (${read.why}): its tables and policies are unchecked`, fix: 'Make the migration a readable UTF-8 SQL file inside the repo' });
      continue;
    }
    const { code, noStrings } = lexSql(read.text);
    // Policies (need string literals, e.g. 'authenticated').
    for (const stmt of sqlStatements(code.replace(/'(?:[^']|'')*'/g, (s) => s.replace(/;/g, ' ')))) {
      const pm = stmt.match(new RegExp(String.raw`^create policy .{0,200}? on ${QNAME}`, 'i'));
      if (!pm) continue;
      const table = norm(pm[2]);
      const isSelect = /\bfor select\b/i.test(stmt);
      for (const km of stmt.matchAll(/\b(using|with check)\s*\(/gi)) {
        let depth = 0; let j = km.index + km[0].length - 1; const s0 = j;
        for (; j < stmt.length; j++) { if (stmt[j] === '(') depth++; else if (stmt[j] === ')') { depth--; if (!depth) break; } }
        let expr = stmt.slice(s0, j + 1).trim();
        while (/^\(.*\)$/.test(expr) && balanced(expr.slice(1, -1))) expr = expr.slice(1, -1).trim();
        expr = expr.replace(/\s+/g, ' ').toLowerCase();
        const everyone = /^(true|1 ?= ?1|true or .*|.* or true)$/.test(expr);
        const authOnly = /^(auth\.role\(\) ?= ?'authenticated'(::text)?|auth\.uid\(\) is not null|\(?select auth\.uid\(\)\)? is not null)$/.test(expr);
        if (!everyone && !authOnly) continue;
        if (isSelect && publicTables.has(table)) continue;
        items.push({ check: 'SG-DB-OPEN-POLICY', level: 'block', file: `supabase/migrations/${f}`, target: table,
          message: `policy open to ${authOnly ? 'any signed-in user (anyone, with open signup)' : 'everyone'} on ${table}: ${stmt.slice(0, 120)}`,
          fix: isSelect
            ? `Scope it with auth.uid() or a membership check, or if ${table} is public by design list it in .jason/gate.json → public_tables`
            : 'Scope it with auth.uid() or a membership check: open writes are never fine' });
        break;
      }
    }
    // Table state and views (strings blanked, so nothing inside them counts).
    for (const stmt of sqlStatements(noStrings)) {
      let m;
      if ((m = stmt.match(new RegExp(String.raw`^create (temp |temporary |global temp |local temp )?(?:unlogged )?table (?:if not exists )?${QNAME}`, 'i')))) {
        if (!m[1] && isPublic(m[2])) create(norm(m[3]), f);
      } else if ((m = stmt.match(new RegExp(String.raw`^select .* into (?:(temp|temporary|unlogged) )?(?:table )?${QNAME}\b`, 'i')))) {
        if (!/^temp/i.test(m[1] || '') && isPublic(m[2])) create(norm(m[3]), f);
      } else if ((m = stmt.match(new RegExp(String.raw`^drop table (?:if exists )?(.*)$`, 'i')))) {
        for (const part of m[1].split(',')) {
          const pm = part.trim().match(new RegExp(String.raw`^${QNAME}`));
          if (pm && isPublic(pm[1])) { rls.delete(norm(pm[2])); src.delete(norm(pm[2])); }
        }
      } else if ((m = stmt.match(new RegExp(String.raw`^alter table (?:if exists )?(?:only )?${QNAME} (.*)$`, 'i')))) {
        const [, sch, nm, actions] = m;
        const name = norm(nm);
        const ren = actions.match(new RegExp(String.raw`^rename to (${ID})`, 'i'));
        const setSchema = actions.match(new RegExp(String.raw`^set schema (${ID})`, 'i'));
        if (ren) {
          if (isPublic(sch) && rls.has(name)) { rls.set(norm(ren[1]), rls.get(name)); src.set(norm(ren[1]), src.get(name)); rls.delete(name); src.delete(name); }
          continue;
        }
        if (setSchema) {
          const toPublic = norm(setSchema[1]) === 'public';
          if (toPublic && !isPublic(sch)) create(name, f); // moved in: RLS state unknown, assume off
          if (!toPublic && isPublic(sch)) { rls.delete(name); src.delete(name); }
          continue;
        }
        if (!isPublic(sch) || !rls.has(name)) continue;
        const ops = [...actions.matchAll(/\b(enable|disable) row level security\b/gi)];
        if (ops.length) rls.set(name, ops[ops.length - 1][1].toLowerCase() === 'enable');
      } else if ((m = stmt.match(new RegExp(String.raw`^create (?:or replace )?(materialized )?view (?:if not exists )?${QNAME}(?: ?\([^)]{0,2000}\))?( with ?\([^)]{0,500}\))? as\b`, 'i')))) {
        if (!isPublic(m[2])) continue;
        const name = norm(m[3]);
        if (publicTables.has(name)) continue;
        if (!m[1] && /security_invoker ?= ?(true|on|1)/i.test(m[4] || '')) continue;
        items.push({ check: 'SG-DB-NO-RLS', level: 'block', file: `supabase/migrations/${f}`, target: name,
          message: m[1]
            ? `materialized view public.${name} has no RLS: anon and authenticated can read all of it unless select is revoked`
            : `view public.${name} runs as its owner and ignores RLS on the tables it reads`,
          fix: m[1]
            ? `revoke select on public.${name} from anon, authenticated (or list it in public_tables if public by design)`
            : `create view public.${name} with (security_invoker = true) as ...; or revoke select from anon, authenticated (or list it in public_tables if public by design)` });
      }
    }
  }
  for (const [name, on] of rls) {
    if (!on) {
      items.push({ check: 'SG-DB-NO-RLS', level: 'block', file: `supabase/migrations/${src.get(name)}`, target: name,
        message: `public.${name} has no RLS after all migrations: anyone with the anon key can read and write it`,
        fix: `alter table public.${name} enable row level security; plus owner policies on auth.uid()` });
    }
  }
}
function balanced(s) {
  let d = 0;
  for (const ch of s) { if (ch === '(') d++; else if (ch === ')') { d--; if (d < 0) return false; } }
  return d === 0;
}

function firebaseRuleFiles(ctx) {
  const { root, files } = ctx;
  const set = new Set(files.filter((f) => /\.rules$/.test(f) || path.basename(f) === 'database.rules.json').map((f) => rel(root, f)));
  const fj = readJson(root, 'firebase.json');
  if (!fj.__error) {
    const add = (v) => { if (typeof v === 'string') set.add(v.replace(/^\.\//, '')); };
    const visit = (o) => { if (Array.isArray(o)) o.forEach(visit); else if (isObject(o)) { add(o.rules); Object.values(o).forEach((v) => (isObject(v) || Array.isArray(v)) && visit(v)); } };
    visit(fj);
  }
  return [...set];
}

function checkFirebaseRules(ctx) {
  const { root, items, skip } = ctx;
  for (const r of firebaseRuleFiles(ctx)) {
    if (skip(r)) continue;
    const f = path.join(root, r);
    if (!fs.existsSync(f) || !insideRepo(root, f)) continue;
    const text = textOf(f);
    if (!text) continue;
    if (r.endsWith('.json')) {
      const lineAt = lineIndex(text);
      for (const m of text.matchAll(/"\.(read|write)"\s*:\s*(true|"true")/g)) {
        items.push({ check: 'SG-DB-OPEN-RULES', level: 'block', file: r, line: lineAt(m.index),
          message: `Realtime Database rule ${m[0]}: grants cascade to everything below`,
          fix: 'Use "auth != null" plus owner checks; never true at a shallow path' });
      }
      continue;
    }
    const clean = stripCodeComments(text);
    const lineAt = lineIndex(clean);
    const TRUE_COND = String.raw`\(*\s*(?:true|1\s*==\s*1)\s*\)*`;
    for (const m of clean.matchAll(new RegExp(String.raw`allow\s+[a-z, ]{1,60}?\s*(?::\s*if\s+${TRUE_COND}\s*)?;`, 'gi'))) {
      items.push({ check: 'SG-DB-OPEN-RULES', level: 'block', file: r, line: lineAt(m.index),
        message: `Firebase rule open to everyone: ${m[0].trim()}`,
        fix: 'Require request.auth and scope to the owner (request.auth.uid == userId)' });
    }
    for (const m of clean.matchAll(/request\.time\s*<\s*timestamp\.date\([^)]{0,40}\)/g)) {
      items.push({ check: 'SG-DB-OPEN-RULES', level: 'block', file: r, line: lineAt(m.index),
        message: `Firebase test-mode rule (${m[0]}): open to everyone until that date`,
        fix: 'Replace test mode with real rules before deploying' });
    }
    for (const m of clean.matchAll(/allow\s+(?:[a-z]+,\s*)*(?:write|create|update|delete)\b[a-z, ]{0,40}:\s*if\s+([^;]{1,400});/gi)) {
      if (/request\.auth/.test(m[1]) || /request\.time\s*</.test(m[1]) || new RegExp(`^\\s*${TRUE_COND}\\s*$`).test(m[1])) continue;
      items.push({ check: 'SG-DB-OPEN-RULES', level: 'warn', file: r, line: lineAt(m.index),
        message: `Firebase write rule without request.auth: ${m[0].slice(0, 120)}`,
        fix: 'Confirm anonymous writes are intended (e.g. a contact form) and limited by field validation' });
    }
  }
}

// Patterns are assembled from fragments so this file's own source never
// matches them (copying the gate into a repo must not count as a rate limiter,
// a route or an LLM call).
const J = (...parts) => parts.join('');
const LIMITER_LIBS = [J('express-rate', '-limit'), J('rate-limiter', '-flexible'), J('@upstash/', 'ratelimit'), J('express-slow', '-down'),
  J('@nestjs/', 'throttler'), J('hono-rate', '-limiter'), J('@fastify/', 'rate-limit'), J('koa-', 'ratelimit'), J('next-rate', '-limit')];
const PY_LIMITERS = [J('slow', 'api'), J('flask-', 'limiter'), J('django-', 'ratelimit'), J('fastapi-', 'limiter')];
const RATE_LIMIT_DEPS = new Set([...LIMITER_LIBS, ...PY_LIMITERS]);
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
const RATE_LIMIT_CODE = new RegExp([
  `require\\(\\s*['"](?:${LIMITER_LIBS.map(esc).join('|')})['"]\\s*\\)`,
  `from\\s+['"](?:${LIMITER_LIBS.map(esc).join('|')})['"]`,
  `(?:^|\\n)\\s*(?:from|import)\\s+(?:${PY_LIMITERS.map((p) => p.replace(/-/g, '[_]')).join('|')})\\b`,
  '\\brateLimit\\s*\\(', '\\bRatelimit\\.', 'new\\s+RateLimiter\\w*\\s*\\(', '@limiter\\.limit', '\\blimiter\\.limit\\s*\\(', '@Throttle\\s*\\(',
].join('|'));
const ROUTE_DEF = new RegExp([
  '\\b(?:app|router|server|api|bp|blueprint|fastify|hono|elysia|routes?|r)\\.(?:post|get|put|patch|delete|all|route)\\s*\\(\\s*[\'"`]',
  '@(?:app|router|bp)\\.(?:post|get|put|route)\\s*\\(', 'export\\s+(?:async\\s+)?function\\s+(?:POST|GET|PUT|PATCH)\\b',
  'export\\s+const\\s+(?:POST|GET)\\s*=', 'onRequest\\s*\\(', 'onCall\\s*\\(', J('create', 'Server', 'Fn'), J('define', 'Event', 'Handler'),
  'Deno\\.serve\\s*\\(',
].join('|'));
const AUTH_PATH = /(login|signin|sign-in|signup|sign-up|register|otp|verify-code|reset-password|forgot|magic-link|password)/i;
const LLM_HOSTS = [['api', J('open', 'ai'), 'com'], ['api', J('anthr', 'opic'), 'com'], ['generativelanguage', 'googleapis', 'com'], ['api', 'groq', 'com'],
  ['api', 'mistral', 'ai'], ['api', 'deepseek', 'com'], ['openrouter', 'ai'], ['api', 'together', 'xyz'], ['api', 'cohere', 'ai'],
  ['api', 'cohere', 'com'], ['api', 'fireworks', 'ai'], ['api', 'x', 'ai']];
const LLM_SDKS = [J('open', 'ai'), J('@anthropic-ai', '/sdk'), J('@google', '/genai'), J('@google', '/generative-ai'), J('groq', '-sdk'),
  J('@mistralai', '/mistralai'), J('cohere', '-ai'), J('@ai-sdk', '/'), J('@langchain', '/'), J('replicate', '')];
const LLM_CALL = new RegExp([
  ...LLM_HOSTS.map((parts) => parts.join('\\.')),
  `['"](?:${LLM_SDKS.map(esc).join('|')})[^'"]{0,40}['"]`,
  'new\\s+OpenAI\\s*\\(', 'new\\s+Anthropic\\s*\\(', 'new\\s+GoogleGenAI\\s*\\(', 'new\\s+Groq\\s*\\(',
  'chat\\.completions\\.create', 'responses\\.create\\s*\\(', 'messages\\.create\\s*\\(', 'models\\.generateContent\\s*\\(',
  'generateContent\\s*\\(', 'generateText\\s*\\(', 'streamText\\s*\\(',
  '(?:^|\\n)\\s*(?:import\\s+(?:openai|anthropic|groq)\\b|from\\s+(?:openai|anthropic|groq|google\\.genai)\\s+import)', 'anthropic\\.Anthropic\\(',
].join('|'));
const NON_PROD_DIR = /^(examples?|docs?|samples?|demo|fixtures?|tests?|__tests__|e2e|cypress|playwright|test-fixtures)\//;

function checkRateLimit(ctx) {
  const { root, files, items, config, skip } = ctx;
  const sensitive = new Map();
  const evidence = [];
  let llmAnywhere = null;
  let firstRoute = null;
  const pj = readJson(root, 'package.json');
  if (!pj.__error && isObject(pj.dependencies)) {
    for (const d of Object.keys(pj.dependencies)) if (RATE_LIMIT_DEPS.has(d)) evidence.push(`package.json dependency ${d}`);
  }
  for (const reqf of ['requirements.txt', 'pyproject.toml']) {
    const t = textOf(path.join(root, reqf)) || '';
    const m = t.match(new RegExp(`^\\s*["']?(${PY_LIMITERS.map(esc).join('|')})\\b`, 'im'));
    if (m) evidence.push(`${reqf} ${m[1]}`);
  }
  if (/^\s*gem\s+['"]rack-attack['"]/m.test(textOf(path.join(root, 'Gemfile')) || '')) evidence.push('Gemfile rack-attack');
  for (const f of files) {
    if (!SERVER_EXT.test(f)) continue;
    const r = rel(root, f);
    if (skip(r) || CLIENT_BUILD.test(r) || SERVER_BUILD.test(r) || NON_PROD_DIR.test(r) || /\.(test|spec)\./.test(r)) continue;
    const raw = textOf(f);
    if (!raw) continue;
    const text = stripCodeComments(raw, /\.(py|rb)$/.test(f));
    if (RATE_LIMIT_CODE.test(text)) evidence.push(r);
    const usesLlm = LLM_CALL.test(text);
    if (usesLlm && !llmAnywhere) llmAnywhere = r;
    const isRoute = ROUTE_DEF.test(text) || /(^|\/)(app|pages|src\/app|src\/pages)\/api\//.test(r) || /(^|\/)supabase\/functions\//.test(r);
    if (!isRoute) continue;
    if (!firstRoute) firstRoute = r;
    const reasons = [];
    if (AUTH_PATH.test(r) || [...text.matchAll(/['"`](\/[^'"`\s]{0,200})['"`]/g)].some((m) => AUTH_PATH.test(m[1]))) reasons.push('auth');
    if (usesLlm) reasons.push('LLM');
    if (reasons.length) sensitive.set(r, reasons);
  }
  if (llmAnywhere && firstRoute && ![...sensitive.values()].some((v) => v.includes('LLM'))) {
    sensitive.set(firstRoute, [...(sensitive.get(firstRoute) || []), `LLM via ${llmAnywhere}`]);
  }
  if (evidence.length) {
    if (sensitive.size) ctx.declarations.push(`rate limiter found in ${evidence.slice(0, 3).join(', ')} (applies repo-wide; confirm it covers: ${[...sensitive.keys()].slice(0, 5).join(', ')})`);
    return;
  }
  const rl = isObject(config.rate_limit) ? config.rate_limit : null;
  let declared = false;
  let covers = null;
  if (rl) {
    if (typeof rl.where !== 'string' || !/\S/.test(rl.where) || CONFIG_PLACEHOLDER.test(rl.where)) {
      items.push({ check: 'SG-CONFIG', level: 'block', file: ctx.configFile, message: 'rate_limit.where is empty or a placeholder: describe the real limiter or remove the block', fix: 'e.g. "Cloudflare WAF rule auth-and-chat, 10 req/min per IP"' });
    } else {
      declared = true;
      covers = Array.isArray(rl.covers) ? rl.covers.filter((c) => typeof c === 'string' && c.replace(/^\//, '').trim()) : null;
      if (covers && !covers.length) covers = null;
      ctx.declarations.push(`rate_limit.where: ${rl.where}${covers ? ` (covers: ${covers.join(', ')})` : ' (no covers list: every route assumed covered)'}`);
    }
  }
  for (const [file, reasons] of sensitive) {
    if (declared && (!covers || covers.some((c) => file.includes(c.replace(/^\//, ''))))) {
      if (!covers) items.push({ check: 'SG-RATE-LIMIT', level: 'warn', file, message: `${reasons.join(' + ')} endpoint assumed covered by the declared edge limiter (no "covers" list)`, fix: 'List covered paths in rate_limit.covers so new routes are checked' });
      continue;
    }
    items.push({ check: 'SG-RATE-LIMIT', level: 'block', file,
      message: `${reasons.join(' + ')} endpoint with no rate limiter found in dependencies, code or config`,
      fix: 'Add a rate limiter (e.g. express-rate-limit, @upstash/ratelimit, slowapi) or, if it lives at the edge (Cloudflare, API gateway), declare it in .jason/gate.json → rate_limit.where and covers' });
  }
}

function checkFindings(ctx) {
  const { root, items } = ctx;
  for (const relp of ['security/findings.json', '.jason/findings.json']) {
    if (!fs.existsSync(path.join(root, relp))) continue;
    const data = readJson(root, relp);
    if (data.__error || !Array.isArray(data.findings)) {
      items.push({ check: 'SG-FINDINGS', level: 'block', file: relp,
        message: `findings file ${data.__error || 'has no findings array'}`, fix: 'Fix or regenerate it (validate-findings.cjs)' });
      continue;
    }
    for (const f of data.findings) {
      if (!isObject(f)) continue;
      if (f.status === 'confirmed' && (f.severity === 'critical' || f.severity === 'high')) {
        const loc = Array.isArray(f.location) && isObject(f.location[0]) ? `${f.location[0].file}${f.location[0].line ? `:${f.location[0].line}` : ''}` : '';
        items.push({ check: 'SG-FINDING', level: 'block', file: loc, key: `finding:${f.fingerprint}`,
          message: `confirmed ${f.severity}: ${f.title} [${f.fingerprint}] (from ${relp})`, fix: f.fix || 'see security/REPORT.md' });
      }
    }
  }
}

// ---------- waivers ----------
const UNWAIVABLE = new Set(['SG-SECRET-VALUE']);

function validDate(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}
const daysBetween = (a, b) => Math.round((new Date(`${b}T00:00:00Z`) - new Date(`${a}T00:00:00Z`)) / 86400000);

function applyWaivers(ctx, errors) {
  const { root, items, today } = ctx;
  const file = '.jason/waivers.json';
  if (!fs.existsSync(path.join(root, file))) return;
  const data = readJson(root, file);
  const bad = (message, fix, level = 'block') => errors.push({ check: 'SG-WAIVERS', level, file, message, fix });
  if (data.__error || data.schema_version !== 1 || !Array.isArray(data.waivers)) {
    bad(`waivers file ${data.__error || 'needs schema_version 1 and a waivers array'}`, 'Fix the file (see templates/waivers.json)');
    return;
  }
  data.waivers.forEach((w, i) => {
    const at = `waiver #${i + 1}`;
    if (!isObject(w)) { bad(`${at}: must be an object`, 'Fix the entry'); return; }
    const missing = ['check', 'reason', 'owner', 'expires'].filter((k) => typeof w[k] !== 'string' || !/\S/.test(w[k]));
    if (missing.length) { bad(`${at}: missing ${missing.join(', ')}`, 'Every waiver needs check, reason, owner and expires (YYYY-MM-DD)'); return; }
    if ('target' in w && (typeof w.target !== 'string' || !w.target.replace(/^[./]+/, '').trim())) { bad(`${at}: target is empty`, 'Remove target to waive the whole check, or give a real path/table'); return; }
    if (OWNER_PLACEHOLDER.test(w.owner)) { bad(`${at}: owner "${w.owner}" is a placeholder or a bot`, 'A waiver is a human decision: put the person accountable for it'); return; }
    if (!validDate(w.expires)) { bad(`${at}: expires is not a valid YYYY-MM-DD date`, 'Use a real ISO date'); return; }
    if (w.expires < today) { bad(`${at} (${w.check}) expired on ${w.expires}`, 'Fix the issue, or renew the waiver with a new reason and date'); return; }
    if (UNWAIVABLE.has(w.check)) { bad(`${at}: ${w.check} cannot be waived`, 'Rotate the secret and remove it from the code'); return; }
    if (daysBetween(today, w.expires) > MAX_WAIVER_DAYS) bad(`${at} (${w.check}) expires more than ${MAX_WAIVER_DAYS} days out (${w.expires})`, 'Keep waivers short and tied to a plan', 'warn');
    let used = false;
    for (const it of items) {
      if (it.level !== 'block' || it.waived) continue;
      const matchesCheck = it.check === w.check || it.key === w.check;
      const matchesTarget = !w.target || (it.file && underPrefix(it.file.replace(/:\d+$/, ''), w.target)) || it.target === w.target;
      if (matchesCheck && matchesTarget) { it.waived = { reason: w.reason, owner: w.owner, expires: w.expires }; used = true; }
    }
    if (!used) bad(`${at} (${w.check}${w.target ? ` @ ${w.target}` : ''}) matches nothing: remove it`, 'Delete stale waivers', 'warn');
  });
}

// ---------- config ----------
function loadConfig(root, errors) {
  for (const legacy of ['security/ship-gate.json', 'security/waivers.json']) {
    if (fs.existsSync(path.join(root, legacy))) {
      errors.push({ check: 'SG-CONFIG', level: 'warn', file: legacy,
        message: `${legacy} is ignored (old location, outside CODEOWNERS and usually git-ignored)`, fix: `Move it to .jason/${legacy.endsWith('waivers.json') ? 'waivers.json' : 'gate.json'}` });
    }
  }
  const configFile = '.jason/gate.json';
  let config = {};
  if (fs.existsSync(path.join(root, configFile))) {
    const loaded = readJson(root, configFile);
    if (loaded.__error) errors.push({ check: 'SG-CONFIG', level: 'block', file: configFile, message: `config ${loaded.__error}`, fix: 'Fix the file (see templates/gate.json in the J.A.S.O.N. skill)' });
    else config = loaded;
  }
  const baitHashes = new Set((Array.isArray(config.honeytokens) ? config.honeytokens : [])
    .map((h) => (typeof h === 'string' ? h : isObject(h) ? h.sha256 : null))
    .filter((h) => typeof h === 'string' && /^[0-9a-f]{64}$/.test(h)));
  return { config, configFile, baitHashes };
}

// ---------- main ----------
function run(root, opts = {}) {
  const today = opts.today || new Date().toISOString().slice(0, 10);
  const items = [];
  const errors = [];
  const { config, configFile, baitHashes } = loadConfig(root, errors);
  const ignore = (Array.isArray(config.ignore_paths) ? config.ignore_paths : []).filter((p) => typeof p === 'string' && p.replace(/^[./]+/, '').trim()).map((p) => p.replace(/^\.\//, ''));
  const ctx = {
    root, today, items, config, configFile, ignore, baitHashes,
    files: walk(root, SKIP_ANYWHERE, SKIP_AT_ROOT),
    allFiles: walk(root, SECRET_SKIP),
    skip: (r) => underIgnored(r, ignore),
    isBait: (v) => baitHashes.size > 0 && baitHashes.has(sha256(v)),
    baitHits: [],
    declarations: [],
  };
  checkPublicSecretEnv(ctx);
  checkSecretValues(ctx);
  checkEnvTracked(ctx);
  checkRls(ctx);
  checkFirebaseRules(ctx);
  checkRateLimit(ctx);
  checkFindings(ctx);
  applyWaivers(ctx, errors);
  const all = [...items, ...errors];
  const blockers = all.filter((i) => i.level === 'block' && !i.waived);
  return { root, today, passed: blockers.length === 0, blockers: blockers.length, items: all,
    ignored: ignore, honeytokens: ctx.baitHits, declarations: ctx.declarations };
}

function format(res) {
  const out = [`J.A.S.O.N. ship-gate — ${res.root}`];
  const order = { block: 0, warn: 1 };
  const sorted = [...res.items].sort((a, b) => (a.waived ? 1 : 0) - (b.waived ? 1 : 0) || order[a.level] - order[b.level]);
  for (const i of sorted) {
    const tag = i.waived ? 'WAIVED' : i.level === 'block' ? 'BLOCK ' : 'WARN  ';
    const loc = i.file ? `${i.file}${i.line ? `:${i.line}` : ''}` : '';
    out.push(`${tag} ${i.check.padEnd(22)} ${loc}`);
    out.push(`       ${i.message}`);
    if (i.waived) out.push(`       waived by ${i.waived.owner} until ${i.waived.expires}: ${i.waived.reason}`);
    else if (i.level === 'block') out.push(`       fix: ${i.fix}`);
  }
  if (res.ignored.length) out.push(`(ignore_paths, skipped except for secret scanning: ${res.ignored.join(', ')})`);
  if (res.honeytokens.length) out.push(`(registered honeytokens matched: ${res.honeytokens.join(', ')})`);
  for (const d of res.declarations) out.push(`(${d})`);
  out.push(res.passed
    ? 'Result: PASS — no blockers. Deterministic checks only; the J.A.S.O.N. pre-deploy check covers the rest.'
    : `Result: BLOCKED — ${res.blockers} blocker(s). Do not deploy. Fix them; shipping anyway needs a human decision recorded in .jason/waivers.json (reason, owner, expires).`);
  return out.join('\n');
}

function honeytokenHashes(file) {
  const text = textOf(file, MAX_SECRET_SCAN);
  if (text === null) { console.error(`cannot read ${file}`); return 2; }
  const hashes = new Set();
  for (const [, re] of SECRET_PATTERNS) { re.lastIndex = 0; for (const m of text.matchAll(re)) hashes.add(sha256(m[0])); }
  for (const { value } of jwtCandidates(text)) hashes.add(sha256(value));
  for (const line of text.split('\n')) { const m = line.match(/^\s*(?:export\s+)?[A-Za-z0-9_]+\s*=\s*['"]?([^'"\s#]+)/); if (m) hashes.add(sha256(m[1])); }
  console.log(JSON.stringify({ honeytokens: [...hashes] }, null, 2));
  console.error('Add these hashes to .jason/gate.json → honeytokens. They name no files and reveal no values. Only bait belongs here.');
  return 0;
}

function main(argv) {
  let root = null;
  let json = false;
  let today;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--json') json = true;
    else if (argv[i] === '--today') today = argv[++i];
    else if (argv[i] === '--honeytoken-hashes') { if (!argv[i + 1]) { console.error('--honeytoken-hashes needs a file'); return 2; } return honeytokenHashes(argv[i + 1]); }
    else if (argv[i].startsWith('-')) { console.error(`unknown option ${argv[i]}`); return 2; }
    else root = argv[i];
  }
  root = path.resolve(root || '.');
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) { console.error(`not a directory: ${root}`); return 2; }
  if (today !== undefined && !validDate(today)) { console.error('--today must be a valid YYYY-MM-DD date'); return 2; }
  const res = run(root, { today });
  console.log(json ? JSON.stringify(res, null, 2) : format(res));
  return res.passed ? 0 : 1;
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));
module.exports = { run, format, main };
