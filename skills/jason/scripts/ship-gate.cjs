#!/usr/bin/env node
'use strict';
// J.A.S.O.N. ship-gate: deterministic pre-deploy checks that BLOCK a deploy.
// Single file, zero dependencies: copy it to scripts/ci/ship-gate.cjs in the
// target repo and run it before every deploy (and before the first one).
//
// Usage: node ship-gate.cjs [repo-root] [--json] [--today YYYY-MM-DD]
// Exit 0 = pass, 1 = blocked, 2 = usage error.
//
// Read-only. Never runs target code (the only subprocess is `git ls-files`,
// started outside the repo with fsmonitor disabled). Prints secret types and
// at most 4 characters of a value, never full values.
//
// Optional files in the target repo:
//   security/ship-gate.json  { "ignore_paths": [...], "public_tables": [...], "rate_limit": { "where": "..." } }
//   security/waivers.json    { "schema_version": 1, "waivers": [{ "check", "target"?, "reason", "owner", "expires" }] }
//   security/findings.json   confirmed critical/high findings block (J.A.S.O.N. full audit output)
//   security/honeytokens.md  bait files listed there are skipped by every check
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

// ---------- constants ----------
const SKIP_DIRS = new Set(['node_modules', '.git', 'vendor', '.venv', 'venv', '__pycache__', '.skills', '.claude',
  'coverage', '.turbo', '.cache', '.pnpm-store', '.yarn', 'Pods', '.gradle', 'target']);
const MAX_TEXT = 2 * 1024 * 1024;   // full checks
const MAX_SECRET_SCAN = 50 * 1024 * 1024; // secret patterns only (large bundles, source maps)
const MAX_WAIVER_DAYS = 90;
const PUBLIC_PREFIX = /^(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_|GATSBY_|VUE_APP_)/;
const SECRET_NAME = /(SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE_KEY|PASSWORD|PASSWD|OPENAI|ANTHROPIC|CLAUDE_API|GROQ|MISTRAL|COHERE|DEEPSEEK|REPLICATE|ELEVENLABS|GEMINI_API|DATABASE_URL|DB_URL|POSTGRES_URL|MONGO(DB)?_URI|STRIPE_SK|SK_LIVE|AWS_SECRET|ADMIN_KEY|RESEND_API|SENDGRID_API|TWILIO_AUTH)/;
const NOT_SECRET_NAME = /(PUBLISHABLE|ANON_KEY|_ANON\b|PUBLIC_KEY|SITE_KEY)/;
const PLACEHOLDER = /(EXAMPLE|NOTREAL|NOT_REAL|x{4,}|changeme|change_me|your[-_ ]|placeholder|replace[-_]me|<[^>]{1,40}>|\.invalid\b|dummy|0{8,})/i;
const SOURCE_EXT = /\.(c?m?[jt]sx?|vue|svelte|astro)$/;
const SERVER_EXT = /\.(c?m?[jt]sx?|py|rb|go|php)$/;
const CLIENT_BUILD = /^(dist|build|out|\.next\/static|\.output\/public|\.vercel\/output\/static)\//;
const SERVER_BUILD = /^(\.next|\.output|\.vercel\/output)\//;

// ---------- helpers ----------
const redact = (v) => (v.length <= 4 ? '****' : `${v.slice(0, 4)}…`);
const rel = (root, p) => path.relative(root, p).split(path.sep).join('/');
const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;
const isEnvFile = (name) => /^\.env(\..+)?$/.test(name);
const isEnvTemplate = (name) => /\.(example|sample|template|dist|defaults)$/.test(name);
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const underIgnored = (r, ignore) => ignore.some((i) => r === i || r.startsWith(`${i.replace(/\/$/, '')}/`));

function walk(root) {
  const files = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) { // Dirent types do not follow symlinks: no loops
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || rel(root, p) === '.next/cache') continue;
        stack.push(p);
      } else if (e.isFile()) files.push(p);
    }
  }
  return files;
}

function readText(p, max = MAX_TEXT) {
  try {
    const st = fs.statSync(p);
    if (st.size > max) return null;
    const buf = fs.readFileSync(p);
    if (buf.subarray(0, 8000).includes(0)) return null; // binary
    return buf.toString('utf8');
  } catch { return null; }
}

function readJson(p) {
  try {
    const v = JSON.parse(fs.readFileSync(p, 'utf8'));
    return isObject(v) ? v : { __error: 'must be a JSON object' };
  } catch (err) { return { __error: err.message }; }
}

const stripComments = (t) => t.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:\\])\/\/[^\n]*/g, '$1').replace(/(^|\s)#[^\n]*/g, '$1');

function honeytokenFiles(root) {
  const out = new Set();
  const text = readText(path.join(root, 'security', 'honeytokens.md'));
  if (!text) return out;
  for (const line of text.split('\n')) {
    if (!/^\|\s*HT-\d+/i.test(line)) continue;
    for (const m of line.matchAll(/`([^`]+)`/g)) out.add(m[1].replace(/^\.\//, ''));
  }
  return out;
}

// ---------- checks ----------
function checkPublicSecretEnv(ctx) {
  const { root, files, items, skip } = ctx;
  for (const f of files) {
    const name = path.basename(f);
    const r = rel(root, f);
    if (!isEnvFile(name) || skip(r)) continue;
    const text = readText(f);
    if (!text) continue;
    text.split('\n').forEach((line, i) => {
      const m = line.match(/^\s*(?:export\s+)?([A-Z0-9_]+)\s*=/);
      if (!m) return;
      const key = m[1];
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
    const text = readText(f);
    if (!text) continue;
    const clientish = /^\s*['"]use client['"]/m.test(text) || /(^|\/)(components|app\/\(.*\)|pages(?!\/api)|src\/(?!server|api|lib\/server))\//.test(r) || /\.(jsx|tsx|vue|svelte|astro)$/.test(r);
    for (const m of text.matchAll(re)) {
      const key = m[2];
      if (SECRET_NAME.test(key) && !NOT_SECRET_NAME.test(key)) {
        items.push({ check: 'SG-SECRET-PUBLIC-ENV', level: 'block', file: r, line: lineOf(text, m.index),
          message: clientish
            ? `client code reads ${key}: a secret in the browser bundle`
            : `${key} is read here and has a public prefix: bundlers inline it into any client bundle that references it`,
          fix: 'Move the call to a server route; keep the key in a server-only variable without a public prefix' });
      }
    }
  }
}

const SECRET_PATTERNS = [
  ['Stripe live secret key', /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/g],
  ['Supabase secret key', /\bsb_secret_[A-Za-z0-9_-]{20,}/g],
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{20,}/g],
  ['OpenAI API key', /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/g],
  ['AWS access key id', /\bAKIA[0-9A-Z]{16}\b/g],
  ['GitHub token', /\b(?:github_pat_[A-Za-z0-9_]{22,}|ghp_[A-Za-z0-9]{36})\b/g],
  ['private key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g],
  ['database URL with password', /\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|rediss?):\/\/([^\s:@/'"`]+):([^\s@/'"`]+)@([^\s/:'"`]+)/g],
];

function isLocalDbUrl(m) {
  const [, user, pass, host] = m;
  if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1|host\.docker\.internal)$/i.test(host)) return true;
  if (!host.includes('.')) return true; // single-label host: docker-compose service or local name
  return user === pass && /^(postgres|root|mysql|mongo|admin|user|test)$/i.test(user);
}

function jwtPayload(token) {
  try { return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')); } catch { return null; }
}

function checkSecretValues(ctx) {
  const { root, files, items, bait, ignore } = ctx;
  for (const f of files) {
    const r = rel(root, f);
    if (bait.has(r)) continue;
    const name = path.basename(f);
    if (/\.(lock|lockb)$|package-lock\.json$|pnpm-lock\.yaml$/.test(name)) continue;
    const text = readText(f, MAX_SECRET_SCAN);
    if (text === null) {
      try { if (fs.statSync(f).size > MAX_SECRET_SCAN) items.push({ check: 'SG-SECRET-VALUE', level: 'warn', file: r, message: 'file too large to scan for secrets', fix: 'Check it by other means or exclude it from the deploy' }); } catch { /* ignore */ }
      continue;
    }
    const ignored = underIgnored(r, ignore);
    const level = ignored ? 'warn' : 'block';
    const where = CLIENT_BUILD.test(r) ? ' in client build output (shipped to browsers)' : SERVER_BUILD.test(r) ? ' in server build output' : '';
    const suffix = ignored ? ' (path is in ignore_paths: reported as a warning, still rotate it)' : '';
    for (const [label, re] of SECRET_PATTERNS) {
      re.lastIndex = 0;
      for (const m of text.matchAll(re)) {
        const lineStart = text.lastIndexOf('\n', m.index) + 1;
        const lineEnd = text.indexOf('\n', m.index);
        const line = text.slice(lineStart, lineEnd === -1 ? lineStart + 400 : Math.min(lineEnd, lineStart + 400));
        if (PLACEHOLDER.test(m[0]) || PLACEHOLDER.test(line)) continue;
        if (label === 'database URL with password' && isLocalDbUrl(m)) continue;
        items.push({ check: 'SG-SECRET-VALUE', level, file: r, line: lineOf(text, m.index),
          message: `real-looking ${label} (${redact(m[0])})${where}${suffix}`,
          fix: 'Rotate it now (deleting it is not enough once committed or deployed), then load it from the host secret store' });
      }
    }
    for (const m of text.matchAll(/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g)) {
      const p = jwtPayload(m[0]);
      if (!p || p.role !== 'service_role') continue;
      if (p.iss === 'supabase-demo') continue; // public Supabase CLI local default
      items.push({ check: 'SG-SECRET-VALUE', level, file: r, line: lineOf(text, m.index),
        message: `Supabase service_role key (${redact(m[0])})${where}: bypasses every RLS policy${suffix}`,
        fix: 'Rotate it in Supabase, use it only in server code, never in the client or a committed file' });
    }
  }
}

function gitTracked(root) {
  try {
    return execFileSync('git', ['-c', 'core.fsmonitor=false', '-C', root, 'ls-files', '-z'], {
      cwd: os.tmpdir(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1' },
    }).split('\0').filter(Boolean);
  } catch { return null; }
}

function checkEnvTracked(ctx) {
  const { root, files, items, skip } = ctx;
  const tracked = gitTracked(root);
  if (tracked) {
    for (const t of tracked) {
      const name = path.posix.basename(t);
      if (isEnvFile(name) && !isEnvTemplate(name) && !skip(t)) {
        items.push({ check: 'SG-ENV-COMMITTED', level: 'block', file: t, message: `${t} is committed to git`,
          fix: 'git rm --cached it, add .env* to .gitignore (keep .env.example), rotate any real value it held' });
      }
    }
    return;
  }
  // No git metadata (archive, build container without .git, git missing).
  const gi = readText(path.join(root, '.gitignore')) || '';
  const ignoresEnv = /^\s*\/?\.env(\*|\.\*|\s*$)/m.test(gi);
  for (const f of files) {
    const name = path.basename(f);
    const r = rel(root, f);
    if (!isEnvFile(name) || isEnvTemplate(name) || skip(r)) continue;
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

// RLS: same heuristic as rls-guard.sh (plus views and authenticated-only
// policies), in JS so this file stays self-contained.
function checkRls(ctx) {
  const { root, items, config } = ctx;
  const dir = path.join(root, 'supabase', 'migrations');
  if (!fs.existsSync(dir)) return;
  const publicTables = new Set((Array.isArray(config.public_tables) ? config.public_tables : []).filter((t) => typeof t === 'string').map((t) => t.toLowerCase()));
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
  const ID = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)`;
  const norm = (n) => (n.startsWith('"') ? n.slice(1, -1).replace(/""/g, '"') : n.toLowerCase());
  const OPEN_COND = String.raw`(?:true|auth\.role\(\) ?= ?'authenticated'|auth\.uid\(\) is not null)`;
  const rls = new Map();
  const src = new Map();
  for (const f of files) {
    let t = readText(path.join(dir, f)) || '';
    t = t.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/--[^\n]*/g, ' ');
    t = t.replace(/\$(\w*)\$[\s\S]*?\$\1\$/g, ' ').replace(/\s+/g, ' ');
    const re = new RegExp(String.raw`\b(?:create (temp |temporary |global temp |local temp )?(?:unlogged )?table (?:if not exists )?(?:(${ID})\.)?(${ID})|alter table (?:if exists )?(?:only )?(?:(${ID})\.)?(${ID}) (enable|disable) row level security)`, 'gi');
    for (const m of t.matchAll(re)) {
      const [, tmp, cs, ct, as, at, op] = m;
      if (ct !== undefined) {
        if (tmp || (cs && norm(cs) !== 'public')) continue;
        const name = norm(ct);
        if (!rls.has(name)) { rls.set(name, false); src.set(name, f); }
      } else {
        if (as && norm(as) !== 'public') continue;
        const name = norm(at);
        if (rls.has(name)) rls.set(name, op.toLowerCase() === 'enable');
      }
    }
    const pol = new RegExp(String.raw`\bcreate policy (?:(?!create policy).){0,120}? on (?:(?:${ID})\.)?(${ID})(?:(?!create policy).){0,200}?(?:using|with check) ?\( ?${OPEN_COND} ?\)`, 'gi');
    for (const m of t.matchAll(pol)) {
      const table = norm(m[1]);
      const isSelect = /\bfor select\b/i.test(m[0]);
      const authOnly = !/\( ?true ?\)/i.test(m[0]);
      if (isSelect && publicTables.has(table)) continue;
      items.push({ check: 'SG-DB-OPEN-POLICY', level: 'block', file: `supabase/migrations/${f}`, target: table,
        message: `policy open to ${authOnly ? 'any signed-in user (anyone, with open signup)' : 'everyone'} on ${table}: ${m[0].slice(0, 120)}`,
        fix: isSelect
          ? `Scope it with auth.uid() or a membership check, or if ${table} is public by design list it in security/ship-gate.json → public_tables`
          : 'Scope it with auth.uid() or a membership check: open writes are never fine' });
    }
    const view = new RegExp(String.raw`\bcreate (?:or replace )?view (?:(${ID})\.)?(${ID})( with ?\([^)]*\))? as`, 'gi');
    for (const m of t.matchAll(view)) {
      if (m[1] && norm(m[1]) !== 'public') continue;
      const name = norm(m[2]);
      if (/security_invoker ?= ?(true|on)/i.test(m[3] || '') || publicTables.has(name)) continue;
      items.push({ check: 'SG-DB-NO-RLS', level: 'block', file: `supabase/migrations/${f}`, target: name,
        message: `view public.${name} runs as its owner and ignores RLS on the tables it reads`,
        fix: `create view public.${name} with (security_invoker = true) as ...; or revoke select from anon, authenticated (or list it in public_tables if public by design)` });
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

function checkFirebaseRules(ctx) {
  const { root, files, items, skip } = ctx;
  for (const f of files) {
    const name = path.basename(f);
    const r = rel(root, f);
    if (skip(r)) continue;
    if (/\.rules$/.test(name)) {
      const text = readText(f);
      if (!text) continue;
      const clean = text.replace(/\/\/[^\n]*/g, '');
      for (const m of clean.matchAll(/allow\s+[a-z, ]+?\s*(?::\s*if\s+true\s*)?;/gi)) {
        items.push({ check: 'SG-DB-OPEN-RULES', level: 'block', file: r, line: lineOf(clean, m.index),
          message: `Firebase rule open to everyone: ${m[0].trim()}`,
          fix: 'Require request.auth and scope to the owner (request.auth.uid == userId)' });
      }
      for (const m of clean.matchAll(/request\.time\s*<\s*timestamp\.date\([^)]*\)/g)) {
        items.push({ check: 'SG-DB-OPEN-RULES', level: 'block', file: r, line: lineOf(clean, m.index),
          message: `Firebase test-mode rule (${m[0]}): open to everyone until that date`,
          fix: 'Replace test mode with real rules before deploying' });
      }
    } else if (name === 'database.rules.json') {
      const text = readText(f) || '';
      for (const m of text.matchAll(/"\.(read|write)"\s*:\s*true/g)) {
        items.push({ check: 'SG-DB-OPEN-RULES', level: 'block', file: r, line: lineOf(text, m.index),
          message: `Realtime Database rule ${m[0]}: grants cascade to everything below`,
          fix: 'Use "auth != null" plus owner checks; never true at a shallow path' });
      }
    }
  }
}

const RATE_LIMIT_DEPS = /^(express-rate-limit|rate-limiter-flexible|@upstash\/ratelimit|express-slow-down|@nestjs\/throttler|hono-rate-limiter|@fastify\/rate-limit|koa-ratelimit|next-rate-limit|limiter|bottleneck|slowapi|flask-limiter|django-ratelimit|fastapi-limiter|rack-attack)$/i;
const RATE_LIMIT_CODE = /(require\(['"](express-rate-limit|rate-limiter-flexible|@upstash\/ratelimit|express-slow-down|@nestjs\/throttler|hono-rate-limiter|@fastify\/rate-limit|koa-ratelimit)['"]\)|from ['"](express-rate-limit|rate-limiter-flexible|@upstash\/ratelimit|express-slow-down|@nestjs\/throttler|hono-rate-limiter|@fastify\/rate-limit|koa-ratelimit)['"]|from slowapi|flask_limiter|django_ratelimit|fastapi_limiter|\brateLimit\s*\(|\bRatelimit\.|new RateLimiter\w*\s*\(|@limiter\.limit|\blimiter\.limit\s*\(|@Throttle\s*\()/;
const ROUTE_DEF = /(\b(app|router|server|api|bp|blueprint)\.(post|get|put|patch|all|route)\s*\(|@(app|router|bp)\.(post|get|put|route)\s*\(|export\s+(async\s+)?function\s+(POST|GET|PUT|PATCH)\b|export\s+const\s+(POST|GET)\s*=|onRequest\s*\(|onCall\s*\(|createServerFn|defineEventHandler|Deno\.serve\s*\()/;
const AUTH_PATH = /(login|signin|sign-in|signup|sign-up|register|otp|verify-code|reset-password|forgot|magic-link|password)/i;
const LLM_CALL = /(api\.openai\.com|new OpenAI\s*\(|@anthropic-ai\/sdk|new Anthropic\s*\(|chat\.completions\.create|messages\.create\s*\(|generateText\s*\(|streamText\s*\(|from ['"]openai['"]|import openai|from openai import|anthropic\.Anthropic\()/;

function checkRateLimit(ctx) {
  const { root, files, items, config, skip } = ctx;
  const sensitive = new Map(); // file -> reasons
  let evidence = false;
  let llmAnywhere = null;
  let firstRoute = null;
  const pj = readJson(path.join(root, 'package.json'));
  if (!pj.__error) {
    const all = { ...(isObject(pj.dependencies) ? pj.dependencies : {}), ...(isObject(pj.devDependencies) ? pj.devDependencies : {}) };
    if (Object.keys(all).some((d) => RATE_LIMIT_DEPS.test(d))) evidence = true;
  }
  for (const reqf of ['requirements.txt', 'pyproject.toml', 'Gemfile']) {
    const t = readText(path.join(root, reqf)) || '';
    if (/^\s*(slowapi|flask-limiter|django-ratelimit|fastapi-limiter|gem ['"]rack-attack)/im.test(t)) evidence = true;
  }
  for (const f of files) {
    if (!SERVER_EXT.test(f)) continue;
    const r = rel(root, f);
    if (skip(r) || CLIENT_BUILD.test(r) || SERVER_BUILD.test(r)) continue;
    if (/(^|\/)(test|tests|__tests__|e2e|cypress|playwright)\//.test(r) || /\.(test|spec)\./.test(r)) continue;
    const raw = readText(f);
    if (!raw) continue;
    const text = stripComments(raw);
    if (RATE_LIMIT_CODE.test(text)) evidence = true;
    const usesLlm = LLM_CALL.test(text);
    if (usesLlm && !llmAnywhere) llmAnywhere = r;
    const isRoute = ROUTE_DEF.test(text) || /(^|\/)(app|pages|src\/app|src\/pages)\/api\//.test(r) || /(^|\/)supabase\/functions\//.test(r);
    if (!isRoute) continue;
    if (!firstRoute) firstRoute = r;
    const reasons = [];
    if (AUTH_PATH.test(r) || [...text.matchAll(/['"`](\/[^'"`\s]*)['"`]/g)].some((m) => AUTH_PATH.test(m[1]))) reasons.push('auth');
    if (usesLlm) reasons.push('LLM');
    if (reasons.length) sensitive.set(r, reasons);
  }
  if (llmAnywhere && firstRoute && ![...sensitive.values()].some((v) => v.includes('LLM'))) {
    sensitive.set(firstRoute, [...(sensitive.get(firstRoute) || []), `LLM via ${llmAnywhere}`]);
  }
  const rl = isObject(config.rate_limit) ? config.rate_limit : null;
  const declared = rl && typeof rl.where === 'string' && /\S/.test(rl.where);
  if (evidence || declared) return;
  for (const [file, reasons] of sensitive) {
    items.push({ check: 'SG-RATE-LIMIT', level: 'block', file,
      message: `${reasons.join(' + ')} endpoint with no rate limiter found in dependencies, code or config`,
      fix: 'Add a rate limiter (e.g. express-rate-limit, @upstash/ratelimit, slowapi) or, if it lives at the edge (Cloudflare, API gateway), declare it in security/ship-gate.json → rate_limit.where' });
  }
}

function checkFindings(ctx) {
  const { root, items } = ctx;
  const p = path.join(root, 'security', 'findings.json');
  if (!fs.existsSync(p)) return;
  const data = readJson(p);
  if (data.__error || !Array.isArray(data.findings)) {
    items.push({ check: 'SG-FINDINGS', level: 'block', file: 'security/findings.json',
      message: `findings file unreadable: ${data.__error || 'no findings array'}`, fix: 'Fix or regenerate it (validate-findings.cjs)' });
    return;
  }
  for (const f of data.findings) {
    if (!isObject(f)) continue;
    if (f.status === 'confirmed' && (f.severity === 'critical' || f.severity === 'high')) {
      const loc = Array.isArray(f.location) && isObject(f.location[0]) ? `${f.location[0].file}${f.location[0].line ? `:${f.location[0].line}` : ''}` : '';
      items.push({ check: 'SG-FINDING', level: 'block', file: loc, key: `finding:${f.fingerprint}`,
        message: `confirmed ${f.severity}: ${f.title} [${f.fingerprint}]`, fix: f.fix || 'see security/REPORT.md' });
    }
  }
}

// ---------- waivers ----------
const UNWAIVABLE = new Set(['SG-SECRET-VALUE']); // a leaked live secret gets rotated, never waived

function validDate(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}
const daysBetween = (a, b) => Math.round((new Date(`${b}T00:00:00Z`) - new Date(`${a}T00:00:00Z`)) / 86400000);

function applyWaivers(ctx, errors) {
  const { root, items, today } = ctx;
  const p = path.join(root, 'security', 'waivers.json');
  if (!fs.existsSync(p)) return;
  const data = readJson(p);
  const bad = (message, fix, level = 'block') => errors.push({ check: 'SG-WAIVERS', level, file: 'security/waivers.json', message, fix });
  if (data.__error || data.schema_version !== 1 || !Array.isArray(data.waivers)) {
    bad(`waivers file invalid: ${data.__error || 'needs schema_version 1 and a waivers array'}`, 'Fix the file (see templates/waivers.json)');
    return;
  }
  data.waivers.forEach((w, i) => {
    const at = `waiver #${i + 1}`;
    if (!isObject(w)) { bad(`${at}: must be an object`, 'Fix the entry'); return; }
    const missing = ['check', 'reason', 'owner', 'expires'].filter((k) => typeof w[k] !== 'string' || !/\S/.test(w[k]));
    if (missing.length) { bad(`${at}: missing ${missing.join(', ')}`, 'Every waiver needs check, reason, owner and expires (YYYY-MM-DD)'); return; }
    if (!validDate(w.expires)) { bad(`${at}: expires is not a valid YYYY-MM-DD date`, 'Use a real ISO date'); return; }
    if (w.expires < today) { bad(`${at} (${w.check}) expired on ${w.expires}`, 'Fix the issue, or renew the waiver with a new reason and date'); return; }
    if (UNWAIVABLE.has(w.check)) { bad(`${at}: ${w.check} cannot be waived`, 'Rotate the secret and remove it from the code'); return; }
    if (daysBetween(today, w.expires) > MAX_WAIVER_DAYS) bad(`${at} (${w.check}) expires more than ${MAX_WAIVER_DAYS} days out (${w.expires})`, 'Keep waivers short and tied to a plan', 'warn');
    let used = false;
    for (const it of items) {
      if (it.level !== 'block' || it.waived) continue;
      const matchesCheck = it.check === w.check || it.key === w.check;
      const matchesTarget = !w.target || (it.file || '').includes(w.target) || it.target === w.target;
      if (matchesCheck && matchesTarget) { it.waived = { reason: w.reason, owner: w.owner, expires: w.expires }; used = true; }
    }
    if (!used) bad(`${at} (${w.check}${w.target ? ` @ ${w.target}` : ''}) matches nothing: remove it`, 'Delete stale waivers', 'warn');
  });
}

// ---------- main ----------
function run(root, opts = {}) {
  const today = opts.today || new Date().toISOString().slice(0, 10);
  const cfgPath = path.join(root, 'security', 'ship-gate.json');
  const loaded = fs.existsSync(cfgPath) ? readJson(cfgPath) : {};
  const items = [];
  const errors = [];
  if (loaded.__error) errors.push({ check: 'SG-CONFIG', level: 'block', file: 'security/ship-gate.json', message: `invalid config: ${loaded.__error}`, fix: 'Fix the file (see templates/ship-gate.json)' });
  const config = loaded.__error ? {} : loaded;
  const ignore = (Array.isArray(config.ignore_paths) ? config.ignore_paths : []).filter((p) => typeof p === 'string' && p.trim()).map((p) => p.replace(/^\.\//, ''));
  const bait = honeytokenFiles(root);
  const ctx = {
    root, today, items, config, bait, ignore,
    files: walk(root),
    skip: (r) => bait.has(r) || underIgnored(r, ignore),
  };
  checkPublicSecretEnv(ctx);
  checkSecretValues(ctx); // scans ignored paths too (as warnings): secrets are never silently skipped
  checkEnvTracked(ctx);
  checkRls(ctx);
  checkFirebaseRules(ctx);
  checkRateLimit(ctx);
  checkFindings(ctx);
  applyWaivers(ctx, errors);
  const all = [...items, ...errors];
  const blockers = all.filter((i) => i.level === 'block' && !i.waived);
  return { root, today, passed: blockers.length === 0, blockers: blockers.length, items: all, ignored: ignore };
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
  out.push(res.passed
    ? 'Result: PASS — no blockers. Deterministic checks only; the J.A.S.O.N. pre-deploy check covers the rest.'
    : `Result: BLOCKED — ${res.blockers} blocker(s). Do not deploy. Fix them, or record a waiver in security/waivers.json (reason, owner, expires).`);
  return out.join('\n');
}

function main(argv) {
  let root = null;
  let json = false;
  let today;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--json') json = true;
    else if (argv[i] === '--today') today = argv[++i];
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
