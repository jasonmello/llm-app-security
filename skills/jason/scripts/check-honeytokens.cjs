#!/usr/bin/env node
'use strict';
// Usage: node check-honeytokens.cjs [inventory.md] [--root <repo>]
// Checks that each bait in the inventory exists, is not under a folder served
// as-is, is excluded from deploy contexts and absent from build output, and
// that "local" bait is not tracked by git. An inventory kept inside --root must
// also be excluded from deploy contexts (it maps where the bait is).
// Default inventory: security/honeytokens.md under the root.
// Exit 0 = ok, 1 = problems found, 2 = usage error.
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

// ---------- inventory ----------
function splitRow(line) {
  return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());
}

function parseInventory(md) {
  const lines = md.split('\n');
  const baits = [];
  const problems = [];
  let cols = null;
  for (const line of lines) {
    if (!line.trim().startsWith('|')) { cols = null; continue; }
    const cells = splitRow(line);
    if (!cols) {
      const lower = cells.map((c) => c.toLowerCase());
      if (lower.includes('id') && lower.some((c) => c.startsWith('bait location'))) {
        cols = {
          id: lower.indexOf('id'),
          loc: lower.findIndex((c) => c.startsWith('bait location')),
          scope: lower.indexOf('scope'),
        };
      }
      continue;
    }
    if (/^:?-{2,}/.test(cells[0])) continue; // separator row
    const id = cells[cols.id];
    if (!/^HT-\d+$/i.test(id || '')) continue;
    const m = (cells[cols.loc] || '').match(/`([^`]+)`/);
    const scope = cols.scope >= 0 ? (cells[cols.scope] || '').toLowerCase() : '';
    baits.push({ id, file: m ? m[1] : null, scope });
  }
  const seen = new Set();
  for (const b of baits) {
    if (seen.has(b.id)) problems.push(`duplicate id ${b.id}`);
    seen.add(b.id);
  }
  return { baits, problems };
}

// ---------- gitignore-style matching ----------
function globToRegex(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') { i++; re += '(?:.*/)?'; } else re += '.*';
      } else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return re;
}

// anchored=true: patterns are relative to the context root (.dockerignore).
// anchored=false: gitignore rules (a pattern without "/" matches at any depth).
function compileIgnore(text, anchored) {
  const rules = [];
  for (let raw of text.split('\n')) {
    raw = raw.replace(/\r$/, '').trim();
    if (!raw || raw.startsWith('#')) continue;
    let neg = false;
    if (raw.startsWith('!')) { neg = true; raw = raw.slice(1); }
    let dirOnly = false;
    if (raw.endsWith('/')) { dirOnly = true; raw = raw.slice(0, -1); }
    const hasSlash = raw.includes('/');
    raw = raw.replace(/^\//, '');
    const body = globToRegex(raw);
    const prefix = anchored || hasSlash ? '^' : '^(?:.*/)?';
    // a matched directory also matches everything below it
    const re = new RegExp(`${prefix}${body}${dirOnly ? '/.*' : '(?:/.*)?'}$`);
    rules.push({ neg, re });
  }
  return (rel) => {
    let ignored = false;
    for (const r of rules) if (r.re.test(rel)) ignored = !r.neg;
    return ignored;
  };
}

// ---------- checks ----------
const IGNORE_FILES = [
  { f: '.dockerignore', anchored: true },
  { f: '.vercelignore', anchored: false },
  { f: '.netlifyignore', anchored: false },
  { f: '.npmignore', anchored: false },
  { f: '.gcloudignore', anchored: false },
];
const SERVED = ['public', 'static', 'wwwroot', 'assets/public'];
const SERVED_WARN = ['docs'];
const BUILD_DIRS = new Set(['dist', 'build', '.next', 'out', '.output', '.vercel', '.netlify']);

function findInBuildDirs(root, base, depth = 0, acc = []) {
  if (depth > 4) return acc;
  let entries;
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { return acc; }
  for (const e of entries) {
    if (!e.isDirectory() || e.name === 'node_modules' || e.name === '.git') continue;
    const p = path.join(root, e.name);
    if (BUILD_DIRS.has(e.name)) {
      walkFor(p, base, acc, 0);
    } else findInBuildDirs(p, base, depth + 1, acc);
  }
  return acc;
}
function walkFor(dir, base, acc, depth) {
  if (depth > 8) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walkFor(p, base, acc, depth + 1);
    else if (e.name === base) acc.push(p);
  }
}

function gitTracked(root, rel) {
  try {
    execFileSync('git', ['-C', root, 'ls-files', '--error-unmatch', '--', rel], { stdio: 'ignore' });
    return true;
  } catch { return false; }
}

function check(root, inventoryPath) {
  const parsed = parseInventory(fs.readFileSync(inventoryPath, 'utf8'));
  const { baits } = parsed;
  const problems = [...parsed.problems];
  const notes = [];
  if (!baits.length) problems.push('inventory has no HT-xx rows (needs a header with "ID" and "Bait location")');

  const ignores = IGNORE_FILES.filter(({ f }) => fs.existsSync(path.join(root, f)))
    .map(({ f, anchored }) => ({ f, match: compileIgnore(fs.readFileSync(path.join(root, f), 'utf8'), anchored) }));

  let pkgFiles = null;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    if (Array.isArray(pkg.files)) pkgFiles = compileIgnore(pkg.files.join('\n'), false);
  } catch { /* no package.json */ }

  const hasDockerfile = fs.existsSync(path.join(root, 'Dockerfile'));
  const copiesAll = hasDockerfile && /^\s*(COPY|ADD)\s+(--\S+\s+)*(\.\/?|\*)\s+/mi.test(fs.readFileSync(path.join(root, 'Dockerfile'), 'utf8'));
  const hasDockerignore = fs.existsSync(path.join(root, '.dockerignore'));

  for (const b of baits) {
    if (!b.file) { problems.push(`${b.id}: no backticked path in "Bait location"`); continue; }
    if (b.file.startsWith('~') || path.isAbsolute(b.file)) {
      notes.push(`${b.id}: ${b.file} is outside the repo; the user checks it manually`);
      continue;
    }
    const rel = path.posix.normalize(b.file.split(path.sep).join('/')).replace(/^\.\//, '');
    if (rel.startsWith('../')) { problems.push(`${b.id}: ${rel} is outside --root`); continue; }
    if (!fs.existsSync(path.join(root, rel))) { problems.push(`${b.id}: ${rel} not found`); continue; }

    const under = (s) => rel.startsWith(`${s}/`) || rel.includes(`/${s}/`); // monorepos: apps/web/public/
    for (const s of SERVED) if (under(s)) problems.push(`${b.id}: ${rel} is under a folder served as-is (${s}/)`);
    for (const s of SERVED_WARN) if (under(s)) notes.push(`${b.id}: ${rel} is under ${s}/ — make sure it is not published (e.g. GitHub Pages)`);

    for (const { f, match } of ignores) {
      if (!match(rel)) problems.push(`${b.id}: ${rel} is not excluded by ${f} (would ship)`);
    }
    if (pkgFiles && pkgFiles(rel)) problems.push(`${b.id}: ${rel} matches package.json "files" (would be published to npm)`);
    if (copiesAll && !hasDockerignore) problems.push(`${b.id}: Dockerfile copies the whole context and there is no .dockerignore`);

    for (const hit of findInBuildDirs(root, path.posix.basename(rel))) {
      problems.push(`${b.id}: copy found in build output ${path.relative(root, hit)}`);
    }
    if (b.scope === 'local' && gitTracked(root, rel)) {
      problems.push(`${b.id}: scope is local but ${rel} is tracked by git (use .git/info/exclude and git rm --cached)`);
    }
  }
  // The inventory is a map of the bait: it must not ship either.
  const invRel = path.relative(root, inventoryPath).split(path.sep).join('/');
  if (!invRel.startsWith('../')) {
    for (const { f, match } of ignores) {
      if (!match(invRel)) problems.push(`inventory ${invRel} is not excluded by ${f} (would ship the bait map)`);
    }
    if (copiesAll && !hasDockerignore) problems.push(`inventory ${invRel}: Dockerfile copies the whole context and there is no .dockerignore`);
    if (gitTracked(root, invRel)) notes.push(`inventory ${invRel} is tracked by git: fine for a private repo, never for a public one`);
  }
  if (!ignores.length && !hasDockerfile) notes.push('no deploy ignore files found; make sure bait files are not deployed');
  return { baits, problems, notes };
}

function main(argv) {
  let root = process.cwd();
  let inventory;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--root') {
      if (!argv[i + 1]) { console.error('--root needs a path'); return 2; }
      root = path.resolve(argv[++i]);
    }
    else inventory = argv[i];
  }
  inventory = inventory ? path.resolve(inventory) : path.join(root, 'security', 'honeytokens.md');
  if (!fs.existsSync(inventory)) {
    console.error(`inventory not found: ${inventory}`);
    return 2;
  }
  const { baits, problems, notes } = check(root, inventory);
  notes.forEach((n) => console.log(`• ${n}`));
  problems.forEach((p) => console.error(`✗ ${p}`));
  if (!problems.length) console.log(`✓ ${baits.length} honeytoken(s) consistent`);
  return problems.length ? 1 : 0;
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));
module.exports = { parseInventory, compileIgnore, check, main };
