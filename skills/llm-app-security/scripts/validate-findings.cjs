#!/usr/bin/env node
'use strict';
// Usage: node validate-findings.cjs <findings.json> [--ledger <coverage-ledger.json>]
// Schema checks plus semantic rules: status-specific fields, fingerprints,
// trace order, repo-relative paths, visible text, run completeness and
// (with --ledger) consistency between ledger and findings.
// Exits 0 when valid, 1 on errors, 2 on usage errors.
const fs = require('node:fs');
const path = require('node:path');
const { validate } = require('./lib/mini-schema.cjs');

const templates = path.join(__dirname, '..', 'templates');
const load = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const visible = (s) => typeof s === 'string' && /\S/.test(s);

function safeRelPath(p) {
  return typeof p === 'string' && p.length > 0 &&
    !p.startsWith('/') && !p.startsWith('~') && !p.includes('\\') &&
    !/^[A-Za-z]:/.test(p) && !p.split('/').some((seg) => seg === '..' || seg === '');
}

function checkFindings(data) {
  const errors = validate(load(path.join(templates, 'findings.schema.json')), data).map((e) =>
    /\.fingerprint: does not match/.test(e)
      ? e.replace(/does not match .*/, 'fingerprint may not contain spaces; allowed: letters digits . _ : / @ + [ ] -')
      : e);
  if (errors.length) return errors;

  if (data.run_status === 'incomplete' && !visible(data.incomplete_reason)) {
    errors.push('run_status incomplete requires incomplete_reason');
  }
  const ids = new Set();
  const fps = new Set();
  for (const f of data.findings) {
    const at = f.id;
    if (ids.has(f.id)) errors.push(`duplicate id ${f.id}`);
    ids.add(f.id);
    if (fps.has(f.fingerprint)) errors.push(`${at}: duplicate fingerprint ${f.fingerprint}`);
    fps.add(f.fingerprint);
    if (/:\d+$/.test(f.fingerprint)) errors.push(`${at}: fingerprint must not end with a line number`);

    for (const k of ['title', 'impact', 'fix', 'evidence', 'attack_path', 'rejection_reason']) {
      if (k in f && !visible(f[k])) errors.push(`${at}: ${k} is blank`);
    }
    for (const loc of f.location) if (!safeRelPath(loc.file)) errors.push(`${at}: location path must be repo-relative: ${loc.file}`);

    if (f.status === 'confirmed') {
      for (const k of ['severity', 'impact', 'fix', 'confidence']) if (!(k in f)) errors.push(`${at}: confirmed requires ${k}`);
      if (!f.trace && !visible(f.attack_path)) errors.push(`${at}: confirmed requires trace or attack_path`);
    } else if (f.status === 'needs_validation') {
      for (const k of ['severity', 'fix']) if (k in f) errors.push(`${at}: needs_validation must not have ${k}`);
      if (!Array.isArray(f.blockers) || !f.blockers.length) errors.push(`${at}: needs_validation requires blockers`);
      if (!f.validation_plan || !(visible(f.validation_plan.local) || visible(f.validation_plan.owner_check))) {
        errors.push(`${at}: needs_validation requires validation_plan.local or validation_plan.owner_check`);
      }
      if (!('impact' in f)) errors.push(`${at}: needs_validation requires impact (what it would mean if true)`);
    } else if (f.status === 'rejected') {
      for (const k of ['severity', 'fix']) if (k in f) errors.push(`${at}: rejected must not have ${k}`);
      if (!visible(f.rejection_reason)) errors.push(`${at}: rejected requires rejection_reason`);
    }

    if (f.trace) {
      const kinds = f.trace.map((s) => s.kind);
      if (kinds.length > 1) {
        if (kinds[0] !== 'entrypoint') errors.push(`${at}: multi-step trace must start at entrypoint`);
        if (kinds[kinds.length - 1] !== 'sink') errors.push(`${at}: multi-step trace must end at sink`);
        if (kinds.slice(1, -1).some((k) => k !== 'propagation')) errors.push(`${at}: middle trace steps must be propagation`);
      }
      const locFiles = new Set(f.location.map((l) => l.file));
      for (const s of f.trace) {
        if (!safeRelPath(s.file)) errors.push(`${at}: trace path must be repo-relative: ${s.file}`);
        else if (!locFiles.has(s.file)) errors.push(`${at}: trace file ${s.file} missing from location`);
      }
    }
  }
  return errors;
}

const NEEDS_NOTES = new Set(['partial', 'deferred', 'out_of_scope', 'not_applicable']);

function checkLedger(ledger, findings) {
  const errors = validate(load(path.join(templates, 'coverage-ledger.schema.json')), ledger);
  if (errors.length) return errors;
  const ids = new Set();
  const referenced = new Set();
  for (const u of ledger.units) {
    if (ids.has(u.id)) errors.push(`duplicate unit id ${u.id}`);
    ids.add(u.id);
    for (const p of u.paths) if (!safeRelPath(p)) errors.push(`${u.id}: path must be repo-relative: ${p}`);
    if (u.status === 'covered' && !(u.classes_checked || []).length) errors.push(`${u.id}: covered requires classes_checked`);
    if (NEEDS_NOTES.has(u.status) && !visible(u.notes)) errors.push(`${u.id}: ${u.status} requires notes with the reason`);
    if (u.status === 'candidate' && !(u.fingerprints || []).length) errors.push(`${u.id}: candidate requires fingerprints`);
    (u.fingerprints || []).forEach((fp) => referenced.add(fp));
  }
  if (findings) {
    const fps = new Set(findings.findings.map((f) => f.fingerprint));
    for (const fp of fps) if (!referenced.has(fp)) errors.push(`finding ${fp} is not referenced by any ledger unit`);
    for (const fp of referenced) if (!fps.has(fp)) errors.push(`ledger references unknown fingerprint ${fp}`);
    if (findings.run_status === 'complete' && ledger.units.some((u) => u.status === 'pending')) {
      errors.push('run_status is complete but the ledger still has pending units');
    }
  }
  return errors;
}

function main(argv) {
  const [file, flag, ledgerPath] = argv;
  if (!file || (flag && flag !== '--ledger') || (flag && !ledgerPath)) {
    console.error('usage: validate-findings.cjs <findings.json> [--ledger <coverage-ledger.json>]');
    return 2;
  }
  let errors;
  try {
    const findings = load(file);
    errors = checkFindings(findings).map((e) => `findings: ${e}`);
    if (ledgerPath) errors.push(...checkLedger(load(ledgerPath), errors.length ? null : findings).map((e) => `ledger: ${e}`));
  } catch (err) {
    console.error(`cannot read input: ${err.message}`);
    return 2;
  }
  if (errors.length) {
    errors.forEach((e) => console.error(`✗ ${e}`));
    return 1;
  }
  console.log('✓ valid');
  return 0;
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));
module.exports = { checkFindings, checkLedger, safeRelPath, main };
