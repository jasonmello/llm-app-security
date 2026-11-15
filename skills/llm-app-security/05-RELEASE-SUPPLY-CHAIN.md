# 05 — Release checklist, dependency hygiene, secret scanning

Habits and settings that keep secrets and bad packages out. The CI workflow
itself lives in [06-PR-GATES.md](06-PR-GATES.md) (one file, not two). Ask the
user before enabling repository settings.

## 1. Secret scanning

- Enable GitHub secret scanning and push protection (repo Settings → Code
  security): free on public repos; private repos need GitHub Secret
  Protection. The user does this; it is a settings change.
- Local and CI scanning with [gitleaks](https://github.com/gitleaks/gitleaks):
  ```bash
  gitleaks git --redact -v                     # whole history
  gitleaks dir --redact .                      # working tree, incl. untracked
  gitleaks git --pre-commit --redact --staged  # pre-commit hook
  ```
- Allowlist honeytokens explicitly (`.gitleaksignore` with their fingerprints)
  so bait does not fail CI — but only in private repos; in a public repo the
  allowlist would reveal the bait.
- If a real secret was ever committed: **rotate it first**, then clean history
  if needed. Rewriting history does not un-leak a key that was public.

## 2. Dependencies

- Commit the lockfile; install with `npm ci` / `pnpm install --frozen-lockfile`.
- Vulnerability scanning: `npm audit --omit=dev`, or
  [osv-scanner](https://github.com/google/osv-scanner) for any ecosystem.
- Dependabot or Renovate for updates (grouped, weekly), including
  `package-ecosystem: github-actions` to bump pinned action SHAs. Auto-merge
  rules: see 06 §3.
- New dependency review (especially ones an AI suggested): does it exist, who
  maintains it, when was it created, weekly downloads, install scripts?
  `npm view <pkg> time.created maintainers repository scripts`.
- Consider `npm config set ignore-scripts true` for installs in CI where
  scripts are not needed.

## 3. CI

Use the workflow in [templates/pr-gates.yml](templates/pr-gates.yml) and the
hygiene rules in 06 §3. If the project does not use dependency review or
osv-scanner, add `npm audit --omit=dev --audit-level=high` to its
`build-test` job.

## 4. Release checklist

- [ ] No secret-class keys in client env prefixes; built bundle grepped for key patterns.
- [ ] Source maps not publicly served unless intended.
- [ ] Debug flags off, error messages generic in production.
- [ ] Security headers set (CSP, HSTS, `X-Content-Type-Options`, `frame-ancestors`).
- [ ] Database rules reviewed after the last migration.
- [ ] Rate limits on auth and LLM endpoints.
- [ ] Backups exist and a restore was tested.
- [ ] Honeytokens (if any) excluded from production builds and inventory up to date.
- [ ] Someone receives alerts (canary email, error tracker, uptime).
