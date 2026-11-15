# 01 — Audit workflow

A phased audit. The phase structure (recon → coverage-led hunting →
adversarial validation → schema-checked findings → report) follows the design
of Cloudflare's MIT-licensed `security-audit-skill`; the text and checklists
here are our own and tuned for small, AI-built apps. See NOTICE.md in the
repository (https://github.com/jasonmello/llm-app-security).

If your agent supports subagents, run hunters and verifiers as separate,
fresh subagents so a verifier never inherits the hunter's conclusion. If not,
do the phases sequentially and re-read the code from scratch when verifying.

## Phase 1 — Recon (map before you hunt)

Produce `security/architecture.md` with:

- **Stack**: frameworks, runtime, hosting (Vercel, Netlify, Cloudflare,
  Supabase, Firebase, Lovable, Bolt, Replit…), package manager.
- **Entry points**: HTTP routes, server actions, API handlers, direct
  browser-to-database calls (Supabase/Firestore SDK in client code: guarded
  only by RLS/rules), webhooks, cron jobs, queue consumers, CLI commands,
  Electron IPC handlers, deep links, MCP/LLM tools.
- **Trust boundaries**: browser ↔ server, server ↔ database, server ↔
  third-party APIs, server ↔ LLM, user content ↔ agent context.
- **Identity**: how users authenticate, where the session is checked, roles.
- **Data stores**: tables/collections, which hold personal or payment data,
  what row-level rules exist.
- **Secrets**: where config is loaded, which env vars exist, which reach the
  client bundle (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`).
- **LLM features**: prompts that include user content, tools the model can
  call, outputs rendered as HTML or executed.

Then write `security/coverage-ledger.json`: one unit per entry point, data
store, auth component, LLM feature and build/release config. Status starts
`pending`.

Quick inventory commands (read-only):

```bash
git ls-files | head -500
git log --oneline -20
grep -rEn "(app|router)\.(get|post|put|patch|delete)\(|export (async )?function (GET|POST|PUT|PATCH|DELETE)" --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" --include="*.mjs" . | grep -v node_modules
grep -rEn "process\.env\.|import\.meta\.env\." --include="*.js" --include="*.ts" --include="*.jsx" --include="*.tsx" --include="*.mjs" . | grep -v node_modules
git log --all --diff-filter=A --name-only --format= | grep -Ei '\.env|secret|credential|key|\.pem$' | sort -u
# Python routes and config
grep -rEn "@(app|router|bp)\.(get|post|put|patch|delete|route)\(|APIRouter\(|path\(|os\.(environ|getenv)|BaseSettings" --include="*.py" . | grep -v venv
# Next.js server actions and client components that talk to the database directly
grep -rlE "^['\"]use (server|client)['\"]" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" . | grep -v node_modules | xargs grep -nE "supabase\.from|from\(['\"]|firestore|getDocs|setDoc" 2>/dev/null
```

No git repo? Use `find . -type f -not -path '*/node_modules/*' -not -path '*/.venv/*' | head -500`
instead of `git ls-files`, record history as unknown, and treat any
real-looking secret as exposed.

The last command finds secret-looking files that were ever committed, even if
deleted since.

## Phase 2 — Hunt (coverage-led)

Work unit by unit from the ledger, in this order: unauthenticated surfaces
first; then units touching the most valuable resource (secrets, cross-tenant
data, money, code execution); then changed files and units left open by a
prior run. For each unit, check the attack classes that apply, using
[02-LLM-CODE-PITFALLS.md](02-LLM-CODE-PITFALLS.md) as the checklist:

| Class | Ask |
|---|---|
| `secrets` | Any key, token, password or private URL in code, history, client bundle, logs? (Skip planted honeytokens if the user keeps an inventory.) |
| `authn` | Can the endpoint be reached without a valid session? Is auth only in the UI? |
| `authz` / `idor` | Can user A read or change user B's data by changing an ID? Admin checks server-side? |
| `data-isolation` | Supabase RLS on every table? Firebase rules not `true`? Multi-tenant filter on every query? |
| `injection` | SQL/NoSQL built with strings? Shell exec with input? Path joins with input? Template/HTML injection (XSS)? SSRF via user-supplied URLs? |
| `llm` | Prompt injection reaching tools with side effects? Model output rendered as HTML, run as code or SQL? System prompt holding secrets? Unbounded token spend? |
| `agent-injection` | Repo/issue/doc content trying to instruct coding agents? |
| `input-validation` | Types, sizes, enums validated on the server (zod/valibot/pydantic)? File uploads checked? |
| `session` | Cookie flags (HttpOnly, Secure, SameSite), JWT verified (alg, exp, signature), logout invalidates? |
| `cors-csrf` | `Access-Control-Allow-Origin: *` with credentials? State-changing GET? CSRF on cookie auth? |
| `rate-limit` | Login, signup, password reset, OTP, LLM endpoints, email sending rate-limited? |
| `payments` | Prices computed server-side? Webhook signatures verified? Idempotency? |
| `supply-chain` | Hallucinated or typo-squatted packages? Unpinned installs, postinstall scripts, abandoned deps? |
| `config` | Debug mode, verbose errors, open admin panels, default credentials, permissive security headers? |
| `business-logic` | Paywall, credits, quotas, coupons enforced server-side? Races on balances? |
| `data-exposure` | Responses or client props carrying more fields than the UI shows? |
| `file-upload` | Type/size checked server-side, served from another origin, filenames sanitized? |
| `crypto` | Tokens/OTPs from `Math.random()`, weak password hashing, homemade encryption? |
| `desktop-mobile` | Electron `nodeIntegration`, `contextIsolation: false`, unsafe IPC, `shell.openExternal` with input; mobile keys in bundle? |

**Fingerprints.** Give each root cause a stable id that survives reruns:
`<category>/<repo-path>/<symbol-or-route>` (e.g.
`idor/app/api/orders/[id]/route.ts/GET`, or `idor/server.js/api/orders/:id/GET`
for Express/Flask). No spaces; never include a line number, run, severity or
verdict. Before raising a candidate, match it against prior
findings by fingerprint. `LAS-NNN` is only the display number in this report.

**Variants.** After a high/critical authz, IDOR or RLS finding, grep sibling
handlers and policies for the same shape: AI-generated code copy-pastes. Same
root cause → add the locations to that finding; a different cause → its own
finding. Stop once the question is settled either way.

**With subagents**, give each hunter: `architecture.md` verbatim, its unit ids
and paths, the relevant 02 sections copied in full (not just their names),
classes excluded with reasons, and units owned by other hunters. Group related
units of one subsystem per hunter. In a full audit add two special hunters:
one that works through quick-mode items 1–7 literally (a hit is a candidate,
not a finding, until its impact is traced), and one wildcard asked about API
calls the UI never makes, half-finished features, features combined in ways
nobody designed, what the tests do not test, and every "this is safe because"
comment. Each hunter returns one JSON object, not prose:

```json
{"units": [{"id": "u-orders", "disposition": "covered|candidate|blocked",
  "paths": ["app/api/orders"], "checks": [{"class": "idor", "result": "owner filter present"}]}],
 "candidates": [{"fingerprint": "idor/app/api/orders/[id]/route.ts/GET", "class": "idor",
  "location": "app/api/orders/[id]/route.ts:14", "attack_path": "one sentence"}],
 "hardening": ["non-findings worth mentioning"],
 "uncovered": ["new entry points or surfaces found that are not in the ledger"]}
```

Update the ledger from these results; `uncovered` items become new units.

**Coverage critic.** After the hunting pass, a fresh read-only critic (or you,
from scratch, without subagents) looks for: entry points not in the ledger,
parallel paths to the same effect (a second Supabase client, a cron route, an
old API version), classes with no unit, exclusions without a reason, units
marked covered without evidence, and prior gaps nobody addressed. It returns
`{"missing_units": [], "reassign_ids": [], "stop": true|false}`. At most two
waves; whatever is left becomes `deferred` with a reason. Coverage counts as
clean only after a critic finds nothing.

Ledger statuses: `covered` (with `classes_checked`, and after validation the
`fingerprints` of every finding the unit produced, rejected ones included),
`candidate` (during hunting, with `fingerprints`), `partial`, `deferred`, `out_of_scope`, `not_applicable` (each
with a `notes` reason), `pending` (not started).

## Phase 3 — Validate (try to disprove)

For each unique candidate, a fresh verifier tries to prove it is **not** real:

- Is the code reachable from an entry point? Write the `trace`:
  `entrypoint` → `propagation` steps → `sink` (a committed secret is just a
  `sink`). The verifier re-opens every step.
- Is there a guard elsewhere (middleware, RLS, framework default) that stops it?
- Is the input actually attacker-controlled?
- What does the attacker concretely gain?

Outcomes:

- `confirmed`: path traced end to end, guard absent. Has severity,
  `confidence` (`observed` if you read every step, `inferred` otherwise),
  impact and fix; optionally a `regression_test` (feeds 06 §4).
- Missing RLS or permissive policies seen in migrations are `confirmed` with
  `confidence: inferred` and "live state not checked" in coverage, not
  `needs_validation`.
- `needs_validation`: a decisive fact is outside the repo or needs execution.
  **No severity, no fix.** Name the exact missing fact in `blockers` and give
  a `validation_plan`: `owner_check` is something the user can look at
  themselves (e.g. "Supabase → Table editor → invoices → RLS shows Enabled",
  "Vercel → Settings → Environment Variables → Preview"), `local` is a safe
  local check. Never a parking place for a hunch: first make sure the code
  cannot answer it.
- `rejected`: with `rejection_reason`. Keep rejected records: matched by
  fingerprint, they stop the next run from re-raising the same unchanged claim.

Without subagents, do this yourself: re-read each candidate's path cold, from
the entry point, and write what you checked in `verification`.

Execution-based proof only inside an OS-level sandbox against a local copy,
never against production.

## Phase 4 — Findings file

Write `security/findings.json` following
[templates/findings.schema.json](templates/findings.schema.json) and run the
validator (command in SKILL.md "Outputs") on both `findings.json` and
`coverage-ledger.json`; it also cross-checks fingerprints between them. Fix
errors before reporting. One finding per root cause: list every location and
fix it needs, and do not combine distinct root causes. Placeholder values
follow SKILL.md ground rule 8.

Set `profile` (`full` or `scoped`) and `run_status`. If time or context runs
low: stop hunting, validate what you have, set `run_status: "incomplete"` with
`incomplete_reason`, and leave unfinished units `pending` or `deferred`. A run
with pending units is never `complete`.

Severity guide:

- **critical**: unauthenticated access to all users' data; payment bypass;
  RCE (including an auto-update fetched over plain HTTP); any real secret key
  granting billable or data access (`service_role`, `sk_live_`,
  OpenAI/Anthropic, AWS, DB URLs with password); IDOR or injection exposing
  the whole database from any account when signup is open (or when another
  finding hands out credentials or sessions to anyone); payment bypass means a
  client-supplied price or amount persisted or charged without the server
  re-deriving it or a verified provider webhook confirming it; prompt
  injection reaching payment or side-effect tools with no confirmation.
- **high**: account takeover; cross-tenant read/write needing an account;
  plaintext or reversible password storage (critical if a reachable path dumps
  it); a non-existent or typo-squatted dependency in the manifest; secrets or
  override codes in a system prompt; LLM output rendered as HTML when the
  model reads third-party or retrieved content; reflected-origin CORS with
  credentials on cookie auth; agent-injection that tells agents to run
  commands, fetch code or hide findings; stored XSS in admin views; SSRF
  reaching cloud metadata or internal services (critical only when credential
  theft is demonstrated).
- **medium**: limited IDOR (only non-sensitive fields, or a precondition the
  attacker cannot meet; unguessable UUIDs do not make an IDOR limited, IDs
  leak); missing rate limit on auth/LLM endpoints; reflected
  XSS; verbose errors leaking internals in production; hidden agent
  instructions that only bias reviews.
- **low**: hardening gaps with no direct exploit path; a signed webhook
  missing only replay protection (medium if a replay moves money or credits).
- **info**: observations, good practices to adopt.

High vs medium: does the flaw fully defeat an explicit control (high) or only
weaken it (medium)? Chained flaws: rate a flaw behind a broken control at its
reachable impact today and say it depends on finding #N (one level lower once
that is fixed).

Severity never exceeds the impact you demonstrated. Not findings: self-XSS,
an attacker acting on their own data, the user's own intentional request
executed by the model, and injected text that has no tool, data or rendering
to abuse. Telling a model "don't do X" in its prompt protects nothing, but a
missing instruction of that kind is not a vulnerability on its own.

## Phase 5 — Re-verify, then report

Before reporting, re-open every `confirmed` finding's trace and check the claim
still matches the current code. Re-check `needs_validation` blockers too, so
the user's time is not spent on a false premise. Any upgrade to `confirmed` or
severity increase at this stage gets a second cold look.

Then write `security/REPORT.md` in the user's language (keep code, identifiers
and paths verbatim). Number findings after sorting by severity. If the
environment refuses the write, paste REPORT.md's full content in chat and say
it was not saved.

1. First line: complete or **partial** (scoped to …, or incomplete because …).
2. One-paragraph verdict in plain language, plus one line on what is already
   done right.
3. Table of confirmed findings: severity, title, where, effort to fix.
4. Per finding: what is wrong, what an attacker could do, how to fix (code),
   how to verify the fix.
5. **Needs checking**: table of `needs_validation` items (no severity), ordered
   by what it would mean if true, each with its owner check.
6. Coverage: counts by ledger status, final critic result, what was not audited.
7. Recommendations: missing controls from 04/05/06 (CI gates, secret
   scanning, agent rules), as advice, not findings. Hardening notes go here.
8. Next steps: rotate confirmed real secrets first, then criticals, then the
   PR gates in 06 so it does not regress. End with: which fixes should I apply?

Zero confirmed findings is a valid result. Do not invent low-severity items to
fill the report.

## Repeat and scoped runs

- Load the prior ledger and findings. Record `target.commit` and
  `target.dirty` (uncommitted changes make a different revision).
- A prior confirmed finding carries over only if its source is unchanged, and
  it is re-verified. If its source changed, it becomes a revalidation unit
  (`prior_status: changed`).
- A prior rejection suppresses only the same unchanged claim (same
  fingerprint, same source), never the coverage of that unit.
- Prior `partial`, `deferred` or `pending` units are current work
  (`prior_status: prior_open`).
- A prior quick or scoped run never implies the rest is fine.
- **Scoped audit** ("audit this PR", "only the payments code"): set
  `profile: "scoped"` and `target.scope` (paths, subsystem or `base..head`);
  units outside it are `out_of_scope`, never `covered`. Same evidence bar.
