# 06 — PR quality gates (so fixed holes stay fixed)

An audit is a snapshot. Gates on every pull request keep new holes out,
especially when agents write and open the PRs. Nothing here is applied without
the user's approval: rulesets, required checks and CI files change how the
whole team merges.

## 1. Pick a tier

| Tier | For | Required checks |
|---|---|---|
| **Starter** (~1 h) | solo dev, Lovable/Bolt/v0 app, small client project | branch protection · build + tests · secrets (gitleaks) · dependencies · ship-gate (07) |
| **Team** | a few devs, paying users | Starter + SAST (Semgrep/CodeQL) · authz tests · coverage on sensitive paths · IaC/container scan · DB-rules job · CODEOWNERS review |
| **Company** | regulated data, many repos | Team + commercial platforms (SonarQube, Wiz, Snyk…) · DAST on preview · security acceptance criteria checked by a QA agent · signed commits/releases |

**Plan limits (check before promising).** Rulesets and branch protection work
on public repos for free; on **private** repos they need GitHub Pro (personal)
or Team/Enterprise (org). On a private repo on GitHub Free, checks run but
cannot block merges: say so, and offer the upgrade or treat gates as advisory.
Dependency review and CodeQL on private repos need GitHub Code Security; push
protection on private repos needs GitHub Secret Protection. Use the free
alternatives in §2 there.

Start at Starter, move up when the app has real users or money. Ten checks
nobody reads are worse than four that block merges.

## 2. Gates and what each one catches

| Gate | Catches | Free/OSS option | Commercial equivalent |
|---|---|---|---|
| **Merge blocking** | merges that skip checks, direct pushes | Ruleset: required checks (expected source: GitHub Actions), no force push, empty bypass list; **≥1 approval only if a second human exists** (solo: 0 approvals + required checks); dismiss stale approvals and require approval of the latest push; "Require conversation resolution" | — |
| **Build + tests** | broken behavior | your test runner | — |
| **Authz tests** | IDOR, routes without login, admin bypass (the #1 bug in AI-built apps; tools rarely find it) | tests per protected resource (§4) | — |
| **Secrets** | keys committed in the PR | gitleaks CLI (MIT); GitHub secret scanning also covers PR titles, bodies and comments (public repos; private needs Secret Protection) | GitGuardian, Wiz |
| **Dependencies** | known-vulnerable or risky new packages | `dependency-review-action` (public / Code Security), osv-scanner (any) | Snyk, Socket, Wiz |
| **SAST** | injection, unsafe APIs | Semgrep CE; CodeQL (free on public repos) | SonarQube (Cloud), Snyk Code |
| **Coverage** | untested auth/payment code | thresholds per path, e.g. Vitest `coverage.thresholds: { 'src/auth/**': { lines: 90, branches: 85 } }`, Jest `coverageThreshold: { './src/auth/': { branches: 85 } }`. Coverage proves code ran, not that authz is right | SonarQube quality gate, Codecov |
| **IaC / container** | public buckets, open security groups, root containers, vulnerable images | Trivy, Checkov | Wiz |
| **DAST** | missing headers, insecure cookies, open CORS on the running app | ZAP baseline (`zaproxy/action-baseline`, pin SHA) with `fail_action: true` (default is false, so it never blocks), `allow_issue_writing: false`, a rules file to tune noise; target the preview URL | Burp Enterprise, Wiz |
| **DB rules** | tables without RLS, open policies, RLS-bypassing views, `security definer` open to anon, public buckets | Starter: `scripts/rls-guard.sh` (heuristic). Team: `db-rules` job (query after `supabase db start`) + pgTAP (`supabase test db`). Firebase: `firebase emulators:exec --only firestore,storage "npm run test:rules"` with `@firebase/rules-unit-testing` (`assertFails` for another user and for unauthenticated) | — |
| **Deploy gate** | exposed secrets, open database rules, missing rate limits, unhandled critical findings reaching production | `scripts/ship-gate.cjs` as a required check here **and** before the deploy itself ([07](07-DEPLOY-GATE.md)) | — |
| **Security review (agent)** | logic flaws tools miss | this skill's pre-deploy check on the PR diff, posted safely (§3) | AI review products |

Ready-to-copy workflow: [templates/pr-gates.yml](templates/pr-gates.yml)
(Starter jobs plus the Team `db-rules` job commented out). Copy
`scripts/rls-guard.sh` to `scripts/ci/rls-guard.sh` in the target repo.

## 3. Agents and CI: protect the pipeline itself

- **A PR can rewrite the workflow that gates it** (`pull_request` runs the
  PR's version). Turn on **Require review from Code Owners** with a human
  owner of `.github/` who is not the PR author. Solo: review every diff to
  `.github/` yourself. On Team/Enterprise orgs, prefer **Require workflows to
  pass** (the workflow lives in a repo the PR cannot edit).
- **CODEOWNERS on sensitive paths**: `.github/`, CI config,
  `supabase/migrations/`, `firestore.rules`, auth code, `package.json`/lockfiles,
  `AGENTS.md`/`CLAUDE.md`, and the deploy gate itself: `.jason/` (config,
  waivers) and `scripts/ci/`. Otherwise an agent PR can add a waiver or an
  edge-limiter declaration and turn its own required check green.
- **Agent-authored PRs get the same gates.** No bypass actors for bots, no
  auto-merge on agent PRs. Agents never use the owner's PAT (admin tokens
  inherit bypass): fine-grained token or GitHub App without admin. Keep
  "Allow GitHub Actions to create and approve pull requests" off.
- **Workflow hygiene**: `permissions: contents: read` by default;
  `persist-credentials: false` on checkout; never `pull_request_target` with
  checkout of the PR head; pin every third-party action to a full commit SHA
  from day one (tags can be force-pushed: tj-actions 2025, trivy-action 2026);
  no `paths:` filters on required workflows; never interpolate untrusted
  event fields (`${{ github.event.issue.title }}`, PR title/body, branch
  names) directly into `run:` — pass them through `env:` and quote them.
- **Merge queue**: required workflows must also trigger on `merge_group:`;
  skip PR-only jobs there with `if:`.
- **Dependabot/Renovate auto-merge** only for patch updates of dev
  dependencies, after all gates pass, with a release-age delay (Dependabot
  `cooldown`, Renovate `minimumReleaseAge`): compromised packages publish
  malicious patch versions that get auto-merged within hours.
- **Preview deploys**: keep the host's fork protection on; previews use a
  separate non-production Supabase project and keys, never prod `service_role`.
- **AI reviewer pattern**: (a) on `pull_request`, read-only token, the model
  reads the diff and writes findings to an artifact (no write tools); (b) a
  separate `workflow_run` job with `pull-requests: write` and no checkout of PR
  code posts the artifact as a comment, sanitized (strip `@mentions`, cap
  length, render as quoted text, never apply suggestions). It comments, never
  approves or pushes. For fork PRs, run it only after a maintainer adds a label.
- Signed commits (Company) prove which key made a commit, not that the code is
  safe; protect agent signing keys like deploy keys.

## 4. Security acceptance criteria

Add to every user story that touches data (the QA agent or reviewer checks
them; tests encode them):

- [ ] Without login, the endpoint/page returns 401/redirect.
- [ ] User A cannot read, edit or delete user B's resource (change the ID).
- [ ] A non-admin cannot reach admin actions via the API, not just the UI.
- [ ] Input is validated on the server (wrong type, too long, extra fields like `role`).
- [ ] Prices, totals and permissions are computed on the server.
- [ ] New tables/collections have access rules, tested with the public client;
      views use `security_invoker = true`; `security definer` functions are not
      executable by `anon` unless intended; storage buckets private with
      policies scoped to `auth.uid()`; no `using (true)` on user data.
- [ ] No new secret in client code or env vars with public prefixes.
- [ ] LLM features: user content cannot trigger side-effect tools without confirmation.
- [ ] Tools the app exposes (MCP, WebMCP): every `readOnlyHint` tool has a
      test proving its handler performs no writes; every `destructiveHint:
      false` tool, a test proving it never deletes or overwrites; WebMCP tools
      with irreversible effects set `consequentialHint`.

API-backed app (Playwright):

```ts
test('user B cannot read user A order', async ({ request }) => {
  const a = await login(request, 'a@test.local');
  const order = await createOrder(request, a);
  const b = await login(request, 'b@test.local');
  const res = await request.get(`/api/orders/${order.id}`, { headers: auth(b) });
  expect([403, 404]).toContain(res.status());
});
```

Supabase-direct app (no `/api`; RLS hides rows with **200 and an empty
result**, not 403):

```ts
import { createClient } from '@supabase/supabase-js';
const url = process.env.SUPABASE_URL!, anon = process.env.SUPABASE_ANON_KEY!;
const as = async (email: string) => { const c = createClient(url, anon);
  await c.auth.signInWithPassword({ email, password: process.env.TEST_PASSWORD! }); return c; };
test('B cannot read or change A order; anon sees nothing', async () => {
  const a = await as('a@test.local'), b = await as('b@test.local');
  const { data: row } = await a.from('orders').insert({ total: 10 }).select().single();
  expect((await b.from('orders').select().eq('id', row!.id)).data).toEqual([]);
  expect((await b.from('orders').update({ total: 0 }).eq('id', row!.id).select()).data).toEqual([]);
  expect((await createClient(url, anon).from('orders').select()).data).toEqual([]);
});
```

Tool annotation honesty: test the handler with spies, not with a
before/after snapshot of the database (a snapshot misses emails, payments,
queued jobs and writes of an unchanged value). Passing is evidence, not proof:
the stronger fix is giving read-only tools read-only clients (02 §6). Build
handlers from their dependencies so tests can inject spies:

```ts
// tools.ts — handlers built from their clients (also what makes a read-only client possible)
export const createHandlers = (deps: { db: Db; mail: Mail }) => ({
  get_order_status: async ({ orderId }: { orderId: string }) => { /* ... */ },
});

// tools.test.ts
const WRITE_SQL = /^\s*(insert|update|delete|merge|upsert|truncate|alter|drop|create)\b/i;
test('get_order_status (readOnlyHint) performs no writes', async () => {
  const writes: string[] = [];
  const db = { query: async (sql: string) => { if (WRITE_SQL.test(sql)) writes.push(sql); return { rows: [] }; } };
  const mail = { send: async () => { writes.push('mail.send'); } };
  const { get_order_status } = createHandlers({ db, mail } as any);
  for (const orderId of ['o1', 'o2', 'missing']) await get_order_status({ orderId });
  expect(writes).toEqual([]);
});
```

For ORMs, spy on their write methods (`insert`, `update`, `delete`,
`upsert`, `create`) the same way.

Database-level tests: pgTAP in `supabase/tests/*.sql` with
`set local role authenticated; set local request.jwt.claims = '{"sub":"<uuid>"}'`
and `select is_empty($$ select * from orders where id = ... $$)`.

## 5. When the user already has gates

Map their checks onto §2 and report only the gaps. Typical gaps even in mature
setups: no authz tests, no DB-rules gate, bots allowed to bypass, CI files
without enforced Code Owners review, unpinned actions, and sensitive-path
coverage hidden inside a healthy global average.
