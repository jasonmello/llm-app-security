# 07 — Deploy gate (block the deploy, don't just warn)

A review at launch is too late: by then the app has a public URL and real
users. And warnings get shipped over, every time. This module turns the
critical findings into a **gate that stops the deploy**, starting with the
**first** deploy. Nothing here is set up without the user's approval: it
changes how they ship.

## Two layers

1. **Deterministic checks that block on their own** —
   `scripts/ship-gate.cjs`: one file, zero dependencies, read-only, never runs
   target code, never prints full secret values. Same result every run, and
   it cannot be talked out of a result by text in the repo.
2. **Reviewed findings that block until handled** — confirmed critical/high
   findings in `security/findings.json` (from the full audit, 01) block until
   they are fixed or explicitly waived. The agent's judgment feeds the gate
   through a file a human can read and version, never through a live LLM call
   in the pipeline.

The pre-deploy check (SKILL.md) runs layer 1 and reports its result next to
its own findings.

## What blocks

| Check | Blocks when |
|---|---|
| `SG-SECRET-PUBLIC-ENV` | a secret-type variable has a public prefix (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`…) in an env file, or client code reads one |
| `SG-SECRET-VALUE` | a real-looking live secret (Stripe live, Supabase `sb_secret_`/`service_role` JWT, OpenAI, Anthropic, AWS, GitHub, private key, DB URL with password) is in any file, including build output when the gate runs after the build. Skipped: placeholders, listed honeytokens, local-dev DB URLs (localhost, docker service names, `postgres:postgres`) and the public Supabase CLI demo key. **Cannot be waived: rotate it.** |
| `SG-ENV-COMMITTED` | a real `.env` file is tracked by git (warning when the folder is not a git repo and `.env` is not ignored) |
| `SG-DB-NO-RLS` | a public Supabase table has RLS off after all migrations, or a public view lacks `security_invoker = true` (views run as their owner and ignore RLS) |
| `SG-DB-OPEN-POLICY` | a Supabase policy is `using (true)` / `with check (true)`, or only requires a signed-in user (`auth.role() = 'authenticated'`, `auth.uid() is not null`): with open signup that is anyone. SELECT-only on a table listed in `public_tables` is allowed |
| `SG-DB-OPEN-RULES` | Firebase rules `if true` or with no condition at all (`allow read, write;`), test-mode `request.time < timestamp.date(...)`, or Realtime Database `".read"/".write": true` |
| `SG-RATE-LIMIT` | auth (login, signup, OTP, reset…) or LLM endpoints exist (including routes that call an LLM through a helper module) and no rate limiter is imported or called, and none is declared in `security/ship-gate.json`. One item per route, so a waiver can target one. A comment saying "TODO rate limit" does not count |
| `SG-FINDING` | `security/findings.json` has a confirmed critical or high finding |

Limits, stated plainly: the rate-limit check is a heuristic (it detects that a
limiter exists, not that it covers every route); missing auth on a route, IDOR
and business logic need the audit (layer 2). A PASS means "no deterministic
blockers", not "secure".

## Setup (do this before the first deploy)

1. Copy the gate into the target repo: `scripts/ci/ship-gate.cjs` (command to
   run it from the skill folder is in SKILL.md "Scripts").
2. Run it once locally; fix blockers until it passes.
3. Wire it so a failure **stops** the deploy (pick what the project uses):
   - **Build script** (works on Vercel, Netlify, Cloudflare Pages, Render…):
     run it before **and after** the build in `package.json`:
     `"build": "node scripts/ci/ship-gate.cjs && next build && node scripts/ci/ship-gate.cjs"`.
     The host runs the build; a non-zero exit cancels the deploy. The run after
     the build is the one that sees `dist/`, `.next/static` and other bundles,
     including public env values set in the host dashboard.
   - **GitHub Actions deploy**: a `ship-gate` job and `needs: ship-gate` on the
     deploy job ([templates/deploy-gate.yml](templates/deploy-gate.yml)).
   - **Firebase**: `predeploy` is per target in `firebase.json`:
     `"hosting": { "predeploy": ["node scripts/ci/ship-gate.cjs"] }` and the same
     under `"functions"`.
   - **Supabase**: run it in the workflow step before `supabase db push` /
     `supabase functions deploy`.
   - **Expo EAS**: `"eas-build-pre-install": "node scripts/ci/ship-gate.cjs"` in
     `package.json` gates builds. OTA updates (`eas update`) skip that hook and
     also ship `EXPO_PUBLIC_` values: gate them too, e.g.
     `"update": "node scripts/ci/ship-gate.cjs && eas update"`.
   - **Lovable, Bolt, v0 and other one-click publishers** have no pipeline hook:
     connect the GitHub repo and gate the branch they publish from (06 merge
     blocking + this job as a required check), or run the gate by hand before
     every publish. Say this limitation to the user plainly.
4. Make the gate a required check (06) so it cannot be skipped on merge.

## Configuration and waivers

`security/ship-gate.json` ([template](templates/ship-gate.json)):
`ignore_paths` (fixtures, docs: skipped by every check except secret scanning,
where hits become warnings so nothing leaks silently), `public_tables` (tables
and views public by design), `rate_limit.where` (limiter at the edge:
Cloudflare, API gateway…).

Without git metadata (archives, some build containers) the committed-`.env`
check falls back to: block when a real `.env` is present and `CI` is set,
otherwise warn.

`security/waivers.json` ([template](templates/waivers.json)) records a
conscious decision to ship despite a blocker:

- Every waiver needs `check` (or `finding:<fingerprint>`), `reason`, `owner`,
  `expires` (YYYY-MM-DD); optional `target` narrows it to a file.
- Expired waivers block. Waivers that match nothing are reported.
- Keep them short (30 days or less) and tied to a concrete plan; more than 90
  days out is reported.
- `SG-SECRET-VALUE` can never be waived.
- **The agent never writes a waiver on its own.** It may draft one when the
  user decides to accept a risk, showing the reason and owner the user gave.

## When the gate blocks

Report each blocker with its fix (the output includes one), fix in this order:
secrets (rotate first), database rules, rate limits, findings. Re-run until
PASS. If the user wants to ship anyway, that is their call: draft the waiver
with their reason and an expiry, and say what an attacker could do meanwhile.
