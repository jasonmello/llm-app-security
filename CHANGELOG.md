# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.6.0] - 2026-11-15

### Added
- Tool annotation honesty (02 §6): MCP hints are claims, not controls. A
  `readOnlyHint` tool that writes (raw SQL included), or a `destructiveHint:
  false` tool that deletes or overwrites, is an approval bypass in clients that
  skip confirmation on those hints (ChatGPT developer mode, claude.ai
  connectors). WebMCP hints default to `false`, so a WebMCP tool with
  irreversible effects and no `consequentialHint` is the usual finding. Fixes by
  construction: confirmation decided by server-side policy, read-only tools get
  read-only clients, server-side confirmation (plus Claude Code's
  `requiresUserInteraction`).
- Pre-deploy check item 5 and the 01 severity guide cover it (high only when a
  client skips confirmation on the hint and the tool has a side effect).
- 04 §4: never auto-approve third-party tools because of their annotations.
- 06 §4: acceptance criterion and a spy-based unit test (handlers built from
  injected clients; SQL text inspected, so raw `query("update ...")` is caught),
  with its limit stated: evidence, not proof.
- Pre-deploy check: a ship-gate block decides the verdict, but the row keeps
  its severity from the 01 guide.
- Example app: an MCP server with a dishonest `readOnlyHint` tool and a
  genuinely read-only decoy; answer key now has 17 flaws.

Not added to the ship-gate on purpose: tracing tool handlers across files by
pattern would block on false positives and miss real cases.

## [0.5.0] - 2026-11-15

Result of running J.A.S.O.N. on its own repository: 23 findings, all confirmed
by an adversarial verifier, all fixed here with regression tests.

### Security
- **v0.4.0 users: re-copy `scripts/ci/ship-gate.cjs`.** In 0.4.0 the gate's
  own source contained strings it treats as evidence of a rate limiter, so a
  copy placed in the repo (as documented) silently disabled `SG-RATE-LIMIT`.
  The gate's patterns are now assembled so its source never matches itself.
- `check-honeytokens.cjs` ran `git` inside the audited repo, so a planted
  `core.fsmonitor` command would execute. It now runs git outside the repo with
  fsmonitor disabled (same as the gate).
- A placeholder word anywhere on the same line (e.g. `// EXAMPLE`) hid a real
  secret from the gate. Placeholders are now judged on the value only.
- The honeytoken inventory exempted whole files from every check. Committed
  bait values are now registered as bare SHA-256 hashes in `.jason/gate.json`
  (`--honeytoken-hashes` prints them); the list names no files, and every other
  value, line and file is still checked.
- Files starting with a UTF-16 byte-order mark, or containing NUL bytes, could
  hide secrets; both decodings are now scanned and NULs are stripped.
- Any file named like a lockfile was skipped; now only real lockfiles next to
  their manifest and outside public/build folders are.

### Changed
- Gate inputs moved to the committed `.jason/` folder (`gate.json`,
  `waivers.json`): `security/` is git-ignored, so CI never saw them. The old
  `security/ship-gate.json` and `security/waivers.json` are ignored (with a
  warning) so a waiver outside CODEOWNERS can never apply. Put `.jason/` and
  `scripts/ci/` under CODEOWNERS.
- Templates are safe to copy as-is: `gate.json` has a placeholder that blocks
  until filled in, `waivers.json` is empty.
- `rate_limit.covers` now narrows a declared edge limiter; without it every
  route is listed as an assumed-covered warning.
- Waivers reject placeholder or bot owners; `target` matches a path prefix.
- Secret scan now covers `.claude/`, `vendor/`, `coverage/`, build caches,
  UTF-16 files and files named `*.lock` that are not real lockfiles; text-like
  files with NUL bytes are reported.
- RLS check rebuilt on a single-pass SQL lexer (strings, quoted identifiers,
  nested comments, dollar quotes): tracks renames, `SET SCHEMA`, multi-table
  `DROP`, multi-action `ALTER`, `SELECT INTO`; reads large migrations
  (unreadable ones block); flags materialized views and open policies written
  as `((true))`, `true or …` or `1=1`. `rls-guard.sh` gets the string and
  `DROP TABLE` fixes and follows a symlinked migrations folder.
- Rate limit: routes in subfolders named like tool dirs are checked;
  devDependencies and examples/docs/tests no longer count as a limiter; the
  output says where the limiter evidence came from; Fastify/Hono-style routes
  and more LLM SDKs (Gemini, Groq, Mistral, AI SDK, LangChain) are detected.
- Firebase: comment markers inside strings no longer hide rules, parenthesized
  `true` is caught, and rules files named in `firebase.json` are checked.
- Inputs (config, waivers, findings, migrations) that are symlinks pointing
  outside the repository are refused; an empty waiver `target` is rejected.
- Threat model stated in 07: the gate catches mistakes, not a committer who
  deliberately evades it; CODEOWNERS and the `db-rules` job cover that.
- Firebase: unconditional and `1 == 1` rules block; write rules without
  `request.auth` warn.
- Linear-time parsing guards against crafted files (JWT, SQL dollar quotes,
  line numbers); per-file match cap.
- `mini-schema` ignores inherited properties (`__proto__`, `constructor`).
- Pre-deploy output lists every waived item, ignored path and declared limiter
  next to the gate result. 04 §1 scan works in zsh. `deploy-gate.yml` runs the
  gate again after the build.

## [0.4.0] - 2026-11-15

A review at launch is too late and warnings get shipped over: J.A.S.O.N. now
gates the deploy.

### Added
- `scripts/ship-gate.cjs`: deterministic, read-only deploy gate (single file,
  zero dependencies). Blocks on secrets with public env prefixes or read by
  client code, real-looking live secrets (including build output and Supabase
  `service_role` JWTs), committed `.env`, Supabase tables without RLS and open
  policies, open Firebase rules, auth/LLM endpoints without rate limiting, and
  confirmed critical/high findings. Exit 1 = do not deploy.
- Expiring waivers (`security/waivers.json`) with reason and owner; leaked
  live secrets cannot be waived. Config in `security/ship-gate.json`
  (`ignore_paths`, `public_tables`, `rate_limit.where`).
- Module `07-DEPLOY-GATE.md`: setup before the first deploy for build scripts
  (Vercel, Netlify, Cloudflare Pages), GitHub Actions (`needs: ship-gate`),
  Firebase predeploy, Supabase and Expo EAS; honest limits for one-click
  publishers.
- Templates: `deploy-gate.yml`, `ship-gate.json`, `waivers.json`; ship-gate job
  in `pr-gates.yml`.
- Tests: the example app is blocked, a fixed copy passes, waivers, Firebase,
  honeytoken exclusion, findings, CLI exit codes, and regressions from an
  independent evaluation on 5 generated apps (15 true positives, 0 false
  positives; the 4 in-scope misses it found are now blocked: unconditional
  Firebase rules, LLM routes calling a helper, authenticated-only policies,
  views without `security_invoker`).
- No unwaivable false positives on local-dev values (localhost or docker DB
  URLs, Supabase CLI demo key); honeytoken bait skipped by every check;
  `ignore_paths` never hides secrets (they become warnings); one rate-limit
  item per route so waivers can target a route; waiver dates validated.

### Changed
- Quick mode is now the **pre-deploy check**: meant for before the first deploy,
  starts with the ship-gate, and its verdict is "do not deploy" when there is a
  blocker or a critical.
- README (EN/pt-BR/ES): deploy gate section, pre-deploy wording.

## [0.3.0] - 2026-11-15

### Changed
- New name: **J.A.S.O.N. — LLM App Security** (Just Audit, Secure, Observe,
  Notify), named after its author. The skill is now `jason`: the folder moved
  from `skills/llm-app-security` to `skills/jason`, so manual installs must copy
  the new folder (and Codex `AGENTS.md` snippets must point to
  `.skills/jason/SKILL.md`). Delete the old `llm-app-security` skill folder
  before copying the new one, or two overlapping skills stay installed.
  Invoke with `/jason`, or `/llm-app-security:jason` as a plugin.
- The repository, the plugin id and its install commands are unchanged.
- README (EN/pt-BR/ES): new title, acronym table, origin of the name; icon
  with a discreet 13.

## [0.2.1] - 2026-11-15

### Changed
- README lists only the agents actually tested (Claude Code, OpenAI Codex CLI);
  Gemini CLI and Cursor removed.

### Added
- Plugin icon. The official `claude plugin validate` passes with no warnings
  and now runs in CI (pinned Claude Code version).

## [0.2.0] - 2026-11-15

### Added
- Claude Code plugin: `.claude-plugin/plugin.json` and a marketplace manifest,
  so users can install with `/plugin marketplace add jasonmello/llm-app-security`
  and `/plugin install llm-app-security@llm-app-security`.
- README: real quick-mode example answer (EN, pt-BR, ES) and plugin install.
- Test that checks the plugin and marketplace manifests.

### Changed
- Script paths in the skill use `${CLAUDE_SKILL_DIR}` so they resolve when
  installed as a plugin; other agents use the skill's own folder.
- Compatibility: tested with OpenAI Codex CLI through `AGENTS.md` (in addition
  to Claude Code).

## [0.1.0] - 2026-11-15

First public release.

### Added
- Quick mode: read-only pre-launch review (exposed keys, routes without login,
  databases without access rules), with owner checks for facts only visible in
  dashboards. Answers in the user's language.
- Full and scoped audits: recon, coverage ledger, coverage-led hunting with a
  coverage critic, adversarial validation, stable fingerprints,
  status-specific findings (confirmed / needs_validation / rejected), report.
- Pitfalls of AI-generated code: secrets, auth, IDOR, mass assignment,
  Supabase and Firebase rules, Next.js server actions, LLM tool loops,
  injection, deserialization, supply chain, desktop and mobile.
- Passive honeytokens with Canarytokens: placement plan, inventory, incident
  runbook and `check-honeytokens.cjs`.
- Repository defense against prompt injection aimed at coding agents.
- Release hygiene and PR quality gates in three tiers, with a SHA-pinned
  starter workflow and the `rls-guard.sh` Supabase migration check.
- Zero-dependency validators, tests, and a deliberately vulnerable example app
  with an answer key.
- README in English, Portuguese (Brazil) and Spanish.

[0.6.0]: https://github.com/jasonmello/llm-app-security/releases/tag/v0.6.0
[0.5.0]: https://github.com/jasonmello/llm-app-security/releases/tag/v0.5.0
[0.4.0]: https://github.com/jasonmello/llm-app-security/releases/tag/v0.4.0
[0.3.0]: https://github.com/jasonmello/llm-app-security/releases/tag/v0.3.0
[0.2.1]: https://github.com/jasonmello/llm-app-security/releases/tag/v0.2.1
[0.2.0]: https://github.com/jasonmello/llm-app-security/releases/tag/v0.2.0
[0.1.0]: https://github.com/jasonmello/llm-app-security/releases/tag/v0.1.0
