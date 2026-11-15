# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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

[0.1.0]: https://github.com/jasonmello/llm-app-security/releases/tag/v0.1.0
