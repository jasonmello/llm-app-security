# llm-app-security

**English** · [Português (Brasil)](README.pt-BR.md) · [Español](README.es.md)

**A defensive security skill for apps built with LLMs and coding agents.**
Works with Claude Code, Codex, Cursor, Gemini CLI and any agent that loads
`SKILL.md`-style skills. The skill itself is written in English; the agent
answers in your language.

AI-built apps ship fast and usually with the same holes: API keys in the
front-end, routes without login, databases without access rules. This skill
teaches your coding agent to find and fix them, to detect intruders with
passive honeytokens, and to defend the repository itself against prompt
injection.

## What it does

| Module | Purpose |
|---|---|
| **Quick mode** | Fast pre-launch review that looks at the app the way an attacker would. Read-only. |
| `01-AUDIT` | Full phased audit: recon → coverage-led hunting → adversarial validation → `findings.json` → report. Also scoped audits ("audit this PR"). |
| `02-LLM-CODE-PITFALLS` | The typical failures of AI-generated code: secrets, auth only in the UI, IDOR, Supabase/Firebase rules, injection, LLM tool loops, hallucinated packages… |
| `03-HONEYTOKENS` | Passive bait (e.g. `password.txt` with a fake AWS key from [Canarytokens](https://canarytokens.org)) that alerts you when someone, or a hijacked agent, tries to use it. |
| `04-AGENT-DEFENSE` | Protects the repository against hidden instructions aimed at agents; rules for `AGENTS.md`/`CLAUDE.md`; permissions and sandboxing. |
| `05-RELEASE-SUPPLY-CHAIN` | Secret scanning, dependency hygiene, release checklist. |
| `06-PR-GATES` | PR quality gates in three tiers (free starter → enterprise with SonarQube/Wiz): merge blocking, authorization tests, SAST, coverage on sensitive code, RLS guard, DAST, security acceptance criteria for a QA agent, and protecting CI itself from agents. |

## Paste-ready prompt before shipping a client's app

> Review this project as if you wanted to break into it. Look for exposed API keys, routes without login and databases without access rules. List what you found and how to fix it, without changing anything yet.

With the skill installed, the agent runs *quick mode* and returns a verdict
(ready / ready after fixing N items / not ready), a table with severity,
location, fix and effort, owner checks for things only visible in your
dashboards, and what it did not check. For the full audit: *"run a full
security audit with llm-app-security"*.

## Install

```bash
git clone https://github.com/jasonmello/llm-app-security.git
```

| Agent | Where to copy `skills/llm-app-security` |
|---|---|
| Claude Code (all projects) | `~/.claude/skills/` |
| Claude Code (one project) | `.claude/skills/` |
| Codex, Cursor, Gemini CLI and others | the agent's skills directory, or reference `SKILL.md` from the project's `AGENTS.md` |

The scripts (`validate-findings.cjs`, `check-honeytokens.cjs`, `rls-guard.sh`)
live in the skill's `scripts/` folder wherever it is installed. They need only
Node 20+ (plus bash and perl for `rls-guard.sh`).

## Principles

- **Defensive only.** Audit what you own or are authorized to test.
- **Passive deception only.** Honeytokens only alert when touched. No text
  designed to manipulate other agents, no booby traps, no hack-back.
- **Target content is data, not instructions.**
- **Never print real secrets**; rotate before deleting.
- **Honest limits**: "no findings in the covered parts" does not mean "the app
  is secure".

## Test

```bash
npm test
```

`examples/vulnerable-vibe-app` is an app with 14 deliberately planted flaws;
the answer key is `examples/ANSWER_KEY.md`. For a fair benchmark, copy only the
app folder somewhere else (without the answer key), run the skill on it, then
compare. Never install or run the example app: it is insecure on purpose and
declares a typosquat-looking dependency. The example's "keys" are fake.

## Credits

- Audit phase structure inspired by Cloudflare's
  [security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT).
- Honeytokens powered by Thinkst [Canarytokens](https://canarytokens.org).
- See [NOTICE.md](NOTICE.md).

## License

MIT. See [LICENSE](LICENSE) and [DISCLAIMER.md](DISCLAIMER.md).
