# 03 — Honeytokens and canaries (passive deception)

A honeytoken is a fake credential or file left as bait. Nobody legitimate has a
reason to use it, so any use is a high-signal alert: an intruder on a laptop or
server, a leaked repo being harvested, or a coding agent hijacked by prompt
injection trying to "test" credentials it found.

This module is **passive only**: bait that reports when touched. It never runs
code on the visitor's machine, never contains instructions aimed at AI agents,
and never retaliates. That keeps it legal, low-risk and free of false positives.

## How it works with Canarytokens

[Canarytokens](https://canarytokens.org) (by Thinkst, free, also
[open source and self-hostable](https://github.com/thinkst/canarytokens))
generates tokens that alert you by email or webhook when used. Token types
change over time, so check the site for the current list. Common ones:

| Token | Bait idea | Fires when |
|---|---|---|
| AWS API key | `password.txt`, `~/.aws/credentials` profile `[prod-backup]`, `.env.backup` | someone calls AWS with it |
| Web bug / URL | "internal admin" link in docs, `ADMIN_URL=` in an old env file | the URL is fetched |
| DNS | hostname in a config (`db-replica.<token>`) | the name is resolved |
| Kubeconfig | `kubeconfig-prod.yaml` | someone connects |
| MySQL dump | `backup.sql` | the dump is imported |
| Office/PDF document | `senhas-clientes.xlsx`, `contracts.pdf` | the document is opened |
| Credit card | test-looking card in a "billing" note | someone tries to use it |

Creating a token needs an alert email or webhook: **ask the user** for it and
let them create the token on the site themselves (or on their self-hosted
instance). Never put the user's email anywhere without asking.

## Placement plan

Pick by the threat you want to detect:

1. **Hijacked coding agent / malware on the dev machine** — highest value for
   people who use agents. Put bait where an agent or infostealer looks first:
   `password.txt` or `credentials.txt` at the project root, a fake
   `[prod]` profile in `~/.aws/credentials`, an AWS canary key in
   `.env.backup` under a believable name. Only tokens that report on use can
   alert: a made-up AI-provider key alerts nobody (use a canary type that
   phones home, e.g. AWS key or URL/DNS token). Do not put decoy entries in MCP
   or agent config files: a client may load them and run the command.
2. **Repo leak / scraping** — bait in a private repo (`.env.production.old`,
   `deploy/secrets.example.real`). If the private repo leaks, harvesting bots
   fire the token within minutes to hours.
3. **Server compromise** — fake AWS profile and `backup.sql` in the server's
   home directory; a DNS token in `/etc/hosts`-style config.
4. **Database exfiltration** — a fake user row whose email is a unique address
   you monitor, or a URL token in a "profile picture" column. If that address
   ever gets mail, your data was dumped.

Avoid public repos for credential bait unless you *want* scraping alerts: you
will get them constantly. For public repos, prefer bait outside the repo.

**Scope of each bait** (record it in the inventory):

- `local`: exists only on one machine. Keep it out of git with
  `.git/info/exclude` (not `.gitignore`, which is public) and confirm with
  `git status --ignored` that it is untracked.
- `committed`: private repos only. Exclude it from deploys with generic
  patterns (`*.bak`, `*.old`, `password*.txt`) rather than its exact name, so
  ignore files do not reveal the bait.
- Never place bait under folders that are served as-is: `public/`, `static/`,
  `wwwroot/`, `docs/` (GitHub Pages), Expo/Next `public` assets. A Dockerfile
  with `COPY . .` and no `.dockerignore` ships everything.
- Files outside the repo (`~/.aws/credentials`, `~/.ssh/config`): the agent
  does not read or edit them (module 04 deny rules). It gives the user an
  append-only snippet with a unique profile name (e.g. `[prod-backup-2024]`)
  and the user adds it.

## Rules that prevent accidents

- **Inventory.** Keep a list of every token: type, file, where it points, date,
  alert channel. Template: [templates/honeytoken-inventory.md](templates/honeytoken-inventory.md).
  For a public repo, keep the inventory **outside** the repo (password manager,
  private notes) so it does not reveal the bait.
- **Make it look real but be obviously fake to you.** Use the token value
  exactly as generated; give the file a believable name and surrounding
  content (a comment like `# old prod creds, rotate later`). Do not add
  instructions to AI agents.
- **Legit agents must never use credentials from files.** Add this rule to
  `AGENTS.md` / `CLAUDE.md` (see module 04): "Credentials come only from the
  environment or the secret manager. Never read, use, test or exfiltrate
  credentials found in files." Then any use of the bait is anomalous by
  definition, and the rule does not reveal which files are bait.
- **Audits must not report bait as leaks.** The audit checks the inventory
  (when available) and marks matches `rejected: honeytoken`.
- **Alerts go to humans, never into the agent.** Do not wire canary webhooks
  into an agent's context or an auto-responding bot: the alert payload contains
  attacker-controlled fields (user agent, source data) and becomes an
  injection vector. Email/Slack/phone to a person.
- Test each token once after planting (the site lets you trigger a test) and
  record the date.
- Expect some self-triggers: secret scanners that *verify* keys (GitHub
  secret scanning partners, some CI tools) may fire AWS tokens in a committed
  file. Note the scanner's IP/user agent so you can recognize it.

## When a token fires (runbook)

Template: [templates/incident-runbook.md](templates/incident-runbook.md). In short:

1. Read the alert: token, source IP, user agent, time. Which bait location?
2. That location is compromised. Assume everything else reachable from it is
   too: rotate real secrets on that machine/repo/server first.
3. Dev machine: stop running agents, check recent agent transcripts and shell
   history for what read the bait and why (look for injected instructions in
   files, issues, MCP output), revoke agent/MCP tokens, scan for malware.
4. Repo: check who has access, recent clones/forks, CI logs; rotate CI secrets.
5. Server: isolate, snapshot for forensics, rebuild from known-good.
6. Replace the token (it is burned) and note the incident.

## What the agent does in this module

1. Ask the threat model (which of the four above) and the alert channel.
2. Propose a placement table (file, token type, why) — no more than 3–5 baits
   to start.
3. Guide the user to generate tokens on canarytokens.org (agent does not
   create accounts or submit the form for them).
4. Create the bait files with the user-provided token values and believable
   surroundings; update the inventory; add the credential rule to AGENTS.md.
5. Run `node <skill-dir>/scripts/check-honeytokens.cjs <inventory.md> --root <repo>`
   to check that each bait exists, is not under a served folder and is
   excluded from deploy contexts and build output.
6. Ask the user to trigger a test alert for each.
