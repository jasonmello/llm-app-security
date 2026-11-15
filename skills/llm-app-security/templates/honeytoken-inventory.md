# Honeytoken inventory

Keep this file **outside** the repository if the repository is public.

| ID | Type (Canarytokens) | Bait location | Scope | Looks like | Alert channel | Planted | Last test |
|----|---------------------|---------------|-------|------------|---------------|---------|-----------|
| HT-01 | AWS API key | `password.txt` | local | old prod creds | email (owner) | YYYY-MM-DD | YYYY-MM-DD |
| HT-02 | DNS | `config/replica.env` | committed | read replica host | email | | |
| HT-03 | AWS API key | `~/.aws/credentials` | local | profile `[prod-backup-old]` | email | | |

`scripts/check-honeytokens.cjs` finds the columns by header name and reads the
first backticked path in "Bait location". Scope is `local` (untracked, kept
out with `.git/info/exclude`) or `committed` (private repos only).

## Excluded from production builds

List build ignore rules that keep bait out of deployed artifacts
(`.dockerignore`, `.vercelignore`, `files` in package.json):

-
