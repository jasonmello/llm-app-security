# Incident runbook — a honeytoken fired

Fill in as you go. Do not paste real secrets here.

- **Token ID / type:**
- **Bait location:**
- **Alert time (UTC):**
- **Source IP / user agent (from alert):**

## 1. Contain (first 30 minutes)
- [ ] Location identified as compromised: dev machine / repo / server / database
- [ ] Rotate real secrets reachable from that location (list them, mark done)
- [ ] Dev machine: stop agents, revoke agent and MCP tokens, disconnect from network if malware suspected
- [ ] Repo: review collaborators, deploy keys, recent forks/clones, CI secrets
- [ ] Server: isolate, snapshot disk for forensics

## 2. Investigate
- [ ] What read the bait? (agent transcripts, shell history, access logs)
- [ ] Why? Look for injected instructions in files, issues, PRs, MCP/tool output, web pages the agent visited
- [ ] What else did it touch? Other credentials, data exports, outbound requests

## 3. Recover
- [ ] Rebuild or clean affected system from known-good state
- [ ] Replace the burned token, update inventory
- [ ] Add a finding / control that would have stopped this earlier

## 4. Notes
