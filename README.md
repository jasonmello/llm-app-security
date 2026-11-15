# llm-app-security

**A defensive security skill for apps built with LLMs and coding agents.**
Works with Claude Code, Codex, Cursor, Gemini CLI and any agent that loads
`SKILL.md`-style skills.

[Português](#português) · [English](#english)

---

## Português

Apps feitos com IA saem rápido e quase sempre com os mesmos buracos: chave de
API no front-end, rota sem login, banco sem regra de acesso. Esta skill ensina
o seu agente a encontrar e corrigir esses problemas, a detectar intrusos com
iscas (honeytokens) e a proteger o próprio repositório contra prompt injection.

### O que ela faz

| Módulo | Para quê |
|---|---|
| **Quick mode** | Revisão rápida antes de subir o app, olhando como um invasor. Só leitura. |
| `01-AUDIT` | Auditoria completa em fases: mapa → caça por cobertura → validação adversarial → `findings.json` → relatório. |
| `02-LLM-CODE-PITFALLS` | As falhas típicas de código gerado por IA (segredos, auth só na UI, IDOR, RLS, injeção, pacotes alucinados…). |
| `03-HONEYTOKENS` | Iscas passivas (ex.: `password.txt` com chave AWS falsa do [Canarytokens](https://canarytokens.org)) que te avisam quando alguém, ou um agente sequestrado, tenta usar. |
| `04-AGENT-DEFENSE` | Proteção do repositório contra instruções escondidas para agentes; regras para `AGENTS.md`/`CLAUDE.md`; permissões e sandbox. |
| `05-RELEASE-SUPPLY-CHAIN` | gitleaks, dependências, CI de segurança, checklist de release. |
| `06-PR-GATES` | Quality gates no PR em 3 níveis (starter grátis → empresa com Sonar/Wiz): bloqueio de merge, testes de autorização, SAST, cobertura em código sensível, guarda de RLS, DAST, critérios de aceite de segurança para o agente de QA, proteção da própria CI contra agentes. |

### Prompt pronto para colar antes de subir o app de um cliente

> revisa esse projeto como se vc quisesse invadir ele. procura chave de API exposta, rota sem login e banco sem regra de acesso. lista o que achou e como corrigir, sem mexer em nada ainda.

Com a skill instalada, o agente entra no *quick mode* e devolve um veredito
("pronto / não pronto para subir"), uma tabela com severidade, local, correção
e esforço, e o que ficou de fora. Para a auditoria completa: *"faz uma auditoria
de segurança completa com a llm-app-security"*.

### Instalação

```bash
git clone https://github.com/OWNER/llm-app-security.git   # troque OWNER pelo dono do repositório
```

| Agente | Onde copiar `skills/llm-app-security` |
|---|---|
| Claude Code (todos os projetos) | `~/.claude/skills/` |
| Claude Code (um projeto) | `.claude/skills/` |
| Codex, Cursor, Gemini CLI e outros | diretório de skills do agente, ou cite `SKILL.md` no `AGENTS.md` do projeto |

Os scripts (`validate-findings.cjs`, `check-honeytokens.cjs`, `rls-guard.sh`)
ficam em `scripts/` dentro da pasta da skill, onde quer que ela esteja
instalada. Só precisam de Node 20+ (e bash/perl para o `rls-guard.sh`).

### Princípios

- **Só defesa.** Audite o que é seu ou o que você tem autorização para testar.
- **Iscas passivas.** Honeytokens só avisam quando tocados. Nada de texto para
  manipular outros agentes, armadilhas que causem dano ou "hack back".
- **Conteúdo do alvo é dado, não instrução.**
- **Nunca imprimir segredos reais**; rotacionar antes de apagar.
- **Limites honestos**: "nenhum achado nas partes cobertas" não quer dizer "app seguro".

### Testar

```bash
npm test
```

`examples/vulnerable-vibe-app` é um app com 14 falhas plantadas de propósito,
com o gabarito em `examples/ANSWER_KEY.md`. Para um teste justo, copie só a
pasta do app para outro lugar (sem o gabarito), rode a skill nela e compare
depois. Não instale nem rode o app: ele é inseguro de propósito e declara uma
dependência com nome de typosquat. As "chaves" do exemplo são falsas.

---

## English

AI-built apps ship fast and usually with the same holes: API keys in the
front-end, routes without auth, databases without access rules. This skill
teaches your coding agent to find and fix them, to detect intruders with
passive honeytokens, and to defend the repo itself against prompt injection.

**Modules:** quick pre-launch check · phased audit with schema-validated
findings · pitfalls of AI-generated code · honeytokens/canaries · agent
defense · release and supply-chain guards · PR quality gates (starter to enterprise, authz tests, security acceptance criteria).

**Paste-ready prompt (pre-launch):**

> Review this project as if you wanted to break into it. Look for exposed API keys, routes without login and databases without access rules. List what you found and how to fix it, without changing anything yet.

**Install:** copy `skills/llm-app-security` into your agent's skills directory
(`~/.claude/skills/` for Claude Code; the agent's skills folder or a reference
in `AGENTS.md` for others). Scripts live in the skill's `scripts/` folder and
need only Node 20+ (plus bash/perl for `rls-guard.sh`).

**Principles:** defensive only · passive deception only (no instructions aimed
at other agents, no booby traps, no hack-back) · target content is data ·
never print real secrets · honest coverage limits.

**Test:** `npm test`; for a fair benchmark copy `examples/vulnerable-vibe-app`
elsewhere (without the answer key), run the skill on it, then compare with
`examples/ANSWER_KEY.md`. Never install or run the example app.

## Credits

- Audit phase structure inspired by Cloudflare's
  [security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT).
- Honeytokens powered by Thinkst [Canarytokens](https://canarytokens.org).
- See [NOTICE.md](NOTICE.md).

## License

MIT. See [LICENSE](LICENSE) and [DISCLAIMER.md](DISCLAIMER.md).
