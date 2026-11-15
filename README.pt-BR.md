# llm-app-security

[English](README.md) · **Português (Brasil)** · [Español](README.es.md)

**Uma skill de segurança defensiva para apps feitos com LLMs e agentes de código.**
Funciona com Claude Code, Codex, Cursor, Gemini CLI e qualquer agente que carregue
skills no formato `SKILL.md`. A skill em si é escrita em inglês; o agente
responde no seu idioma.

Esta é uma tradução; o [README em inglês](README.md) é a versão de referência.

Apps feitos com IA saem rápido e quase sempre com os mesmos buracos: chaves de API no
front-end, rotas sem login, bancos de dados sem regras de acesso. Esta skill
ensina o seu agente de código a encontrar e corrigir esses problemas, a detectar invasores com
honeytokens passivos e a defender o próprio repositório contra prompt
injection.

## O que ela faz

| Módulo | Para que serve |
|---|---|
| **Quick mode** (modo rápido) | Revisão rápida antes do lançamento, que olha o app como um atacante olharia. Somente leitura. |
| `01-AUDIT` | Auditoria completa em fases: reconhecimento → caça guiada por cobertura → validação adversarial → `findings.json` → relatório. Também faz auditorias com escopo definido ("audite este PR"). |
| `02-LLM-CODE-PITFALLS` | As falhas típicas de código gerado por IA: segredos expostos, autenticação só na UI, IDOR, regras do Supabase/Firebase, injection, loops de ferramentas do LLM, pacotes alucinados… |
| `03-HONEYTOKENS` | Iscas passivas (por exemplo, um `password.txt` com uma chave AWS falsa do [Canarytokens](https://canarytokens.org)) que te avisam quando alguém, ou um agente sequestrado, tenta usá-las. |
| `04-AGENT-DEFENSE` | Protege o repositório contra instruções escondidas direcionadas a agentes; regras para `AGENTS.md`/`CLAUDE.md`; permissões e sandboxing. |
| `05-RELEASE-SUPPLY-CHAIN` | Secret scanning, higiene de dependências, checklist de release. |
| `06-PR-GATES` | Quality gates de PR em três níveis (do inicial gratuito ao enterprise com SonarQube/Wiz): bloqueio de merge, testes de autorização, SAST, cobertura em código sensível, guarda de RLS, DAST, critérios de aceite de segurança para um agente de QA e proteção do próprio CI contra agentes. |

## Prompt pronto para colar antes de entregar o app de um cliente

> Revise este projeto como se você quisesse invadi-lo. Procure chaves de API expostas, rotas sem login e bancos de dados sem regras de acesso. Liste o que encontrou e como corrigir, sem alterar nada ainda.

Com a skill instalada, o agente roda o *quick mode* e devolve um veredito
(pronto / pronto depois de corrigir N itens / não está pronto), uma tabela com severidade,
localização, correção e esforço, itens para o dono conferir, já que só aparecem nos seus
painéis, e o que ele não verificou. Para a auditoria completa: *"rode uma auditoria
de segurança completa com a llm-app-security"*.

## Instalação

```bash
git clone https://github.com/jasonmello/llm-app-security.git
```

| Agente | Para onde copiar `skills/llm-app-security` |
|---|---|
| Claude Code (todos os projetos) | `~/.claude/skills/` |
| Claude Code (um projeto) | `.claude/skills/` |
| Codex, Cursor, Gemini CLI e outros | o diretório de skills do agente, ou referencie o `SKILL.md` no `AGENTS.md` do projeto |

Os scripts (`validate-findings.cjs`, `check-honeytokens.cjs`, `rls-guard.sh`)
ficam na pasta `scripts/` da skill, onde quer que ela esteja instalada. Eles só precisam de
Node 20+ (mais bash e perl para o `rls-guard.sh`).

## Princípios

- **Só defensiva.** Audite o que é seu ou o que você tem autorização para testar.
- **Só engano passivo.** Honeytokens só disparam alerta quando alguém mexe neles. Nada de texto
  feito para manipular outros agentes, nada de armadilhas, nada de hack-back.
- **O conteúdo do alvo é dado, não instrução.**
- **Nunca imprima segredos reais**; rotacione antes de apagar.
- **Limites honestos**: "nenhum achado nas partes cobertas" não significa "o app
  é seguro".

## Testes

```bash
npm test
```

`examples/vulnerable-vibe-app` é um app com 14 falhas plantadas de propósito;
o gabarito está em `examples/ANSWER_KEY.md`. Para um benchmark justo, copie só a
pasta do app para outro lugar (sem o gabarito), rode a skill nela e depois
compare. Nunca instale nem rode o app de exemplo: ele é inseguro de propósito e
declara uma dependência com cara de typosquat. As "chaves" do exemplo são falsas.

## Créditos

- Estrutura de fases da auditoria inspirada na
  [security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT) da Cloudflare.
- Honeytokens fornecidos pelo [Canarytokens](https://canarytokens.org) da Thinkst.
- Veja [NOTICE.md](NOTICE.md).

## Licença

MIT. Veja [LICENSE](LICENSE) e [DISCLAIMER.md](DISCLAIMER.md).
