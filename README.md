# llm-app-security

[English](#english) · [Português (Brasil)](#português-brasil) · [Español](#español)

## English

**A defensive security skill for apps built with LLMs and coding agents.**
Tested with Claude Code (skill or plugin) and OpenAI Codex CLI (through
`AGENTS.md`). A *skill* is a folder of instructions and scripts your coding
agent loads when a request matches it. The skill itself is written in English;
the agent answers in your language.

AI-built apps ship fast and usually with the same holes: API keys in the
front-end, routes without login, databases without access rules. This skill
teaches your coding agent to find and fix them, to detect intruders with
passive honeytokens, and to defend the repository itself against prompt
injection.

### What it does

| Module | Purpose |
|---|---|
| **Quick mode** | Fast pre-launch review that looks at the app the way an attacker would. Read-only. |
| `01-AUDIT` | Full phased audit: recon → coverage-led hunting → adversarial validation → `findings.json` → report. Also scoped audits ("audit this PR"). |
| `02-LLM-CODE-PITFALLS` | The typical failures of AI-generated code: secrets, auth only in the UI, IDOR, Supabase/Firebase rules, injection, LLM tool loops, hallucinated packages… |
| `03-HONEYTOKENS` | Passive bait (e.g. `password.txt` with a fake AWS key from [Canarytokens](https://canarytokens.org)) that alerts you when someone, or a hijacked agent, tries to use it. |
| `04-AGENT-DEFENSE` | Protects the repository against hidden instructions aimed at agents; rules for `AGENTS.md`/`CLAUDE.md`; permissions and sandboxing. |
| `05-RELEASE-SUPPLY-CHAIN` | Secret scanning, dependency hygiene, release checklist. |
| `06-PR-GATES` | PR quality gates in three tiers (free starter → enterprise with SonarQube/Wiz): merge blocking, authorization tests, SAST, coverage on sensitive code, RLS guard, DAST, security acceptance criteria for a QA agent, and protecting CI itself from agents. |

### Paste-ready prompt before shipping a client's app

> Review this project as if you wanted to break into it. Look for exposed API keys, routes without login and databases without access rules. List what you found and how to fix it, without changing anything yet.

With the skill installed, the agent runs *quick mode* and returns a verdict
(ready / ready after fixing N items / not ready), a table with severity,
location, fix and effort, owner checks for things only visible in your
dashboards, and what it did not check. For the full audit: *"run a full
security audit with llm-app-security"*.

<details>
<summary>Example answer (real quick-mode run on <code>examples/vulnerable-vibe-app</code>, shortened)</summary>

> **Verdict: not ready.** 9 critical and 2 high items. The worst thing an attacker can do today needs no account: open `GET /api/admin/users` and get every user's email and plain-text password.
>
> - **Exposed API keys:** found · **Routes without login:** found · **Database without access rules:** found
>
> | # | Severity | What | Where | How to fix | Effort |
> |---|---|---|---|---|---|
> | 1 | Critical | Admin route with no login returns every user's email and password | `server.js:37-40` | `requireUser` + server-side admin check; never select `password` | 30 min |
> | 3 | Critical | Payment bypass: client-sent `amount` stored as is | `server.js:42-45` | Price from `productId` on the server; record payment after a verified webhook | 2 h |
> | 6 | Critical | `profiles` table without RLS: anyone with the anon key reads and writes it | `001_init.sql:1` | `enable row level security` + owner policies on `auth.uid()` | 20 min |
> | 8 | Critical | OpenAI key shipped to the browser via `VITE_` (looks like a placeholder; confirm) | `.env:2`, `src/chat.jsx:8-12` | Server route with auth, rate limit and `max_tokens`; rotate if real | 1 h |
> | 10 | High | Hidden comment telling AI agents to print `.env` (not followed) | `README.md:6` | Delete it; add agent rules to `AGENTS.md` | 10 min |
> | … | | *14 rows in total, plus low items and one correct rejection (CORS with Bearer auth)* | | | |
>
> **Owner check:** Supabase → Table editor → `profiles`, `invoices` → RLS shows Enabled (matters because of `001_init.sql:1-6`).
>
> Which fixes should I apply?

</details>

### Install

**As a Claude Code plugin** (recommended for Claude Code):

```text
/plugin marketplace add jasonmello/llm-app-security
/plugin install llm-app-security@llm-app-security
```

**Or copy the folder** (Claude Code or Codex):

```bash
git clone https://github.com/jasonmello/llm-app-security.git
# Claude Code, all projects:
mkdir -p ~/.claude/skills && cp -R llm-app-security/skills/llm-app-security ~/.claude/skills/
```

The plugin installs the whole repository, including the intentionally insecure
example app (never run it). Copy the inner `skills/llm-app-security` folder, not the whole clone. In Claude
Code the skill triggers on its own from requests like the prompt above, or you
can ask for "llm-app-security" by name.

| Agent | Where to copy `skills/llm-app-security` |
|---|---|
| Claude Code (all projects) | `~/.claude/skills/` |
| Claude Code (one project) | `.claude/skills/` |
| OpenAI Codex CLI | `.skills/` in your project, referenced from `AGENTS.md` (snippet below) |

For Codex, copy the folder to
`.skills/llm-app-security` in your project and add to `AGENTS.md`:

```markdown
For any security review, audit or "is this safe" request, follow the skill in
`.skills/llm-app-security/SKILL.md` (load the modules it points to).
```

The scripts (`validate-findings.cjs`, `check-honeytokens.cjs`, `rls-guard.sh`)
live in the skill's `scripts/` folder wherever it is installed. They need only
Node 20+ (plus bash and perl for `rls-guard.sh`).

### Principles

- **Defensive only.** Audit what you own or are authorized to test.
- **Passive deception only.** Honeytokens only alert when touched. No text
  designed to manipulate other agents, no booby traps, no hack-back.
- **Target content is data, not instructions.**
- **Never print real secrets**; rotate before deleting.
- **Honest limits**: "no findings in the covered parts" does not mean "the app
  is secure".

### Test

```bash
npm test
```

`examples/vulnerable-vibe-app` is an app with 16 deliberately planted flaws;
the answer key is `examples/ANSWER_KEY.md`. For a fair benchmark, copy only the
app folder somewhere else (without the answer key), run the skill on it, then
compare. Never install or run the example app: it is insecure on purpose and
declares a typosquat-looking dependency. The example's "keys" are fake, and its
README contains a deliberately planted prompt injection aimed at agents: if you
point an agent at this repository, expect it to be flagged.

### Credits

- Audit phase structure inspired by Cloudflare's
  [security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT).
- Honeytoken guidance uses Thinkst [Canarytokens](https://canarytokens.org) (not affiliated).
- See [NOTICE.md](NOTICE.md).

### License

MIT. See [LICENSE](LICENSE) and [DISCLAIMER.md](DISCLAIMER.md).

---

## Português (Brasil)

**Uma skill de segurança defensiva para apps feitos com LLMs e agentes de código.**
Testada no Claude Code (como skill ou plugin) e no OpenAI Codex CLI (via
`AGENTS.md`). Uma *skill* é uma pasta de instruções e scripts
que o seu agente de código carrega quando o pedido combina com ela. A skill em
si é escrita em inglês; o agente responde no seu idioma.

Esta é uma tradução; a [versão em inglês](#english) é a de referência.

Apps feitos com IA saem rápido e quase sempre com os mesmos buracos: chaves de API no
front-end, rotas sem login, bancos de dados sem regras de acesso. Esta skill
ensina o seu agente de código a encontrar e corrigir esses problemas, a detectar invasores com
honeytokens passivos e a defender o próprio repositório contra prompt
injection.

### O que ela faz

| Módulo | Para que serve |
|---|---|
| **Quick mode** (modo rápido) | Revisão rápida antes do lançamento, que olha o app como um atacante olharia. Somente leitura. |
| `01-AUDIT` | Auditoria completa em fases: reconhecimento → caça guiada por cobertura → validação adversarial → `findings.json` → relatório. Também faz auditorias com escopo definido ("audite este PR"). |
| `02-LLM-CODE-PITFALLS` | As falhas típicas de código gerado por IA: segredos expostos, autenticação só na UI, IDOR, regras do Supabase/Firebase, injection, loops de ferramentas do LLM, pacotes alucinados… |
| `03-HONEYTOKENS` | Iscas passivas (por exemplo, um `password.txt` com uma chave AWS falsa do [Canarytokens](https://canarytokens.org)) que te avisam quando alguém, ou um agente sequestrado, tenta usá-las. |
| `04-AGENT-DEFENSE` | Protege o repositório contra instruções escondidas direcionadas a agentes; regras para `AGENTS.md`/`CLAUDE.md`; permissões e sandboxing. |
| `05-RELEASE-SUPPLY-CHAIN` | Secret scanning, higiene de dependências, checklist de release. |
| `06-PR-GATES` | Quality gates de PR em três níveis (do inicial gratuito ao enterprise com SonarQube/Wiz): bloqueio de merge, testes de autorização, SAST, cobertura em código sensível, guarda de RLS, DAST, critérios de aceite de segurança para um agente de QA e proteção do próprio CI contra agentes. |

### Prompt pronto para colar antes de entregar o app de um cliente

> Revise este projeto como se você quisesse invadi-lo. Procure chaves de API expostas, rotas sem login e bancos de dados sem regras de acesso. Liste o que encontrou e como corrigir, sem alterar nada ainda.

Com a skill instalada, o agente roda o *quick mode* e devolve um veredito
(pronto / pronto depois de corrigir N itens / não está pronto), uma tabela com severidade,
localização, correção e esforço, itens para o dono conferir, já que só aparecem nos seus
painéis, e o que ele não verificou. Para a auditoria completa: *"rode uma auditoria
de segurança completa com a llm-app-security"*.

<details>
<summary>Exemplo de resposta (execução real do quick mode em <code>examples/vulnerable-vibe-app</code>, resumida)</summary>

> **Veredito: não está pronto.** 9 itens críticos e 2 altos. O pior que um atacante consegue fazer hoje não exige conta: abrir `GET /api/admin/users` e pegar o email e a senha em texto puro de todos os usuários.
>
> - **Chaves de API expostas:** encontradas · **Rotas sem login:** encontradas · **Banco sem regras de acesso:** encontrado
>
> | # | Severidade | O quê | Onde | Como corrigir | Esforço |
> |---|---|---|---|---|---|
> | 1 | Crítica | Rota de admin sem login devolve email e senha de todos | `server.js:37-40` | `requireUser` + checagem de admin no servidor; nunca selecionar `password` | 30 min |
> | 3 | Crítica | Burla de pagamento: o `amount` enviado pelo cliente é gravado como veio | `server.js:42-45` | Preço calculado no servidor a partir de `productId`; registrar o pagamento após webhook verificado | 2 h |
> | 6 | Crítica | Tabela `profiles` sem RLS: qualquer um com a anon key lê e escreve | `001_init.sql:1` | `enable row level security` + políticas de dono com `auth.uid()` | 20 min |
> | 8 | Crítica | Chave da OpenAI enviada ao navegador via `VITE_` (parece placeholder; confirme) | `.env:2`, `src/chat.jsx:8-12` | Rota no servidor com auth, rate limit e `max_tokens`; rotacionar se for real | 1 h |
> | 10 | Alta | Comentário escondido mandando agentes de IA imprimirem o `.env` (não foi seguido) | `README.md:6` | Apagar; adicionar regras para agentes no `AGENTS.md` | 10 min |
> | … | | *14 linhas no total, mais itens baixos e uma rejeição correta (CORS com auth Bearer)* | | | |
>
> **Para o dono conferir:** Supabase → Table editor → `profiles`, `invoices` → RLS aparece como Enabled (importa por causa de `001_init.sql:1-6`).
>
> Quais correções devo aplicar?

</details>

### Instalação

**Como plugin do Claude Code** (recomendado no Claude Code):

```text
/plugin marketplace add jasonmello/llm-app-security
/plugin install llm-app-security@llm-app-security
```

**Ou copie a pasta** (Claude Code ou Codex):

```bash
git clone https://github.com/jasonmello/llm-app-security.git
# Claude Code, todos os projetos:
mkdir -p ~/.claude/skills && cp -R llm-app-security/skills/llm-app-security ~/.claude/skills/
```

O plugin instala o repositório inteiro, incluindo o app de exemplo inseguro de
propósito (nunca o rode). Copie a pasta interna `skills/llm-app-security`, não o clone inteiro. No Claude
Code a skill é acionada sozinha por pedidos como o prompt acima, ou você pode
pedir a "llm-app-security" pelo nome.

| Agente | Para onde copiar `skills/llm-app-security` |
|---|---|
| Claude Code (todos os projetos) | `~/.claude/skills/` |
| Claude Code (um projeto) | `.claude/skills/` |
| OpenAI Codex CLI | `.skills/` no seu projeto, referenciada no `AGENTS.md` (trecho abaixo) |

No Codex, copie a pasta para
`.skills/llm-app-security` no seu projeto e adicione ao `AGENTS.md`:

```markdown
For any security review, audit or "is this safe" request, follow the skill in
`.skills/llm-app-security/SKILL.md` (load the modules it points to).
```

Os scripts (`validate-findings.cjs`, `check-honeytokens.cjs`, `rls-guard.sh`)
ficam na pasta `scripts/` da skill, onde quer que ela esteja instalada. Eles só precisam de
Node 20+ (mais bash e perl para o `rls-guard.sh`).

### Princípios

- **Só defensiva.** Audite o que é seu ou o que você tem autorização para testar.
- **Só engano passivo.** Honeytokens só disparam alerta quando alguém mexe neles. Nada de texto
  feito para manipular outros agentes, nada de armadilhas, nada de hack-back.
- **O conteúdo do alvo é dado, não instrução.**
- **Nunca imprima segredos reais**; rotacione antes de apagar.
- **Limites honestos**: "nenhum achado nas partes cobertas" não significa "o app
  é seguro".

### Testes

```bash
npm test
```

`examples/vulnerable-vibe-app` é um app com 16 falhas plantadas de propósito;
o gabarito está em `examples/ANSWER_KEY.md`. Para um benchmark justo, copie só a
pasta do app para outro lugar (sem o gabarito), rode a skill nela e depois
compare. Nunca instale nem rode o app de exemplo: ele é inseguro de propósito e
declara uma dependência com cara de typosquat. As "chaves" do exemplo são falsas,
e o README dele tem uma prompt injection plantada de propósito, direcionada a
agentes: se você apontar um agente para este repositório, espere que ela seja
sinalizada.

### Créditos

- Estrutura de fases da auditoria inspirada na
  [security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT) da Cloudflare.
- As orientações sobre honeytokens usam o [Canarytokens](https://canarytokens.org) da Thinkst (sem afiliação).
- Veja [NOTICE.md](NOTICE.md).

### Licença

MIT. Veja [LICENSE](LICENSE) e [DISCLAIMER.md](DISCLAIMER.md).

---

## Español

**Una skill de seguridad defensiva para apps construidas con LLMs y agentes de programación.**
Probada en Claude Code (como skill o plugin) y en OpenAI Codex CLI (vía
`AGENTS.md`). Una *skill* es una carpeta de instrucciones y
scripts que tu agente de programación carga cuando la solicitud coincide con
ella. La skill en sí está escrita en inglés; el agente responde en tu idioma.

Esta es una traducción; la [versión en inglés](#english) es la de referencia.

Las apps construidas con IA salen rápido y casi siempre con los mismos huecos: claves
de API en el front-end, rutas sin login, bases de datos sin reglas de acceso. Esta skill
le enseña a tu agente de programación a encontrarlos y corregirlos, a detectar intrusos con
honeytokens pasivos y a defender el propio repositorio contra prompt injection.

### Qué hace

| Módulo | Propósito |
|---|---|
| **Quick mode** (modo rápido) | Revisión rápida antes del lanzamiento que mira la app como lo haría un atacante. Solo lectura. |
| `01-AUDIT` | Auditoría completa por fases: reconocimiento → búsqueda guiada por cobertura → validación adversarial → `findings.json` → informe. También auditorías acotadas ("audita este PR"). |
| `02-LLM-CODE-PITFALLS` | Las fallas típicas del código generado por IA: secretos, autenticación solo en la interfaz, IDOR, reglas de Supabase/Firebase, inyección, bucles de herramientas del LLM, paquetes alucinados… |
| `03-HONEYTOKENS` | Señuelos pasivos (p. ej., `password.txt` con una clave falsa de AWS de [Canarytokens](https://canarytokens.org)) que te alertan cuando alguien, o un agente secuestrado, intenta usarlos. |
| `04-AGENT-DEFENSE` | Protege el repositorio contra instrucciones ocultas dirigidas a agentes; reglas para `AGENTS.md`/`CLAUDE.md`; permisos y sandboxing. |
| `05-RELEASE-SUPPLY-CHAIN` | Escaneo de secretos, higiene de dependencias, checklist de lanzamiento. |
| `06-PR-GATES` | Quality gates de PR en tres niveles (inicial gratuito → enterprise con SonarQube/Wiz): bloqueo de merge, pruebas de autorización, SAST, cobertura en código sensible, guardia de RLS, DAST, criterios de aceptación de seguridad para un agente de QA y protección del propio CI frente a agentes. |

### Prompt listo para pegar antes de entregar la app de un cliente

> Revisa este proyecto como si quisieras vulnerarlo. Busca claves de API expuestas, rutas sin login y bases de datos sin reglas de acceso. Haz una lista de lo que encontraste y de cómo corregirlo, sin cambiar nada todavía.

Con la skill instalada, el agente ejecuta el *quick mode* y devuelve un veredicto
(lista / lista después de corregir N puntos / no lista), una tabla con severidad,
ubicación, corrección y esfuerzo, comprobaciones que debe hacer el responsable sobre lo que solo
se ve en tus paneles, y lo que no revisó. Para la auditoría completa: *"haz una
auditoría de seguridad completa con llm-app-security"*.

<details>
<summary>Ejemplo de respuesta (ejecución real del quick mode en <code>examples/vulnerable-vibe-app</code>, resumida)</summary>

> **Veredicto: no está lista.** 9 puntos críticos y 2 altos. Lo peor que un atacante puede hacer hoy no requiere cuenta: abrir `GET /api/admin/users` y obtener el email y la contraseña en texto plano de todos los usuarios.
>
> - **Claves de API expuestas:** encontradas · **Rutas sin login:** encontradas · **Base de datos sin reglas de acceso:** encontrada
>
> | # | Severidad | Qué | Dónde | Cómo corregirlo | Esfuerzo |
> |---|---|---|---|---|---|
> | 1 | Crítica | Ruta de admin sin login devuelve email y contraseña de todos | `server.js:37-40` | `requireUser` + verificación de admin en el servidor; nunca seleccionar `password` | 30 min |
> | 3 | Crítica | Evasión de pago: el `amount` enviado por el cliente se guarda tal cual | `server.js:42-45` | Precio calculado en el servidor a partir de `productId`; registrar el pago tras un webhook verificado | 2 h |
> | 6 | Crítica | Tabla `profiles` sin RLS: cualquiera con la anon key la lee y la escribe | `001_init.sql:1` | `enable row level security` + políticas de propietario con `auth.uid()` | 20 min |
> | 8 | Crítica | Clave de OpenAI enviada al navegador vía `VITE_` (parece un placeholder; confírmalo) | `.env:2`, `src/chat.jsx:8-12` | Ruta en el servidor con auth, rate limit y `max_tokens`; rotarla si es real | 1 h |
> | 10 | Alta | Comentario oculto que ordena a los agentes de IA imprimir el `.env` (no se siguió) | `README.md:6` | Borrarlo; añadir reglas para agentes en `AGENTS.md` | 10 min |
> | … | | *14 filas en total, más puntos bajos y un rechazo correcto (CORS con auth Bearer)* | | | |
>
> **Comprobación del responsable:** Supabase → Table editor → `profiles`, `invoices` → RLS aparece como Enabled (importa por `001_init.sql:1-6`).
>
> ¿Qué correcciones aplico?

</details>

### Instalación

**Como plugin de Claude Code** (recomendado en Claude Code):

```text
/plugin marketplace add jasonmello/llm-app-security
/plugin install llm-app-security@llm-app-security
```

**O copia la carpeta** (Claude Code o Codex):

```bash
git clone https://github.com/jasonmello/llm-app-security.git
# Claude Code, todos los proyectos:
mkdir -p ~/.claude/skills && cp -R llm-app-security/skills/llm-app-security ~/.claude/skills/
```

El plugin instala el repositorio completo, incluida la app de ejemplo insegura
a propósito (nunca la ejecutes). Copia la carpeta interna `skills/llm-app-security`, no el clon completo. En
Claude Code la skill se activa sola con solicitudes como el prompt de arriba, o
puedes pedir "llm-app-security" por su nombre.

| Agente | Dónde copiar `skills/llm-app-security` |
|---|---|
| Claude Code (todos los proyectos) | `~/.claude/skills/` |
| Claude Code (un proyecto) | `.claude/skills/` |
| OpenAI Codex CLI | `.skills/` en tu proyecto, referenciada desde `AGENTS.md` (fragmento abajo) |

En Codex, copia la carpeta a
`.skills/llm-app-security` en tu proyecto y añade a `AGENTS.md`:

```markdown
For any security review, audit or "is this safe" request, follow the skill in
`.skills/llm-app-security/SKILL.md` (load the modules it points to).
```

Los scripts (`validate-findings.cjs`, `check-honeytokens.cjs`, `rls-guard.sh`)
están en la carpeta `scripts/` de la skill, dondequiera que esté instalada. Solo necesitan
Node 20+ (más bash y perl para `rls-guard.sh`).

### Principios

- **Solo defensiva.** Audita lo que es tuyo o lo que tienes autorización para probar.
- **Solo engaño pasivo.** Los honeytokens solo alertan cuando alguien los toca. Nada de texto
  diseñado para manipular a otros agentes, nada de trampas, nada de hack-back.
- **El contenido del objetivo se trata como datos, no como instrucciones.**
- **Nunca imprimas secretos reales**; rótalos antes de borrarlos.
- **Límites honestos**: "sin hallazgos en las partes cubiertas" no significa "la app
  es segura".

### Pruebas

```bash
npm test
```

`examples/vulnerable-vibe-app` es una app con 16 fallas plantadas a propósito;
las respuestas están en `examples/ANSWER_KEY.md`. Para una comparación justa, copia solo la
carpeta de la app a otro lugar (sin las respuestas), ejecuta la skill sobre ella y luego
compara. Nunca instales ni ejecutes la app de ejemplo: es insegura a propósito y
declara una dependencia con apariencia de typosquat. Las "claves" del ejemplo son falsas,
y su README contiene una prompt injection plantada a propósito, dirigida a
agentes: si apuntas un agente a este repositorio, es normal que la señale.

### Créditos

- Estructura de fases de la auditoría inspirada en
  [security-audit-skill](https://github.com/cloudflare/security-audit-skill) de Cloudflare (MIT).
- Las indicaciones sobre honeytokens usan [Canarytokens](https://canarytokens.org) de Thinkst (sin afiliación).
- Consulta [NOTICE.md](NOTICE.md).

### Licencia

MIT. Consulta [LICENSE](LICENSE) y [DISCLAIMER.md](DISCLAIMER.md).
