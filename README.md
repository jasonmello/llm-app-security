<img src=".claude-plugin/icon.png" alt="J.A.S.O.N. shield icon" width="96" align="right">

# J.A.S.O.N. — LLM App Security

***J**ust **A**udit, **S**ecure, **O**bserve, **N**otify.* Ship on Friday the 13th. Fearlessly.

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

**Why "J.A.S.O.N."?** It is named after its author, Jason, and every letter is
a part of the skill:

| Letter | Means | Modules |
|---|---|---|
| **J**ust | it should be that simple | — |
| **A**udit | find the holes | pre-deploy check, `01`, `02` |
| **S**ecure | keep them from coming back, block the deploy | `04`, `05`, `06`, `07` |
| **O**bserve | watch with bait | `03` (honeytokens) |
| **N**otify | tell the right people | alerts and the report |

### What it does

| Module | Purpose |
|---|---|
| **Pre-deploy check** | Review before the first deploy (and every deploy after) that looks at the app the way an attacker would, plus the deterministic ship-gate. Read-only. |
| `01-AUDIT` | Full phased audit: recon → coverage-led hunting → adversarial validation → `findings.json` → report. Also scoped audits ("audit this PR"). |
| `02-LLM-CODE-PITFALLS` | The typical failures of AI-generated code: secrets, auth only in the UI, IDOR, Supabase/Firebase rules, injection, LLM tool loops, hallucinated packages… |
| `03-HONEYTOKENS` | Passive bait (e.g. `password.txt` with a fake AWS key from [Canarytokens](https://canarytokens.org)) that alerts you when someone, or a hijacked agent, tries to use it. |
| `04-AGENT-DEFENSE` | Protects the repository against hidden instructions aimed at agents; rules for `AGENTS.md`/`CLAUDE.md`; permissions and sandboxing. |
| `05-RELEASE-SUPPLY-CHAIN` | Secret scanning, dependency hygiene, release checklist. |
| `06-PR-GATES` | PR quality gates in three tiers (free starter → enterprise with SonarQube/Wiz): merge blocking, authorization tests, SAST, coverage on sensitive code, RLS guard, DAST, security acceptance criteria for a QA agent, and protecting CI itself from agents. |
| `07-DEPLOY-GATE` | **Blocks the deploy** instead of listing warnings: `ship-gate.cjs` (one file, zero dependencies) fails on exposed secrets, open Supabase/Firebase rules, auth or LLM endpoints without rate limiting, and unhandled critical findings. Conscious exceptions go in an expiring waiver file. |

### Paste-ready prompt before the first deploy

> Review this project as if you wanted to break into it. Look for exposed API keys, routes without login and databases without access rules. List what you found and how to fix it, without changing anything yet.

Run it before the **first** deploy, not at launch: by launch the app already
has a public URL and real users. With the skill installed, the agent runs the
ship-gate and the pre-deploy check and returns a verdict (ready to deploy / do
not deploy until N items are fixed / do not deploy), a table with severity,
location, fix and effort, owner checks for things only visible in your
dashboards, and what it did not check. For the full audit: *"run a full
security audit with J.A.S.O.N."*.

<details>
<summary>Example answer (real pre-deploy run on <code>examples/vulnerable-vibe-app</code>, shortened)</summary>

> **Verdict: do not deploy.** 9 critical and 2 high items; ship-gate BLOCKED (6). The worst thing an attacker can do today needs no account: open `GET /api/admin/users` and get every user's email and plain-text password.
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

### Deploy gate: block, don't warn

Builders ship over warnings. The ship-gate stops the deploy instead: copy
`skills/jason/scripts/ship-gate.cjs` to `scripts/ci/` in your app and run it
before and after the build (the second run sees the bundles), so a blocker
fails the deploy on Vercel, Netlify, Cloudflare Pages and similar hosts:

```json
"build": "node scripts/ci/ship-gate.cjs && next build && node scripts/ci/ship-gate.cjs"
```

It checks exposed secrets (env prefixes, live keys, bundles), Supabase RLS,
open policies and views, Firebase rules, rate limits on auth/LLM endpoints and
confirmed critical findings. Exit 1 means do not deploy. Shipping anyway takes
an explicit, expiring waiver with a reason and an owner; leaked live secrets
cannot be waived. Details, GitHub Actions, Firebase and Expo setups:
`skills/jason/07-DEPLOY-GATE.md`.

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
mkdir -p ~/.claude/skills && cp -R llm-app-security/skills/jason ~/.claude/skills/
```

The plugin installs the whole repository, including the intentionally insecure
example app (never run it). Copy the inner `skills/jason` folder, not the whole clone. In Claude
Code the skill triggers on its own from requests like the prompt above; you
can also type `/jason` (as a plugin: `/llm-app-security:jason`) or ask for
"J.A.S.O.N." by name.

**Upgrading from 0.2.x (manual install):** delete the old
`llm-app-security` skill folder first (`~/.claude/skills/`, `.claude/skills/`
or `.skills/`), otherwise two overlapping skills stay installed.

| Agent | Where to copy `skills/jason` |
|---|---|
| Claude Code (all projects) | `~/.claude/skills/` |
| Claude Code (one project) | `.claude/skills/` |
| OpenAI Codex CLI | `.skills/` in your project, referenced from `AGENTS.md` (snippet below) |

For Codex, copy the folder to
`.skills/jason` in your project and add to `AGENTS.md`:

```markdown
For any security review, audit or "is this safe" request, follow the skill in
`.skills/jason/SKILL.md` (load the modules it points to).
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

**Por que "J.A.S.O.N."?** O nome vem do autor, Jason, e cada letra é uma parte
da skill:

| Letra | Significa | Módulos |
|---|---|---|
| **J**ust | "simples assim" | — |
| **A**udit | encontrar as falhas | checagem pré-deploy, `01`, `02` |
| **S**ecure | impedir que voltem, barrar o deploy | `04`, `05`, `06`, `07` |
| **O**bserve | vigiar com iscas | `03` (honeytokens) |
| **N**otify | avisar quem precisa | alertas e o relatório |

### O que ela faz

| Módulo | Para que serve |
|---|---|
| **Pre-deploy check** (checagem pré-deploy) | Revisão antes do primeiro deploy (e de todos os seguintes), olhando o app como um atacante olharia, mais o ship-gate determinístico. Somente leitura. |
| `01-AUDIT` | Auditoria completa em fases: reconhecimento → caça guiada por cobertura → validação adversarial → `findings.json` → relatório. Também faz auditorias com escopo definido ("audite este PR"). |
| `02-LLM-CODE-PITFALLS` | As falhas típicas de código gerado por IA: segredos expostos, autenticação só na UI, IDOR, regras do Supabase/Firebase, injection, loops de ferramentas do LLM, pacotes alucinados… |
| `03-HONEYTOKENS` | Iscas passivas (por exemplo, um `password.txt` com uma chave AWS falsa do [Canarytokens](https://canarytokens.org)) que te avisam quando alguém, ou um agente sequestrado, tenta usá-las. |
| `04-AGENT-DEFENSE` | Protege o repositório contra instruções escondidas direcionadas a agentes; regras para `AGENTS.md`/`CLAUDE.md`; permissões e sandboxing. |
| `05-RELEASE-SUPPLY-CHAIN` | Secret scanning, higiene de dependências, checklist de release. |
| `06-PR-GATES` | Quality gates de PR em três níveis (do inicial gratuito ao enterprise com SonarQube/Wiz): bloqueio de merge, testes de autorização, SAST, cobertura em código sensível, guarda de RLS, DAST, critérios de aceite de segurança para um agente de QA e proteção do próprio CI contra agentes. |
| `07-DEPLOY-GATE` | **Barra o deploy** em vez de listar avisos: o `ship-gate.cjs` (um arquivo, zero dependências) falha com segredos expostos, regras abertas no Supabase/Firebase, endpoints de auth ou LLM sem rate limit e achados críticos não resolvidos. Exceções conscientes vão num arquivo de waivers com data de validade. |

### Prompt pronto para colar antes do primeiro deploy

> Revise este projeto como se você quisesse invadi-lo. Procure chaves de API expostas, rotas sem login e bancos de dados sem regras de acesso. Liste o que encontrou e como corrigir, sem alterar nada ainda.

Rode antes do **primeiro** deploy, não no lançamento: no lançamento o app já tem
URL pública e usuários reais. Com a skill instalada, o agente roda o ship-gate e a
checagem pré-deploy e devolve um veredito (pode fazer o deploy / não faça o deploy até
corrigir N itens / não faça o deploy), uma tabela com severidade,
localização, correção e esforço, itens para o dono conferir, já que só aparecem nos seus
painéis, e o que ele não verificou. Para a auditoria completa: *"rode uma auditoria
de segurança completa com o J.A.S.O.N."*.

<details>
<summary>Exemplo de resposta (execução real da checagem pré-deploy em <code>examples/vulnerable-vibe-app</code>, resumida)</summary>

> **Veredito: não faça o deploy.** 9 itens críticos e 2 altos; ship-gate BLOQUEADO (6). O pior que um atacante consegue fazer hoje não exige conta: abrir `GET /api/admin/users` e pegar o email e a senha em texto puro de todos os usuários.
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

### Trava de deploy: bloquear, não só avisar

Aviso a gente ignora e faz o deploy mesmo assim. O ship-gate trava o deploy:
copie `skills/jason/scripts/ship-gate.cjs` para `scripts/ci/` no seu app e
rode antes e depois do build (a segunda execução enxerga os bundles), para que
um bloqueio derrube o deploy na Vercel, Netlify, Cloudflare Pages e hosts parecidos:

```json
"build": "node scripts/ci/ship-gate.cjs && next build && node scripts/ci/ship-gate.cjs"
```

Ele verifica segredos expostos (prefixos de env, chaves reais, bundles), RLS,
políticas e views abertas no Supabase, regras do Firebase, rate limit em
endpoints de auth/LLM e achados críticos confirmados. Saída 1 significa: não faça
o deploy. Para subir mesmo assim, é preciso um waiver explícito, com motivo,
responsável e data de validade; segredos reais vazados não podem ser
dispensados. Detalhes e configurações para GitHub Actions, Firebase e Expo:
`skills/jason/07-DEPLOY-GATE.md`.

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
mkdir -p ~/.claude/skills && cp -R llm-app-security/skills/jason ~/.claude/skills/
```

O plugin instala o repositório inteiro, incluindo o app de exemplo inseguro de
propósito (nunca o rode). Copie a pasta interna `skills/jason`, não o clone inteiro. No Claude
Code a skill é acionada sozinha por pedidos como o prompt acima; você também
pode digitar `/jason` (como plugin: `/llm-app-security:jason`) ou chamar o
"J.A.S.O.N." pelo nome.

**Atualizando da 0.2.x (instalação manual):** apague antes a pasta antiga
`llm-app-security` (em `~/.claude/skills/`, `.claude/skills/` ou `.skills/`);
senão ficam duas skills parecidas instaladas.

| Agente | Para onde copiar `skills/jason` |
|---|---|
| Claude Code (todos os projetos) | `~/.claude/skills/` |
| Claude Code (um projeto) | `.claude/skills/` |
| OpenAI Codex CLI | `.skills/` no seu projeto, referenciada no `AGENTS.md` (trecho abaixo) |

No Codex, copie a pasta para
`.skills/jason` no seu projeto e adicione ao `AGENTS.md`:

```markdown
For any security review, audit or "is this safe" request, follow the skill in
`.skills/jason/SKILL.md` (load the modules it points to).
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

**¿Por qué "J.A.S.O.N."?** El nombre viene de su autor, Jason, y cada letra es
una parte de la skill:

| Letra | Significa | Módulos |
|---|---|---|
| **J**ust | "así de simple" | — |
| **A**udit | encontrar los huecos | revisión previa al deploy, `01`, `02` |
| **S**ecure | evitar que vuelvan, frenar el deploy | `04`, `05`, `06`, `07` |
| **O**bserve | vigilar con señuelos | `03` (honeytokens) |
| **N**otify | avisar a quien corresponde | alertas y el informe |

### Qué hace

| Módulo | Propósito |
|---|---|
| **Pre-deploy check** (revisión previa al deploy) | Revisión antes del primer deploy (y de cada deploy siguiente) que mira la app como lo haría un atacante, más el ship-gate determinista. Solo lectura. |
| `01-AUDIT` | Auditoría completa por fases: reconocimiento → búsqueda guiada por cobertura → validación adversarial → `findings.json` → informe. También auditorías acotadas ("audita este PR"). |
| `02-LLM-CODE-PITFALLS` | Las fallas típicas del código generado por IA: secretos, autenticación solo en la interfaz, IDOR, reglas de Supabase/Firebase, inyección, bucles de herramientas del LLM, paquetes alucinados… |
| `03-HONEYTOKENS` | Señuelos pasivos (p. ej., `password.txt` con una clave falsa de AWS de [Canarytokens](https://canarytokens.org)) que te alertan cuando alguien, o un agente secuestrado, intenta usarlos. |
| `04-AGENT-DEFENSE` | Protege el repositorio contra instrucciones ocultas dirigidas a agentes; reglas para `AGENTS.md`/`CLAUDE.md`; permisos y sandboxing. |
| `05-RELEASE-SUPPLY-CHAIN` | Escaneo de secretos, higiene de dependencias, checklist de lanzamiento. |
| `06-PR-GATES` | Quality gates de PR en tres niveles (inicial gratuito → enterprise con SonarQube/Wiz): bloqueo de merge, pruebas de autorización, SAST, cobertura en código sensible, guardia de RLS, DAST, criterios de aceptación de seguridad para un agente de QA y protección del propio CI frente a agentes. |
| `07-DEPLOY-GATE` | **Frena el deploy** en lugar de listar avisos: `ship-gate.cjs` (un archivo, cero dependencias) falla con secretos expuestos, reglas abiertas en Supabase/Firebase, endpoints de auth o LLM sin rate limit y hallazgos críticos sin resolver. Las excepciones conscientes van en un archivo de waivers con fecha de vencimiento. |

### Prompt listo para pegar antes del primer deploy

> Revisa este proyecto como si quisieras vulnerarlo. Busca claves de API expuestas, rutas sin login y bases de datos sin reglas de acceso. Haz una lista de lo que encontraste y de cómo corregirlo, sin cambiar nada todavía.

Ejecútalo antes del **primer** deploy, no en el lanzamiento: para entonces la app
ya tiene URL pública y usuarios reales. Con la skill instalada, el agente ejecuta el
ship-gate y la revisión previa al deploy y devuelve un veredicto (lista para el deploy /
no hagas el deploy hasta corregir N puntos / no hagas el deploy), una tabla con severidad,
ubicación, corrección y esfuerzo, comprobaciones que debe hacer el responsable sobre lo que solo
se ve en tus paneles, y lo que no revisó. Para la auditoría completa: *"haz una
auditoría de seguridad completa con J.A.S.O.N."*.

<details>
<summary>Ejemplo de respuesta (ejecución real de la revisión previa al deploy en <code>examples/vulnerable-vibe-app</code>, resumida)</summary>

> **Veredicto: no hagas el deploy.** 9 puntos críticos y 2 altos; ship-gate BLOQUEADO (6). Lo peor que un atacante puede hacer hoy no requiere cuenta: abrir `GET /api/admin/users` y obtener el email y la contraseña en texto plano de todos los usuarios.
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

### Bloqueo de deploy: frenar, no solo avisar

Los avisos se ignoran y el deploy sale igual. El ship-gate frena el deploy:
copia `skills/jason/scripts/ship-gate.cjs` a `scripts/ci/` en tu app y
ejecútalo antes y después del build (la segunda ejecución ve los bundles), para
que un bloqueo haga fallar el deploy en Vercel, Netlify, Cloudflare Pages y hosts similares:

```json
"build": "node scripts/ci/ship-gate.cjs && next build && node scripts/ci/ship-gate.cjs"
```

Revisa secretos expuestos (prefijos de env, claves reales, bundles), RLS,
políticas y vistas abiertas en Supabase, reglas de Firebase, rate limit en
endpoints de auth/LLM y hallazgos críticos confirmados. Salida 1 significa: no
hagas el deploy. Para subir de todos modos hace falta un waiver explícito, con
motivo, responsable y fecha de vencimiento; los secretos reales filtrados no se
pueden eximir. Detalles y configuraciones para GitHub Actions, Firebase y Expo:
`skills/jason/07-DEPLOY-GATE.md`.

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
mkdir -p ~/.claude/skills && cp -R llm-app-security/skills/jason ~/.claude/skills/
```

El plugin instala el repositorio completo, incluida la app de ejemplo insegura
a propósito (nunca la ejecutes). Copia la carpeta interna `skills/jason`, no el clon completo. En
Claude Code la skill se activa sola con solicitudes como el prompt de arriba;
también puedes escribir `/jason` (como plugin: `/llm-app-security:jason`) o
pedir "J.A.S.O.N." por su nombre.

**Actualizar desde 0.2.x (instalación manual):** borra antes la carpeta
antigua `llm-app-security` (en `~/.claude/skills/`, `.claude/skills/` o
`.skills/`); si no, quedan instaladas dos skills que se solapan.

| Agente | Dónde copiar `skills/jason` |
|---|---|
| Claude Code (todos los proyectos) | `~/.claude/skills/` |
| Claude Code (un proyecto) | `.claude/skills/` |
| OpenAI Codex CLI | `.skills/` en tu proyecto, referenciada desde `AGENTS.md` (fragmento abajo) |

En Codex, copia la carpeta a
`.skills/jason` en tu proyecto y añade a `AGENTS.md`:

```markdown
For any security review, audit or "is this safe" request, follow the skill in
`.skills/jason/SKILL.md` (load the modules it points to).
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
