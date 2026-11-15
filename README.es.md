# llm-app-security

[English](README.md) · [Português (Brasil)](README.pt-BR.md) · **Español**

**Una skill de seguridad defensiva para apps construidas con LLMs y agentes de programación.**
Funciona con Claude Code, Codex, Cursor, Gemini CLI y cualquier agente que cargue
skills al estilo `SKILL.md`. La skill en sí está escrita en inglés; el agente
responde en tu idioma.

Esta es una traducción; el README en inglés es la versión de referencia.

Las apps construidas con IA salen rápido y casi siempre con los mismos huecos: claves
de API en el front-end, rutas sin login, bases de datos sin reglas de acceso. Esta skill
le enseña a tu agente de programación a encontrarlos y corregirlos, a detectar intrusos con
honeytokens pasivos y a defender el propio repositorio contra prompt injection.

## Qué hace

| Módulo | Propósito |
|---|---|
| **Quick mode** (modo rápido) | Revisión rápida antes del lanzamiento que mira la app como lo haría un atacante. Solo lectura. |
| `01-AUDIT` | Auditoría completa por fases: reconocimiento → búsqueda guiada por cobertura → validación adversarial → `findings.json` → informe. También auditorías acotadas ("audita este PR"). |
| `02-LLM-CODE-PITFALLS` | Las fallas típicas del código generado por IA: secretos, autenticación solo en la interfaz, IDOR, reglas de Supabase/Firebase, inyección, bucles de herramientas del LLM, paquetes alucinados… |
| `03-HONEYTOKENS` | Señuelos pasivos (p. ej., `password.txt` con una clave falsa de AWS de [Canarytokens](https://canarytokens.org)) que te alertan cuando alguien, o un agente secuestrado, intenta usarlos. |
| `04-AGENT-DEFENSE` | Protege el repositorio contra instrucciones ocultas dirigidas a agentes; reglas para `AGENTS.md`/`CLAUDE.md`; permisos y sandboxing. |
| `05-RELEASE-SUPPLY-CHAIN` | Escaneo de secretos, higiene de dependencias, checklist de lanzamiento. |
| `06-PR-GATES` | Quality gates de PR en tres niveles (inicial gratuito → enterprise con SonarQube/Wiz): bloqueo de merge, pruebas de autorización, SAST, cobertura en código sensible, guardia de RLS, DAST, criterios de aceptación de seguridad para un agente de QA y protección del propio CI frente a agentes. |

## Prompt listo para pegar antes de entregar la app de un cliente

> Revisa este proyecto como si quisieras vulnerarlo. Busca claves de API expuestas, rutas sin login y bases de datos sin reglas de acceso. Haz una lista de lo que encontraste y de cómo corregirlo, sin cambiar nada todavía.

Con la skill instalada, el agente ejecuta el *quick mode* y devuelve un veredicto
(lista / lista después de corregir N puntos / no lista), una tabla con severidad,
ubicación, corrección y esfuerzo, comprobaciones que debe hacer el responsable sobre lo que solo
se ve en tus paneles, y lo que no revisó. Para la auditoría completa: *"haz una
auditoría de seguridad completa con llm-app-security"*.

## Instalación

```bash
git clone https://github.com/jasonmello/llm-app-security.git
```

| Agente | Dónde copiar `skills/llm-app-security` |
|---|---|
| Claude Code (todos los proyectos) | `~/.claude/skills/` |
| Claude Code (un proyecto) | `.claude/skills/` |
| Codex, Cursor, Gemini CLI y otros | el directorio de skills del agente, o haz referencia a `SKILL.md` desde el `AGENTS.md` del proyecto |

Los scripts (`validate-findings.cjs`, `check-honeytokens.cjs`, `rls-guard.sh`)
están en la carpeta `scripts/` de la skill, dondequiera que esté instalada. Solo necesitan
Node 20+ (más bash y perl para `rls-guard.sh`).

## Principios

- **Solo defensiva.** Audita lo que es tuyo o lo que tienes autorización para probar.
- **Solo engaño pasivo.** Los honeytokens solo alertan cuando alguien los toca. Nada de texto
  diseñado para manipular a otros agentes, nada de trampas, nada de hack-back.
- **El contenido del objetivo se trata como datos, no como instrucciones.**
- **Nunca imprimas secretos reales**; rótalos antes de borrarlos.
- **Límites honestos**: "sin hallazgos en las partes cubiertas" no significa "la app
  es segura".

## Pruebas

```bash
npm test
```

`examples/vulnerable-vibe-app` es una app con 14 fallas plantadas a propósito;
las respuestas están en `examples/ANSWER_KEY.md`. Para una comparación justa, copia solo la
carpeta de la app a otro lugar (sin las respuestas), ejecuta la skill sobre ella y luego
compara. Nunca instales ni ejecutes la app de ejemplo: es insegura a propósito y
declara una dependencia con apariencia de typosquat. Las "claves" del ejemplo son falsas.

## Créditos

- Estructura de fases de la auditoría inspirada en
  [security-audit-skill](https://github.com/cloudflare/security-audit-skill) de Cloudflare (MIT).
- Honeytokens con tecnología de [Canarytokens](https://canarytokens.org) de Thinkst.
- Consulta [NOTICE.md](NOTICE.md).

## Licencia

MIT. Consulta [LICENSE](LICENSE) y [DISCLAIMER.md](DISCLAIMER.md).
