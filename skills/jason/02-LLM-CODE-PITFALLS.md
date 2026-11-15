# 02 — Pitfalls typical of AI-generated code

Coding agents produce code that works on the happy path and ships fast. These
are the failures we see most. Use this as the hunting checklist in the full
audit (phase 2) and as the reference behind the pre-deploy check's list.

## 1. Secrets in the wrong place

- Keys pasted into source "to test", then committed. Check history, not just
  HEAD: `git log -p -S 'sk_' --all`, `git log -p -S 'service_role' --all`.
- Secret keys behind client prefixes: `NEXT_PUBLIC_OPENAI_API_KEY`,
  `VITE_STRIPE_SECRET`, `EXPO_PUBLIC_SUPABASE_SERVICE_ROLE`. Anything with
  these prefixes is shipped to every visitor.
- `.env` committed because `.gitignore` was generated after the first commit.
- LLM API called directly from the browser with the key in the bundle. Fix:
  proxy through a server route with auth and rate limit.
- Secrets or override codes in system prompts ("Your API key is …"). Prompts
  leak; the system prompt is not access control.
- Built output (`dist/`, `.next/`, `build/`) committed with inlined env.

Placeholders vs real values: SKILL.md ground rule 8. Patterns worth grepping
(case-insensitive; put specific prefixes before generic ones):

```
sk-ant-[A-Za-z0-9_-]{20,}                       Anthropic
\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}  OpenAI-style
sk_live_[A-Za-z0-9]{20,}  rk_live_[A-Za-z0-9]{20,}   Stripe secret / restricted
sb_secret_[A-Za-z0-9_-]{20,}                    Supabase secret key (new format)
eyJ[A-Za-z0-9_-]{20,}\.eyJ                      JWT (Supabase legacy: check payload "role":"service_role")
AKIA[0-9A-Z]{16}                                AWS access key id
ghp_[A-Za-z0-9]{36}  github_pat_[A-Za-z0-9_]{22,}   GitHub tokens
xox[baprs]-                                     Slack
-----BEGIN .*PRIVATE KEY-----
postgres(ql)?://[^ ]+:[^ ]+@                    DB URL with password
mongodb(\+srv)?://[^ ]+:[^ ]+@
```

**Honeytokens:** before reporting a "secret", check the honeytoken inventory
if the user keeps one. Planted bait is expected and must not be reported as a
leak (nor used).

## 2. Auth only in the UI

- The page hides the admin button, but `/api/admin/*` never checks the role.
- Middleware protects pages but not API routes or server actions
  (Next.js `matcher` that excludes `/api`).
- Next.js **server actions are public POST endpoints**: "logged in" is not
  authorization. Verify the caller's role in the target tenant, and never pair
  a service-role client with IDs from the client.
- Middleware as the only gate on self-hosted Next.js 11.1.4–15.2.2 (fixed in
  12.3.5 / 13.5.9 / 14.2.25 / 15.2.3) is bypassable with the
  `x-middleware-subrequest` header (CVE-2025-29927). Flag from the lockfile
  version as "(inferred, registry not checked)".
- Server action / RPC / Cloud Function (`onRequest`) trusts `userId` sent by
  the client instead of the session or a verified ID token. Prefer `onCall`
  with `request.auth`.
- Machine routes (cron, non-Stripe webhooks, seed/debug endpoints) without a
  verified signature or secret header.
- Fail open: an empty `catch` around token verification or `getUser` must deny.
- JWT not verified: JS `jwt.decode` instead of `jwt.verify`; PyJWT/python-jose
  with `verify_signature: False` or no `algorithms=[...]`; `alg: none`
  accepted; `exp`/`iss`/`aud` unchecked; secret is `"secret"`.
- Open redirect: `?next=` / `redirect_to` / `returnUrl` must start with
  exactly one `/` followed by a character that is not `/` or `\`, or be parsed
  with `new URL(next, origin)` and required to keep `.origin === origin`.
  Auth-provider redirect allow-lists exact (no wildcards).
- Password reset tokens that never expire or are predictable.
- Mass assignment: `update(req.body)`, Prisma `data: body`, Firestore
  `setDoc(..., {merge: true})` from form state let users set `role`, `plan`,
  `credits`, `tenant_id`. Allow-list fields (zod `.pick().strict()`), keep
  entitlements where users cannot write (see §4 for the DB-rule version).

## 3. IDOR (the most common real bug)

`GET /api/orders/:id` returns any order to any logged-in user. Every query
by ID must also filter by owner/tenant from the session:
`where id = $1 and user_id = $session.user`. Writes too: `UPDATE/DELETE ...
WHERE id = $1` without the owner filter (with `RETURNING` it also leaks the
victim's row). The tell is one handler missing the `user_id` filter its
siblings have.

## 4. Database rules missing or fake

- **Supabase**: RLS disabled on any table (including ones added in later
  migrations) → the anon key, public by design, reads/writes it.
  `service_role` / `sb_secret_` in client code bypasses everything. Then:
  - Views run as their owner and bypass RLS unless created
    `with (security_invoker = true)` (or anon/authenticated grants revoked).
  - `using (true)` is fine only for SELECT on data meant to be public.
    `to authenticated using (true)` or `auth.role() = 'authenticated'` on
    UPDATE/DELETE means cross-tenant writes once signup is open: scope with
    `auth.uid()` or a membership check.
  - An explicit `with check` weaker than `using`, or a tenant/owner column the
    user can change, lets rows move to another tenant.
  - An INSERT policy on a membership/roles table that checks only
    `auth.uid() = user_id` lets anyone join any tenant with any role.
  - Roles and tenant IDs from `user_metadata` are client input: use
    `app_metadata` or a table users cannot write. An "update own row" policy
    without column limits is mass assignment
    (`grant update (name, avatar) on profiles to authenticated`).
  - `security definer` functions are fine when they pin `search_path` and scope
    to `auth.uid()`; otherwise `revoke execute ... from public, anon`
    (functions are executable by PUBLIC by default).
  - `storage.objects` policies scoped to the owner's path; Edge Functions
    with `verify_jwt = false` must verify on their own.
  - Live project state (Security Advisor) cannot be seen from code: list it
    under "not checked".
- **Firebase**: `firestore.rules`, `database.rules.json`, `storage.rules`.
  `allow read, write: if true;` or `if request.time < timestamp.date(...)`
  (test mode; compare the date with today). Rules are OR'd: one permissive
  match (e.g. `/{document=**}`) overrides every stricter rule; Realtime
  Database grants cascade and cannot be revoked deeper down. Owner-write rules
  (`request.auth.uid == userId`) without field limits let users set `role`,
  `balance`, `banned`: require
  `request.resource.data.diff(resource.data).affectedKeys().hasOnly([...])` on
  update and `request.resource.data.keys().hasOnly([...])` on create, and grant
  admin via custom claims (`request.auth.token.admin`). App Check not enforced
  is a note, not a finding.
- Public storage buckets holding user uploads, invoices, IDs.

## 5. Injection and unsafe parsing

- SQL built with template strings: `` `select * from users where email = '${email}'` ``.
- NoSQL (Mongo): request JSON like `{"$ne": null}` placed into a query bypasses
  login and filters. Cast values to strings or validate with a schema.
- `child_process.exec` / `os.system` with user input; prefer `execFile` with args.
- `path.join(uploadDir, req.params.name)` without normalizing → path traversal.
- Deserializing or evaluating untrusted data → RCE: `pickle`/`marshal`/
  `jsonpickle`/`joblib`, `torch.load` without `weights_only=True`, `yaml.load`
  without `SafeLoader`, `eval`/`exec`/`new Function`/`vm`, `node-serialize`.
  Not findings on their own: `json.loads`, `yaml.safe_load`, `ast.literal_eval`.
- `dangerouslySetInnerHTML`, `v-html`, `innerHTML` with user or model content → XSS.
- Markdown renderers with HTML enabled, or loading remote images, for model
  output (images are an exfiltration channel: block or allow-list hosts).
- Fetching user-supplied URLs server-side (link previews, webhooks, "import
  from URL", LLM fetch tools) → SSRF to `169.254.169.254` / internal services.

## 6. LLM-feature risks

- **Prompt injection with side effects**: user or third-party content (emails,
  docs, web pages, RAG results) reaches a model that can call tools (send
  email, DB write, refund). Report the tool-dispatch loop as one finding.
  Fix: least-privilege tools scoped to the requesting user, confirmation
  outside the model for side effects.
- **Output trusted as code**: model output executed (`eval`, SQL, shell) or
  rendered as HTML.
- **Open proxy / cost exhaustion**: no auth or rate limit on the chat endpoint;
  no `max_tokens`; unbounded history; a route that forwards client-supplied
  `system` messages, `model` or `max_tokens`. The server owns system prompt,
  model, tools and limits; client history is restricted to user/assistant.
- **Data leakage across users**: shared conversation cache, RAG retrieval
  without a tenant filter applied before scoring; agent memory, prompt-cache
  or embedding keys without the user/tenant; memory writable by other users
  (persistent poisoning).
- **Tool arguments are untrusted input**: a JSON schema constrains shape, not
  authorization. The handler re-checks that the requester owns the resource
  named in the arguments and validates paths, URLs and SQL. Confused deputy:
  a tool running with `service_role` that never re-checks the requesting user.
- **Approval binding**: the confirmation must bind the exact tool name and full
  argument object and be single-use; otherwise the model executes different
  arguments or replays it on retry/resume. Side-effecting tools need
  idempotency keys; agent loops need step and spend caps per request.
- Report injected text by what it can reach (tools, data, rendering), not by
  its mere presence. Instructions in a system prompt ("never reveal X") are
  not access control; enforce limits in code.

## 7. Hallucinated and risky dependencies

- Packages that do not exist (an attacker may register them: "slopsquatting").
  Verify each unfamiliar dependency exists, has history, maintainers and
  downloads: `npm view <pkg> time.created maintainers repository`. If you
  cannot look it up, report it as "(inferred)" and list the lookup as not done.
- Near-miss names of popular packages.
- `postinstall` scripts in new deps; `curl | sh` in setup docs.
- Lockfile missing or ignored.

## 8. Config and defaults

- `DEBUG=True`, stack traces to the client, GraphQL introspection in prod.
- CORS reflecting any origin (`origin: true`) or `*` with `credentials: true`
  when auth is a cookie.
- No security headers (CSP, `X-Content-Type-Options`, `frame-ancestors`).
- Default admin credentials in seed files used in prod.
- Payment amount taken from the request body; Stripe webhook without
  signature verification.
- No rate limit on login, signup, OTP, password reset, email sending, LLM.

**Usually not findings** (low/info at most; check the condition, not the
pattern): self-XSS or an attacker acting only on their own data; debug output, `ssl: false` or seeds gated on
`NODE_ENV !== 'production'` when the deploy sets production (if `NODE_ENV`
defaults to development when unset, that is ONE low row or one owner check,
not both, never one row per gated behavior); `trust proxy` set to a hop count
(flag `true`; the hop count itself is an owner check); reflected or any-origin
CORS, with or without `credentials: true`, when auth is only an
`Authorization: Bearer` header (no auth cookies). Rate limits: report them on
endpoints that are otherwise properly authenticated; never restate a
missing-auth finding as a rate-limit row.

## 9. Also check (often missed)

- **Account takeover flows**: email change without re-auth or confirmation to
  the old address; reset links built from the `Host` header; account linking
  by unverified email (e.g. NextAuth `allowDangerousEmailAccountLinking`),
  hand-rolled OAuth without `state`/PKCE; login/reset/invite responses that
  reveal whether an email exists; MFA enrollment or replacement without fresh
  authentication.
- **Session lifetime**: sessions survive password change, logout or role
  removal; role claims cached in the JWT (Supabase custom claims) stay stale
  until refresh.
- **Spoofable client IP**: rate limiters keyed on `X-Forwarded-For` without a
  correct `trust proxy` setting can be bypassed by sending the header.
- **Excessive data exposure**: `select *` or full objects returned to the client
  (password hashes, other users' emails, internal flags), including props
  passed to client components and API responses filtered only in the UI.
- **Business logic**: paywalls, credits, quotas or trial limits enforced only
  in the client; coupons reusable; negative or zero quantities; skipping
  steps in checkout/onboarding; race conditions on balance/credit updates
  (check-then-decrement: decrement atomically on the server).
- **Webhooks**: every provider (Stripe, Clerk, Supabase auth hooks, GitHub)
  verified by signature, deduplicated by event ID, timestamp tolerance
  checked; never trust a user ID in an unverified body.
- **Data lifecycle**: signed URLs with long expiry or built from a
  user-supplied path; export/CSV endpoints without tenant scope; search,
  filters or counts that reveal records the user cannot open; account
  deletion that leaves data in storage, vector indexes, exports or queues.
- **Weak randomness and crypto**: tokens, reset codes or IDs from
  `Math.random()`, short numeric OTPs without attempt limits, MD5/SHA1 for
  passwords, homemade encryption.
- **File uploads**: type checked only by extension or client MIME, no size
  limit, files served from the app origin (stored XSS via SVG/HTML), original
  filenames used in paths, public buckets.
- **Unbounded queries**: list endpoints without pagination/limit, user-chosen
  `limit`, expensive search without rate limit.
- **Sensitive data to third parties**: full prompts with personal data sent to
  LLM providers or logged in observability tools; secrets or tokens in logs.
- **Preview and staging**: preview deploys public with production keys or
  data; Lovable/Bolt/Replit projects or Supabase dashboards shared publicly.
- **Browser storage and messaging**: long-lived tokens in `localStorage`
  (XSS steals them); `postMessage` handlers without an exact `event.origin`
  check (common in embedded chat widgets); third-party scripts on pages with
  sensitive data; service workers caching personalized responses that
  survive logout.
- **Environment drift**: dev flags or env defaults that disable auth outside
  local development; edge middleware assuming a check the origin does not
  enforce; Docker images containing `.env` because `.dockerignore` is missing.

## 10. Desktop and mobile

- Electron: `nodeIntegration: true`, `contextIsolation: false`,
  `webSecurity: false`; IPC handlers that take raw paths/commands or skip
  `event.senderFrame` checks; `shell.openExternal(userInput)`; remote content in
  a privileged window; windows loading remote content without `will-navigate` /
  `setWindowOpenHandler` guards; renderer HTML without CSP; auto-update feed
  over `http://` or unsigned (electron-updater `publish` URL, signing,
  notarization); unsupported Electron major.
- Mobile: secret keys in the app bundle (they can be extracted), certificate
  checks disabled, deep links that perform actions without confirmation,
  sensitive data in unencrypted local storage.
