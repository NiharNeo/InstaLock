# IntentLock

A tenant-scoped authorization gateway for untrusted AI-agent refund proposals.
The production entrypoint is `app.main:app`. No legacy API routes are mounted.
All business records come from the database; the checked-in policy has **no tenant
permissions**, and there are no seed/demo business-data commands.

## Main interface

`stitch_intentlock_operator_console/` is the user-selected frontend source of
truth. Use its exported screens and design for all future interface work.
`web/` currently supplies the runnable React/Vite integration; adapt it to those
Stitch screens rather than maintaining a separate visual design. Stitch's sample
business values are design references only and must be replaced with actual
backend data or honest empty states when connected.

## Run and test

Python 3.12+, Node 22+, and an actual database are required. From the project root:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements.lock
pip install --no-deps -e .
cp .env.example .env
```

Fill `GRANT_ISSUER` with your actual stable issuer name. Configure the real tenant
permissions in `policies/refunds.yaml` as described below. Load environment values
using shell-safe quoting or your secret manager:

```sh
# Export only gateway-specific settings from your secret manager.
# .env is for Compose interpolation; do not source all service secrets globally.
export DATABASE_URL=sqlite:///./intentlock.db
export POLICY_FILE=policies/refunds.yaml
export APP_ORIGIN=http://127.0.0.1:5173
# Generate once; retain this dedicated key across every restart.
python -m app.core.receipts /private/tmp/intentlock-receipt.pem
export RECEIPT_PRIVATE_KEY_FILE=/private/tmp/intentlock-receipt.pem
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In separate terminals, with the same non-provider gateway configuration and the
executor-only secrets loaded **only** into executor/reconciler environments:

```sh
uvicorn app.executor.main:app --host 127.0.0.1 --port 8001
python -m app.executor.reconcile
# Or run a single recovery pass:
python -m app.executor.reconcile --once
```

In another terminal:

```sh
npm ci --prefix web
npm run dev --prefix web
```

Open http://127.0.0.1:5173. The human console accepts a previously provisioned
operator session and its CSRF token, loads a real proposal by ID, displays the
trusted live effect, and offers explicit approval. It holds no signing key or
agent key. Successful session entry sets an HttpOnly, SameSite=Strict cookie
scoped to `/v1`; HTTPS deployments also set Secure. Secrets stay out of local
storage. Session revocation requires CSRF.

```sh
.venv/bin/python -m pytest -q
npm run build --prefix web
```

For Compose, use `DATABASE_URL=sqlite:////data/intentlock.db` and
`APP_ORIGIN=http://localhost:8080` in `.env`:

```sh
docker compose config --quiet
docker compose up --build
```

Open http://localhost:8080. Host ports bind only loopback. The named `ledger`
volume persists real records, and `./policies` is mounted read-only. A changed
policy requires restarting gateway, executor and reconciler. A one-shot `migrate`
service completes Alembic before all three services start. Docker Engine must be
running. Image build/startup was not exercised in this environment.

## Executor configuration

Populate `EXECUTOR_TENANT_ID`, actual `RAZORPAY_ACCOUNT_ID`, `RAZORPAY_KEY_ID`
(`rzp_test_` only), `RAZORPAY_KEY_SECRET`, and a dedicated 32+ character
`RAZORPAY_WEBHOOK_SECRET`. Generate a separate strong `EXECUTOR_AUTH_TOKEN` shared
only by gateway/executor. Configure `EXECUTOR_URL=http://localhost:8001` locally;
Compose sets the internal service address automatically. Keep provider secrets out
of agent and gateway environments. Compose explicitly passes them only to executor
and reconciler; do not use a global `env_file` for every service. Secret-file sources
`NAME_FILE` are supported by executor configuration and must be protected regular
files (0600/0400), with exactly one source per secret. Mount them explicitly when
using containers. Never use live keys: startup rejects them.

Expose only `/v1/webhooks/razorpay` through your HTTPS ingress to executor port 8001.
Keep `/internal/*` private in addition to its bearer authentication. Configure the
actual account's payment and refund webhooks with the dedicated secret. Resources
and payment mappings must already refer to actual imported records; webhooks never
create orders from untrusted event contents. Unprocessed provider refunds remain
PENDING until the reconciler observes their final status.

No real Razorpay credentials were supplied here. Adapter protocol tests use
synthetic fixtures exclusively in tests; no live test-account refund was performed.

## Real-data and credential provisioning

The gateway starts with empty business and identity tables. The trusted operator
must first import actual users, orders and tickets from the source of record:

```sh
python -m intentlock.operator import "$REAL_EXPORT_PATH"
```

The export object contains exactly `users`, `orders`, and `tickets` arrays:

| Record | Required fields |
| --- | --- |
| User | `id`, `tenant_id`, actual Ed25519 `public_key` (base64 raw 32 bytes), `active` boolean |
| Order | `id`, `tenant_id`, `paid_paise`, `refunded_paise`, `currency` (`INR`), original `destination`, `version` |
| Ticket | `id`, `tenant_id`, `order_id`, `text` |

Import is strict, transactional and insert-only. IDs are globally unique and
bounded to 128 characters. No existing balances or versions are reset. If a new
human has no key yet, the existing `intentlock.operator keygen` command can create
an encrypted bootstrap key before importing that actual human's record; its
password and output path come from `SIGNING_KEY_PASSWORD` / `SIGNING_KEY_PATH`.
Key generation creates security material, never fictitious human identities.

Import the actual source-system payment mappings next:

```sh
python -m app.auth.cli import-payments "$REAL_PAYMENT_EXPORT_PATH"
```

This file is a JSON array with `id` (actual payment ID), `tenant_id`, `order_id`,
`destination_kind`, and integer `in_flight_refunds` (0 or 1 from actual state).
Each payment must reference an existing order in the same tenant. This first
adapter supports **one payment per order**; the order owns financial amounts,
original destination, currency and version. `destination_kind` must resolve to
`original_payment` for policy to permit a refund. Import never changes an
existing mapping or clears an existing in-flight reservation.

Register a human-owned JWT signing key. For a fresh key, set
`GRANT_PRIVATE_KEY_FILE` to a new protected secret-file path and set
`GRANT_PRIVATE_KEY_PASSWORD` through your environment/secret manager (at least
16 bytes). The human must already exist and be active:

```sh
python -m app.core.keys generate \
  --kid "$NEW_SIGNING_KID" --operator-id "$HUMAN_SIGNER_ID" \
  --tenant-id "$REAL_TENANT_ID"
```

This exclusively creates an encrypted mode-0600 PEM and registers only its public
half. Existing kids/files cannot be overwritten. To register an existing public
PEM instead, use `app.core.keys register --kid ... --operator-id ... --tenant-id
... --public-key-file ...`. Rotation adds a new kid; old kids verify until revoked:

```sh
python -m app.core.keys revoke --kid "$OLD_SIGNING_KID"
```

Configure the trusted gateway issuer with **one** of:

* `GRANT_PRIVATE_KEY_FILE`: regular, non-symlink file readable by the gateway,
  with no group/other access (0600 or 0400).
* `GRANT_PRIVATE_KEY_PEM`: PEM supplied by a secret manager/environment.
* `GRANT_KEY_FILE_MAP`: JSON mapping of registered kids to protected mounted PEM
  paths, for multiple human operators/tenants. Do not also configure a single-key
  source. File contents never come from client input or JWT header URLs.

`GRANT_PRIVATE_KEY_PASSWORD` is used only for encrypted keys. The loaded public
half must match the session's registered kid and its human/tenant ownership.
Compose can receive the single PEM through environment injection; protected file
maps additionally require your deployment to mount those actual secrets with
appropriate ownership/permissions. No keys are generated at application startup.
Agents and the browser never receive these variables or filesystem access.

After externally authenticating the real human, trusted administration provisions
an opaque session and CSRF token. Choose TTLs and service IDs from actual policy:

```sh
python -m app.auth.cli operator-session \
  --operator-id "$HUMAN_SIGNER_ID" --kid "$NEW_SIGNING_KID" \
  --ttl "$SESSION_TTL_SECONDS"
python -m app.auth.cli agent-key \
  --service-id "$REAL_SERVICE_ID" --tenant-id "$REAL_TENANT_ID" \
  --actor-id "$REAL_AGENT_ACTOR_ID" --ttl "$SERVICE_KEY_TTL_SECONDS"
```

Capture credential JSON securely. Raw service/session/CSRF secrets are random
security tokens and are stored only as SHA-256 hashes in the database. Human
sessions require an active user and owned registered signing kid. Set credential
rows `active=false` through trusted administration to revoke them; expiry and
human deactivation are enforced on every request. There is no public endpoint
that creates users, service keys, or operator sessions.

## Endpoint contracts

`POST /v1/proposals` and `POST /v1/execute` accept only the database-backed
`Authorization: Bearer <agent service key>`. Because the requested endpoint list
explicitly includes agent execution, these are the **two** permitted agent routes.
That key cannot authenticate human reads, approvals, session entry, or legacy
routes. Supplying both human cookies and an agent bearer is rejected. A different
service cannot redeem another service's approval, even in the same tenant.

| Endpoint | Authentication and behavior |
| --- | --- |
| `POST /v1/proposals` | Strict `ProposedAction` JSON. Tenant and actor must match the service. Fetch live resource, evaluate policy, then persist a `PENDING` proposal and receipt. Returns 201 and proposal ID/digest. |
| `GET /v1/proposals/{id}/preview` | Human session cookie. Re-fetch live payment/order; enforce tenant read scope and refund policy. Return amount, currency, original destination, order version, remaining refundable and server digest. Record exactly the effect seen by this human session. |
| `POST /v1/proposals/{id}/approve` | Human cookie plus `X-CSRF-Token`. Body is empty or `{}`; any client digest/arguments are rejected. Re-fetch and re-evaluate; require this session's matching preview, then recompute the digest and issue one JWT. Duplicate approval cannot mint a second grant. |
| `POST /v1/execute` | Agent bearer plus required **HTTP `Idempotency-Key` header**. JSON body has exactly `action` and `grant_token`. On a new execution, verify/consume the grant, evaluate live policy, then orchestrate the effect in the same SQL transaction. |
| `POST /v1/session` | Authenticate an **already provisioned** human session using JSON `session_token` and `csrf_token`; set the protected cookie. This exchanges an existing credential, never creates a session. Agent keys cannot be exchanged. |
| `DELETE /v1/session` | Human cookie and `X-CSRF-Token`; revoke the stored session and clear its cookie. |

All lookups are tenant-scoped. Missing/cross-tenant proposal IDs return the same
`PROPOSAL_NOT_FOUND`. The service cannot choose another tenant or actor through
query parameters or body fields. Cross-site browser requests, ambiguous headers,
duplicate session cookies, duplicate JSON members, extra fields, malformed JSON,
non-NFC strings, floats, numeric coercion and unsafe integers fail closed. Origin,
when supplied, must exactly match `APP_ORIGIN`; nonbrowser clients can omit it but
still need session CSRF for approval/revocation.

A minimal agent flow using actual files and credentials:

```sh
curl --fail-with-body "$GATEWAY_URL/v1/proposals" \
  -H "Authorization: Bearer $AGENT_SERVICE_KEY" \
  -H 'Content-Type: application/json' --data-binary @"$REAL_ACTION_PATH"
```

The human uses the console or calls preview/approve with their cookie. Approval
returns a single-use `grant_token`; return it to the submitting service. Execution
body is exactly the original typed action plus that real returned token:

```sh
curl --fail-with-body "$GATEWAY_URL/v1/execute" \
  -H "Authorization: Bearer $AGENT_SERVICE_KEY" \
  -H "Idempotency-Key: $REAL_OPERATION_KEY" \
  -H 'Content-Type: application/json' --data-binary @"$REAL_EXECUTION_PATH"
```

Idempotency keys are 1–128 ASCII letters/digits or `_ . : -`, scoped to tenant and
service. Same key plus the identical canonical action and token returns the stored
refund ID with a fresh `IDEMPOTENT_RETRY` receipt. This is retrieval of an already
committed result, not a new effect or fresh grant use; it does not repeat grant or
policy execution. The agent credential must still be active. The response records
the current receipt policy and the original execution policy separately. A
changed request under the same key returns `IDEMPOTENCY_CONFLICT`; a used grant
under a new key returns `GRANT_USED` while unexpired. New calls never use retry
logic to bypass verification or policy.

## Deterministic YAML policy

`policies/refunds.yaml` is strict, versioned YAML loaded **once at startup**. Its
`policy_version` is `sha256:` plus SHA-256 of the **exact file bytes**, including
comments/whitespace. `POLICY_VERSION` environment values do not override it.
Unknown fields, duplicate keys, unsafe tags, anchors/aliases, duplicate rule IDs,
invalid tools/scopes, floats and malformed limits prevent startup. The in-memory
snapshot uses immutable mappings/sets and is not changed by editing the file.

Keep `schema_version: 1`, `default: deny`, and all named rule IDs. Under `tenants`,
configure each **real** tenant ID with these required fields:

| Tenant configuration | Meaning |
| --- | --- |
| `tools` | Explicit allowlist; currently only `refund.create` is understood. An empty list denies writes. |
| `max_refund_paise` | Positive safe integer cap on **cumulative refunded amount per payment**, including the proposed refund. This prevents splitting a larger refund into smaller calls. |
| `read_scopes` | Explicit auto-allowed reads; currently `payment.read`. Empty means no read scope. A grant is never needed for an in-scope read. |

Refund rules execute in fixed order: supported schema, tenant scope, tool
allowlist, payment/order association, current resource version, original payment
destination, INR currency, cumulative cap, remaining refundable balance, and no
in-flight refund. Every decision identifies its fired `rule_id` and the policy
hash. Exceptions produce `POLICY_ERROR` under the configured default-deny rule.
No model, customer text, random value or external call makes a policy decision.

Proposals, previews and approved grants are bound to the deployed policy hash.
After a policy restart, old proposals/approvals require a new submission. Approval
and execution additionally compare the complete trusted effect snapshot, catching
an unversioned destination/balance change. Re-fetching does not silently update a
stale proposed action; a changed effect requires a fresh proposal/review.

## Transactions, receipts and deny codes

Production uses a separate trusted executor (`app.executor.main:app`). The gateway
holds only its internal RPC token; Razorpay credentials are supplied exclusively
to the executor and reconciler. Explicitly injected database adapters remain for
reference tests. Environment-based production startup requires `EXECUTOR_URL` and
`EXECUTOR_AUTH_TOKEN` and cannot silently fall back to ledger-only execution.

A transaction first conditionally consumes an unexpired ACTIVE grant, verifies
its signature and approved proposal, reserves the payment, and inserts a PENDING
operation with unique `(tenant_id, idempotency_key)` and grant jti. The transaction
commits before provider I/O. Exact retries return the persisted result; changed
requests deny IDEMPOTENCY_CONFLICT. A used grant with a new key denies GRANT_USED.
The executor re-fetches live payment state, checks the approved resource hash and
policy, then persists dispatch intent before calling Razorpay. A changed resource
fails STALE_RESOURCE without a provider call; the grant remains USED.

Provider refund creation uses the operation UUID in both `receipt` and
`X-Refund-Idempotency`, always with the same amount and `speed=normal` body.
DONE requires a processed provider refund and a refreshed absolute refunded balance.
Timeouts, ambiguous responses and persistence errors remain PENDING, holding the
payment reservation. Leases fence stale workers. The reconciler queries actual
provider refunds before retrying and reuses the same provider key; it never creates
a replacement key for an uncertain refund. Duplicate prevention depends on
[Razorpay's refund idempotency contract](https://razorpay.com/docs/api/refunds/normal-refunds-idempotent/),
not a fictitious distributed transaction. No undocumented idempotency expiration
is assumed. Stale ambiguous operations stay reserved for investigation.

`resources.version_hash` is SHA-256 of the JCS-encoded ordered array
`[provider_id, amount_paise, amount_refunded_paise, status]`. Provider synchronization
updates the actual order balance absolutely and increments its integer version on
change. Approval stores both this hash and the refunded baseline. Old approvals
without provider-backed hash metadata cannot execute through the executor.

The webhook verifies HMAC-SHA256 over the **raw body** using the dedicated webhook
secret before parsing. It checks the configured account, supported event and
pre-provisioned tenant payment mapping; event IDs and body hashes deduplicate
retries. It re-fetches live state rather than incrementing event amounts, so
reordered deliveries cannot regress a balance merely because of old event content.
See [Razorpay webhook verification](https://razorpay.com/docs/webhooks/validate-test/).
Concurrent synchronizations fence the observed cache version and re-fetch on conflict.

Assumptions: one test merchant account maps to one configured tenant per executor;
separate accounts/tenants require separate executor deployments and gateway routing.
All refund writers must coordinate through this gateway. Razorpay offers no payment
version compare-and-swap spanning the final GET and refund POST; an independent
merchant-side change in that interval cannot be prevented locally. Provider limits
remain authoritative. SQLite is tested; no live Postgres instance was used.

Every action response includes `allowed`, `reason`, `rule_id`, `policy_version`
and a `receipt_id` when persistence succeeds. Receipts store hashes/minimal
metadata, never customer text, session secrets, private keys or bearer JWTs.
Body size is bounded at 65,536 bytes; oversized requests hash only the bounded
prefix. If the database cannot even persist a denial, return 503
`AUDIT_UNAVAILABLE` and no successful result. Persisting into a failed database
is impossible; no receipt-persistence guarantee is claimed during that outage.

| Deny reasons | Fired condition |
| --- | --- |
| `UNAUTHENTICATED`, `CSRF_INVALID`, `WRONG_TENANT`, `ACTOR_MISMATCH` | Credential/session scope, expiry/revocation, same-origin or CSRF failure |
| `INVALID_REQUEST`, `AMBIGUOUS_HEADERS`, `INVALID_CONTENT_TYPE`, `REQUEST_TOO_LARGE`, `ENDPOINT_NOT_ALLOWED` | Strict wire/route validation |
| `TENANT_OUT_OF_SCOPE`, `TOOL_NOT_ALLOWED`, `READ_OUT_OF_SCOPE`, `UNSUPPORTED_SCHEMA_VERSION` | Missing explicit policy permissions |
| `RESOURCE_NOT_FOUND`, `INVALID_RESOURCE`, `RESOURCE_MISMATCH`, `STALE_RESOURCE` | Missing/inconsistent/unbound or changed live resource |
| `DESTINATION_NOT_ORIGINAL`, `CURRENCY_MISMATCH`, `REFUND_LIMIT_EXCEEDED`, `INSUFFICIENT_REFUNDABLE`, `REFUND_IN_FLIGHT` | Deterministic refund rules |
| `PROPOSAL_NOT_FOUND`, `PROPOSAL_ALREADY_APPROVED`, `PREVIEW_REQUIRED`, `PREVIEW_STALE`, `POLICY_CHANGED`, `PROPOSAL_NOT_APPROVED` | Human review/approval provenance |
| `IDEMPOTENCY_KEY_REQUIRED`, `INVALID_IDEMPOTENCY_KEY`, `IDEMPOTENCY_CONFLICT` | Required stable execution key or exact request binding |
| `BAD_SIGNATURE`, `ALG_NOT_ALLOWED`, `EXPIRED`, `WRONG_AUDIENCE`, `ACTION_MISMATCH`, `GRANT_USED`, `UNKNOWN_KEY` | Pinned JWT verification and single use |
| `POLICY_ERROR`, `INTERNAL_ERROR`, `AUDIT_UNAVAILABLE` | Fail-closed operational failures |

HTTP status is 401 for failed authentication, 400 for invalid schema/headers,
404 for unavailable scoped resources/proposals, 409 for idempotency conflicts,
413/415 for size/type, 503 for operational/audit failures, and 403 for ordinary
authorization denies. Invalid policy prevents serving at all.

## Core contracts and trust assumptions

`app/core/canonical.py` provides frozen strict `ProposedAction`/`RefundArgs` models,
`parse_action`, `canonicalize` (JCS UTF-8 bytes) and `digest` (`sha256:<hex>`). Action
fields are `v`, `tool`, `args`, `tenant_id`, `actor_id`, `resource_ref` and
`resource_version`. Arguments are `payment_id`, positive integer `amount_paise`,
`currency=INR`, and enum `destination=original_payment`. All fields participate in
the digest. Canonicalization admits positive safe schema versions; the production
policy currently accepts only version 1. Integer `499` is valid; `"499"` and
`499.0` in an integer field are rejected. Non-NFC strings are rejected, not
normalized. Use original JSON bytes to detect duplicate members before an ordinary
parser discards them. Published [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
vectors exercise the underlying serializer separately from float-free actions.

`app/core/grants.py` issues EdDSA/Ed25519 JWTs with `iss`,
`aud=intentlock-gateway`, human `sub`, `tid`, UUID4 `jti`, integer `iat`,
`exp=iat+300`, `act_digest`, `res_ver` and `max_uses=1`. Key IDs are pinned to active
registry rows and owner/tenant identities. All claims, exact token hash and kid
must match the `ACTIVE` issued row. Header-provided key URLs/embedded keys are
rejected. Time leeway is fixed at 30 seconds; `now >= exp+30` denies, as does
issuance more than 30 seconds in the future. The action digest uses constant-time
comparison. Unknown/revoked kids and inactive owners deny. Rotation keeps an old
kid usable until explicit revocation. Verification never loads a private key.

Standalone `verify_grant` consumes a grant. Production executor reservation uses
a conditional consumption plus cryptographic validation in the same transaction
as the durable operation. Provider I/O begins only after commit. The grant
primitive alone does not evaluate business policy.

The LLM is an untrusted proposer and never receives operator/session/CSRF secrets,
private keys, database credentials, provider credentials or the gateway process
filesystem/environment. Unlike the earlier offline-only prototype, this v1
server is explicitly authorized to sign after an authenticated human's CSRF-
protected approval. There is no LLM-accessible signing path. Physical human
presence cannot be proved cryptographically: stolen sessions, a compromised
human/gateway host, malicious trusted administration, or a compromised signing key
are outside this boundary. Use TLS outside loopback and keep private material out
of agent/code-execution containers. Randomness creates only security credentials,
key material and opaque record IDs; it never fabricates business values.

## Support intake and the Gemini proposal worker

`/support` is a public form backed by `POST /public/tickets`. It begins with empty
fields and can take the actual provisioned channel from `/support?channel=<id>`.
Provision an actual support channel for an existing tenant through trusted CLI:

```sh
python -m app.auth.cli support-channel --channel-id "$SUPPORT_CHANNEL_ID" --tenant-id "$REAL_TENANT_ID"
```

The JSON body is exactly `channel_id`, optional `order_id`, and `text`. Tenant scope
comes from the active database channel, never a body tenant. Limits are 65,536 wire
bytes and 16,000 text characters. A stable 32+ character INTAKE_RATE_SECRET enables
persistent HMAC-keyed peer counters: ten attempts per 60 seconds, shared across
workers; invalid/oversized attempts count too. Exceeding the limit returns 429
RATE_LIMITED with Retry-After. Missing configuration fails closed. The socket peer
is used; spoofed forwarding headers cannot evade limits. Behind the supplied web
proxy, clients share the proxy's limit. Put public per-client limits at your ingress
if you need independent customer quotas; do not blindly trust forwarded headers.

Tickets retain original decoded raw text in `tickets.text` and a deterministic
`redacted_text`. Redaction normalizes a separate projection using NFKC, removes
format characters, maps Unicode decimal digits and masks email addresses,
phone/card-like digit runs, UUIDs and identifier-like values. Raw Unicode text is
preserved unchanged. This conservative matcher can over-mask and does not claim
perfect recognition of arbitrary obfuscated personal data. No model receives raw
ticket text through the supported path. Old imports are re-redacted at claim time,
so a null or old redacted projection is never blindly trusted.

An optional order reference associates only an existing order in that channel's
tenant; unknown/cross-tenant references are accepted as **unlinked** with the same
public response. A customer-supplied reference is not proof of ownership. Unlinked
tickets and email tickets require a human to associate the actual order using
`POST /v1/tickets/{id}/link` with `{"order_id":...}`, an operator session and CSRF.
Humans must verify the underlying customer request before signing approval.

Provision the worker's own tenant/actor service credential (save its one-time JSON
output securely and set AGENT_SERVICE_KEY in your secret manager):

```sh
python -m app.auth.cli agent-key --service-id "$AGENT_SERVICE_ID" --tenant-id "$REAL_TENANT_ID" --actor-id "$AGENT_ACTOR_ID" --ttl "$AGENT_KEY_TTL"
docker compose --profile agent up --build
```

Set GEMINI_MODEL to an actual available model and GEMINI_API_KEY to the real API
key. `Dockerfile.agent` builds a separate non-root read-only worker image with only
its HTTP/model contracts, no database driver or volume, signing modules, executor
modules, provider keys, signing keys or receipt key. Compose supplies exactly
GATEWAY_URL, AGENT_SERVICE_KEY, GEMINI_MODEL and GEMINI_API_KEY to that process.
It never sources a global .env. Host execution is development-only and must use
an isolated identity/filesystem and minimal environment; startup rejects inherited
privileged variables. To process one ticket through Compose:

```sh
docker compose run --rm agent python -m app.agent.worker --once
```

The worker claims a tenant-scoped ticket with a five-minute lease via
`POST /v1/agent/tickets/claim`. The gateway checks the payment.read policy scope
and returns only redacted content plus trusted payment/resource metadata.
Gemini receives customer text in a separate JSON data field and an explicit system
instruction that it cannot approve or authorize anything. The only declared
function is `propose_refund(payment_id, amount_paise, reason)`. No code execution,
search, approval, signing or execution tools are exposed. Protocol follows the
[Gemini generateContent API](https://ai.google.dev/api/generate-content) and
[function-calling documentation](https://ai.google.dev/gemini-api/docs/function-calling).

The worker requires one unambiguous function call, its exact name and strict
arguments: positive safe integer paise, the trusted payment ID, and a bounded
reason. Floats, strings for money, duplicate keys, extra fields, unknown functions,
multiple calls and substituted payments are dropped. INVALID_PROPOSAL is reported
to `POST /v1/agent/model-calls`, where the gateway writes a signed DENY receipt.
The agent never holds the receipt signing key. Valid suggestions become exact
ProposedActions sent to `/v1/proposals`; tenant, actor, destination, resource/version
come from trusted context, not model arguments. The untrusted free-text reason is
discarded and never becomes authorization data or raw receipt text.

The worker has no execute implementation. Existing `/v1/execute` authorization
continues to require an operator-issued grant matching the canonical action;
claims, policy, single use and provider enforcement remain unchanged. A separate
trusted grant handoff may execute the approved action for the submitting service.
Ticket text and function output can never mint a grant. Prompting is an aid, not
the authorization boundary.

Each model attempt records configured model, real provider-reported input/output/
total token counts (null when unavailable), measured model latency in integer ms,
and a fixed outcome in `model_calls`. Telemetry/report receipts commit together;
claim tokens bind reports to the tenant, service and ticket and deduplicate retries.
No prompt, completion, free-text reason or raw ticket is stored in telemetry or
receipts. Metrics reported by an untrusted worker are informational, never an
input to authorization or billing. A lost worker retries via lease expiry; this
may repeat a model call/proposal, but cannot create an authorized refund.

Optional real-email ingestion:

```sh
docker compose --profile imap up --build
# Or one bounded mailbox pass:
docker compose run --rm imap python -m app.intake.imap --once
```

Set IMAP_HOST, IMAP_PORT, IMAP_USERNAME, IMAP_PASSWORD, IMAP_MAILBOX and the actual
IMAP_CHANNEL_ID. This trusted intake process gets DB/receipt credentials, but no
grant/private provider keys. It uses certificate-verified TLS, read-only SELECT,
UID SEARCH ALL and BODY.PEEK; it never sends, deletes or marks email read.
UIDVALIDITY plus mailbox/account/host/UID produce a stable deduplication hash.
At most 50 unseen-to-the-database deliveries are processed per pass, every 30s.
Use a dedicated support mailbox; overly large search responses fail closed.
Only plain-text MIME bodies are admitted, with a 256 KiB message cap and 16,000
character decoded cap; attachments are ignored and HTML-only/unsupported/oversized
messages get durable rejection markers and signed denials, so they do not starve
subsequent mail. Sender text/headers never select tenant or authorize an order.

No live Gemini call, mailbox connection or provider refund was made during local
verification because real credentials were not supplied. Tests inject fixture-only
HTTP/IMAP transports and exercise the actual gateway, policy, database and receipts.

## Signed receipts

Every new receipt is appended using `app/core/receipts.py` in the decision's SQL
transaction. Each authenticated tenant has an independent chain with committed
sequence numbers starting at 1. A locked `receipt_heads` row serializes writers;
head updates, receipt insertion and decision changes roll back together. A unique
`(tenant_id, seq)` constraint adds a database guard. Unauthenticated failures have
`tenant_id=null` and use a separate system chain; the application never guesses a
tenant from an untrusted request. The operator API cannot read that system chain.

Receipt fields include id, tenant_id, seq, decision, reason_code, rule_id,
policy_version, action_digest, grant_jti, actor_id, operation_id, created_at,
prev_hash, receipt_hash and signature. Existing structured compatibility columns
(timestamp, allowed, reason, input_hash, request_id, refund_id) are also included
in the signed payload. No raw request, ticket text or token is retained. The genesis
prev_hash is 64 zeroes. `receipt_hash` is lowercase SHA-256 hex of RFC 8785 JCS of
**every persisted receipt column except receipt_hash and signature**. The signature
is standard base64 Ed25519 over the 32 raw digest bytes. Verification uses the
configured receipt key's public half, never a key supplied in the receipt itself.

Generate the dedicated persistent key once with
`python -m app.core.receipts /secure/path/receipts.pem`; this also prints its public
PEM for independent retention. Configure exactly one of RECEIPT_PRIVATE_KEY_FILE
(protected regular 0600/0400 file) or RECEIPT_PRIVATE_KEY_PEM; encrypted files/PEMs
may use RECEIPT_PRIVATE_KEY_PASSWORD. Gateway, executor and reconciler must share
the same receipt key. Startup fails if it is missing. It must differ from grant
keys; registered grant public keys and valid single-key secret configuration are
checked. Do not replace this key on restart or rotate it without a separately
planned historical-verifier migration. No receipt-key rotation is implicit.

Compose passes receipt configuration only to trusted writers. For a local file,
mount it explicitly at the configured container path and ensure UID 10001 can read
it while its permissions remain 0600/0400. Alternatively, pass PEM through your
secret manager as RECEIPT_PRIVATE_KEY_PEM; avoid configuring both sources.

Authenticated human-session endpoints:

- `GET /v1/receipts?limit=50&after_seq=0&decision=ALLOW&reason=PROPOSAL_ACCEPTED`
  returns items, next_after_seq and snapshot_seq. Limit is 1–200. Decision/reason
  filters are optional. For a stable finite traversal, retain snapshot_seq and send
  it on every subsequent page along with next_after_seq. Tenant scope comes solely
  from the session; caller-supplied tenant parameters are rejected.
- `GET /v1/receipts/verify` walks the entire tenant chain in sequence, checking gaps,
  prev_hash, JCS hashes, Ed25519 signatures and the persisted high-water head.
  It reports valid, checked, reason and first_broken_seq. Verification locks the
  head so concurrent appends cannot produce a false broken-link report. A successful
  check returns the checked head_seq/head_hash before its own audit append. Broken
  tenant-chain verification is audited in the independent system chain so a deleted
  tail does not block the diagnostic response.

Migration 0005 preserves old unsigned receipts with null chain metadata; it does
not fabricate tenant ownership or retroactively sign historical decisions. Those
rows remain available to trusted database administration and are explicitly
reported LEGACY_UNSIGNED by core system-chain verification. Tenant API chains cover
new signed decisions after migration. Keep pre-migration audit backups separately.

The persisted head detects deletion of the final or every receipt. An attacker who
can roll back **both receipts and heads together** can replay an older valid state;
retain head_seq/head_hash and the public key outside the database to detect such
rollback. The database is not an external notarization service. A missing signing
key or audit write failure prevents a successful decision; audit database outages
remain AUDIT_UNAVAILABLE, as documented above.

## Live evaluation and Stitch Metrics

`tools/eval/` runs misuse (60), valid (40), concurrency (50 requests / one grant),
actual provider-bypass baseline and measured provider-excluded latency against an
already running test-account stack. It requires genuine captured tickets/grants,
real expired/used grants, four distinct post-webhook stale approvals and actual
cross-tenant provider observers. It never seeds business data or simulates replies.
Read [the live evaluation runbook](tools/eval/README.md) for exact preparation,
secret handling, budget limits, reason-code expectations and interpretation.

Configured runs, including blocked/failed attempts, are checkpointed in eval_runs
with actual Git/build provenance and UTC timestamps. Operator-only APIs are
`GET /v1/eval-runs` and `GET /v1/eval-runs/{id}`. The `/metrics/` page is built from
`stitch_intentlock_operator_console/metrics_intentlock/`, follows that frontend's
design and fetches actual persisted history; absent measurements stay unmeasured.
No live evaluation results are claimed by the code/unit tests. This workspace has
no Git repository, captured real grants or supplied live service/provider credentials;
a full live benchmark cannot be truthfully reported until those are provided.

## File map and verification

| Paths | Responsibility |
| --- | --- |
| `app/main.py`, `app/config.py`, `app/api/gateway.py` | Production routes, startup policy/configuration, transaction workflows |
| `app/core/policy.py`, `policies/refunds.yaml` | Immutable deterministic rule engine and default-deny deployment artifact |
| `app/executor/` | Credential-isolated Razorpay test adapter, durable execution, webhook, RPC and reconciliation |
| `app/adapters/payments.py`, `app/core/orchestrator.py` | Explicit reference database adapters used in regression tests |
| `app/auth/service.py`, `app/auth/cli.py` | Tenant service keys, human sessions, CSRF and trusted provisioning |
| `app/intake/`, `app/agent/`, `web/src/Support.tsx`, `tests/test_intake_agent.py` | Public intake, masking, IMAP, isolated Gemini proposals and telemetry |
| `app/core/receipts.py`, `app/api/receipts.py`, `tests/test_receipts.py` | Signed chains, authenticated inspection and tamper/concurrency tests |
| `app/core/canonical.py`, `app/core/grants.py`, `app/core/keys.py` | Canonical contracts, JWT consent, public-key registry and key lifecycle |
| `intentlock/db.py`, `migrations/versions/0001_initial.py`, `0002_jwt_grants.py`, `0003_gateway.py`, `0004_executor.py`, `0005_receipts.py`, `0006_intake_agent.py` | Portable schema and empty-data migrations |
| `web/src/main.tsx`, `web/src/style.css`, `web/vite.config.ts`, `web/nginx.conf` | Same-origin live human consent UI |
| `tests/test_gateway_v1.py`, `tests/test_policy.py`, `tests/test_auth_provisioning.py` | Endpoint/rule/identity/transaction/concurrency regressions with fixture-only business data |
| Other `tests/test_*.py` | Canonical, published JCS, Hypothesis, grant/key lifecycle, migration and earlier regression tests |
| `pyproject.toml`, `requirements.lock`, `web/package-lock.json`, `Dockerfile`, `compose.yaml`, `.env.example` | Dependencies, deployment and environment contracts |

`intentlock/api.py` and its earlier envelope utilities remain as regression/reference
code; the production Docker entrypoint and console use `app.main:app` and `/v1`.
`intentlock.agent` now delegates to the isolated Gemini worker; the old raw-context
model adapter has been removed. The worker submits typed proposals to `/v1/proposals`. No live provider, bank,
model API or Postgres call was performed during testing. Docker startup remains
unverified because Engine is unavailable in this environment.

Verified in this workspace: **524 pytest cases passed**, including 106 v1
policy/workflow/authentication tests, plus TypeScript/Vite production build and
Alembic metadata/Compose configuration checks. The updated console was visually
checked with honest empty states. Docker Engine and live external payment/model
providers were not used.

### Performance and Daybreak

IntentLock has no Daybreak runtime dependency. Metrics history uses indexed,
tenant-scoped keyset pagination and reads summaries without loading per-case
JSON; opening a run loads its details separately. Provider observation batches
payment lookup into two SQL reads, independent of the number of payment IDs.
Apply `alembic upgrade head` to install the history indexes on an existing DB.

The live evaluator measures actual gateway overhead separately from actual
provider I/O. Local tests check concurrency, recovery, and bounded query behavior;
they do not establish production latency. Run the live evaluation described in
`tools/eval/README.md` with real test-mode credentials and captured grants before
claiming deployment throughput or latency. Signing and receipt writes remain
mandatory on the decision path.
