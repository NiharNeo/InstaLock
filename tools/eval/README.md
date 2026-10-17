# Live IntentLock evaluation

This runner requires an already running **trusted-executor** stack, actual database
records, real Razorpay **test-mode** API access, and real operator/service credentials.
There is no fixture, mock, seeded-payment, synthetic-grant, or offline scoring mode.
Unit tests under `tests/test_eval.py` are explicitly fixtures and are not benchmark
runs. Do not put capture artifacts into source control, a slide deck or an agent image.

## Install and configure

Run Alembic 0007 against the same database used by the live gateway/executor, then
restart both services to enable provider span metadata and the Metrics API:

```sh
.venv/bin/pip install --no-deps -e .
.venv/bin/alembic upgrade head
docker compose up --build -d
umask 077
mkdir -p .eval-private
```

Run the trusted evaluator where it can access the **actual stack database**. For
SQLite this means the same database file, not a copy/export. A bind-mounted ledger
can be accessed by a host runner. The default Compose named volume is inside Docker;
run the evaluator in an administrative environment with that volume mounted, or
configure a real shared Postgres connection. Do not silently substitute a new empty
SQLite file. The provider observer command must also be available in that environment.

Required environment:

| Variable | Actual deployment value |
| --- | --- |
| DATABASE_URL | The live stack database URL |
| EVAL_TENANT_ID | Actual tenant represented by the operator and service key |
| EVAL_GATEWAY_URL | Running gateway origin, HTTPS except loopback/internal service |
| EVAL_AGENT_SERVICE_KEY | Actual submitting service key matching the captures |
| EVAL_OPERATOR_SESSION | Provisioned active operator session secret |
| EVAL_CSRF_TOKEN | That session's CSRF token |
| EVAL_APP_ORIGIN | Exact deployed APP_ORIGIN |
| EVAL_POLICY_FILE | Exact deployed policy artifact; its hash must match live receipts |
| EVAL_PROVIDER_COMMANDS | JSON object mapping actual tenant IDs to executor-local probe argv vectors |
| EVAL_GIT_SHA | Optional explicit **actual build SHA** when the checkout's Git HEAD is unavailable |

No signing or Razorpay key is passed to the runner or untrusted agent. The provider
command runs `python -m app.executor.eval_probe` **inside each trusted executor's
own environment**. On a host with Docker, a command vector can consist of `docker`,
`compose`, `exec`, `-T`, the actual executor service name, `python`, `-m`, and
`app.executor.eval_probe`. Use a separate real executor/account command for the
other tenant. Commands are deployment-owned JSON argv vectors, run without a shell;
stdout is bounded evidence, stderr is never printed with credentials. There is no
HTTP provider-bypass route. Only an administrator able to invoke that executor-local
CLI can run the bypass baseline. The CLI refuses live-mode Razorpay configuration.

Set EVAL_PROVIDER_COMMANDS with your **actual tenant names** as keys, not copied
sample identities. `python -m tools.eval schema` prints the plan schema; it does not
generate sample business data. `schema --capture` prints the capture schema.

This workspace has no Git repository. A real run blocks with GIT_SHA_UNAVAILABLE
unless actual build provenance is supplied. It never fabricates a Git hash.

## Capture actual tickets and grants

Use the running UI/API to submit a real ticket-associated proposal, load its live
preview, and approve it with a real operator session and CSRF. Store the returned
exact bearer token in a protected file (0600/0400). Capture export validates the
real ticket/order/payment association, proposal digest/action, submitting actor,
actual database grant/token hash, pinned Ed25519 signature, key ownership and
historical prerequisites. It exports references and action metadata, **not ticket text**.

```sh
python -m tools.eval capture --name "$CAPTURE_NAME" --role fresh \
  --ticket-id "$TICKET_ID" --proposal-id "$PROPOSAL_ID" \
  --grant-file "$REAL_GRANT_FILE" --output "$CAPTURE_FILE"
```

Required capture roles:

- `fresh`: real approved refund action. Supply a base source, a different actual
  same-tenant payment source, and the sources to schedule 40 valid refunds plus
  one concurrency refund. Sources may be reused, but preflight requires enough
  actual remaining funds and cumulative policy capacity for all 41 intended allows.
  Every ordinary mutation and valid execution obtains a fresh real live preview and
  human-session approval; this avoids treating an expired source token as a fake pass.
  Financial values come from captured actions. Only resource_version is refreshed
  from the real database before requesting the actual live preview.
- `expired`: a real ACTIVE grant whose actual issued/database expiry has passed.
  Wait for its real 300-second lifetime. Do **not** edit exp or database state.
- `used`: a real consumed grant with a DONE operation from an earlier actual refund.
  Its original refund is a prerequisite, outside the misuse measurement window.
- `stale`: **four distinct actual approvals/grants** made before a real provider
  change delivered by a signature-verified webhook. Supply `--webhook-event-id`.
  Capture validation requires the tenant-bound WEBHOOK_APPLIED receipt to follow
  APPROVED in the signed sequence and requires a changed resource hash. The runner
  never signs or fabricates a webhook. Each stale grant is used once because the
  executor legitimately consumes it before failing STALE_RESOURCE. Keep these
  grants unexpired; reprepare them if prerequisites take longer than their lifetime.
- `different_tool`: an actual operator-signed ACTIVE grant bound to the JCS digest
  of the same captured action with **only tool changed**. Supply its exact token
  and `--other-tool-action-file` (also protected). Since the v1 gateway only admits
  refund.create, this prerequisite must be explicitly issued by trusted human
  administration through the existing `GrantService.issue_grant` primitive using
  the actual operator/kid and canonical other-tool digest. It is a security artifact,
  not a new business record, and cannot be issued by a model. Capture validation
  verifies that actual signed digest and database row; modifying JWT claims is not
  an acceptable substitute. No unsupported tool is executed.

The actual foreign payment ID must exist in another tenant's database mapping and
be independently observable through that tenant's actual executor/test account.
The runner does not create payments, tickets, identities, grants, webhook events,
refund balances or versions by writing fixture data to the database. Approvals go
through the real HTTP human-session authorization flow. Existing issuer primitives
are used only by explicit trusted prerequisite preparation, never by the runner.

Assemble a protected plan from actual exported captures. Repeat --capture-file for
all roles and four stale artifacts. --valid-name can be repeated for real source
captures; the plan cycles those names into exactly 40 slots without inventing money.

```sh
python -m tools.eval plan \
  --capture-file "$BASE_CAPTURE_FILE" \
  --capture-file "$ALTERNATE_CAPTURE_FILE" \
  --capture-file "$EXPIRED_CAPTURE_FILE" \
  --capture-file "$USED_CAPTURE_FILE" \
  --capture-file "$STALE_CAPTURE_FILE_1" \
  --capture-file "$STALE_CAPTURE_FILE_2" \
  --capture-file "$STALE_CAPTURE_FILE_3" \
  --capture-file "$STALE_CAPTURE_FILE_4" \
  --capture-file "$OTHER_TOOL_CAPTURE_FILE" \
  --base-name "$BASE_CAPTURE_NAME" --alternate-name "$ALTERNATE_CAPTURE_NAME" \
  --foreign-payment-id "$OTHER_TENANT_REAL_PAYMENT_ID" \
  --valid-name "$VALID_SOURCE_CAPTURE_NAME" \
  --concurrency-name "$CONCURRENCY_SOURCE_CAPTURE_NAME" \
  --output .eval-private/plan.json
```

Include any additional valid/concurrency captures in --capture-file. The JSON schema
also permits an explicit list of exactly 40 actual source names in valid_ids.
Preflight requires a quiescent test tenant, matching deployed policy, enough real
refund capacity and a running provider observer for every involved merchant account.
No incomplete prerequisites are converted to passing or skipped misuse tests.

## Run all phases

```sh
python -m tools.eval run --plan .eval-private/plan.json \
  --baseline --baseline-max-paise "$EXPLICIT_BASELINE_PAISE_BUDGET"
```

This performs **real test-account refunds**: 40 valid refunds, one concurrency refund,
and actual unsafe provider-bypass attempts. --baseline is explicit and its positive
integer budget is required. The budget conservatively reserves the captured amount
plus one paise before each baseline attempt, including rejected/unknown attempts.
The runner never uses a live-mode provider key. Running without --baseline performs
the defended suites but records INCOMPLETE, not a completed all-phases pass.

Default per-case observation window is five seconds; --observe-seconds accepts 1–60.
--settle-timeout bounds waiting for actual PENDING operations/reconciler completion.
There is no provider reply stub, time-travel, grant-row mutation, synthetic success,
provider-response replacement, account reset, or manufactured percentile.

### Sixty misuse probes

Four probes each for the first twelve categories below and three each for the last
four total exactly 60. Mutations clone actual captured financial values and real
alternate/foreign identifiers. The expected code is exact, not a generic non-2xx:

| Mutation | Exact expected reason |
| --- | --- |
| Changed amount | ACTION_MISMATCH |
| Changed destination | INVALID_REQUEST (only original_payment is in the enum) |
| Changed real payment ID | ACTION_MISMATCH |
| Other-tenant payment and tenant scope | WRONG_TENANT |
| Actually expired grant | EXPIRED |
| Used grant with a new idempotency key | GRANT_USED |
| Stale resource after actual verified webhook | STALE_RESOURCE |
| Forged Ed25519 signature | BAD_SIGNATURE |
| alg=none | ALG_NOT_ALLOWED |
| HS256 signed with the actual public key | ALG_NOT_ALLOWED |
| Missing grant | INVALID_REQUEST |
| Actual different-tool signed grant | ACTION_MISMATCH |
| Float money literal | INVALID_REQUEST |
| Duplicate amount JSON members | INVALID_REQUEST |
| NFC Cyrillic lookalike in the real payment prefix | ACTION_MISMATCH |
| Oversized arguments | REQUEST_TOO_LARGE |

Before and after each case, independently query both SQL refund IDs and the real
provider payment/refund collections. Require zero newly created provider records,
zero new SQL refunds, zero absolute refunded-balance change and no pending operation,
as well as allowed=false and the exact code. A failed case stops the run rather
than continuing to make unsafe requests. Historical used/stale setup refunds are
outside this incremental observation window. A finite window is recorded; this is
not a claim to observe future changes forever. Keep unrelated refund writers idle.

### Forty valid probes and the 50-way race

Each valid request gets a new actual proposal/preview/operator approval, then must
settle DONE. Assert exactly one new SQL refund and one new processed provider refund,
matching provider ID, operation receipt reference, amount and balance increment.
The race uses one freshly issued grant and fifty concurrent executes with **distinct**
idempotency keys. Require exactly one DB/provider refund and 49 GRANT_USED replies.
A timeout or uncertain provider outcome is never reported as success.

### Latency without fake provider responses

The executor timestamps every actual Razorpay request/response using its monotonic
clock and computes the union of provider spans. Those durations cross the trusted
RPC as private metadata. Public response headers expose gateway-path duration,
provider I/O duration and timing validity; the private metadata is removed from JSON.
Gateway middleware timestamps its request handling independently. Subtract durations,
not wall-clock timestamps across processes, to avoid clock-skew errors.

For the 40 valid execute responses, overhead is gateway-path ns minus actual provider
I/O ns. This includes gateway/executor logic, DB work and internal RPC overhead;
it excludes external client networking, approval preparation, provider observation
probes and asynchronous reconciliation. Client round-trip ns is retained separately.
Report nearest-rank p50/p95/p99 and sample count; small samples are not a production
latency guarantee. Async completion evidence is separate from initial HTTP timing.
Missing/invalid timing fails the valid case; no samples means null/unmeasured.

### Actual bypass baseline

After defended phases, the executor-local --bypass CLI projects each mutation's
payment_id and amount_paise into an actual Razorpay refund POST, ignoring gateway
credentials/grants/policy. Keys remain inside that executor. It uses new actual
provider idempotency references and never enters the gateway refund orchestrator.
It records accepted/rejected/uncertain provider outcomes and observed refund deltas.
Invalid ambiguous JSON or identifiers that cannot safely form a provider request
are NOT_REPRESENTABLE, not invented provider responses. The history distinguishes
actual POST count, unrepresentable cases and actual newly observed provider refunds.

This is an **explicitly defined unsafe implementation**, not an assertion about all
possible bypass implementations. It is unpaired/sequential: earlier real refunds
consume balances, provider limits may reject subsequent attempts, and unsupported
wire shapes have no measured provider response. No counterfactual refund count or
risk-reduction percentage is fabricated. Use sufficient actual test-account capacity
and read the per-case evidence rather than extrapolating a slide claim.

## Persistence, API and Stitch Metrics

Each configured run creates eval_runs before captures/network prerequisites are
loaded and checkpoints sanitized cases. Store actual Git/build SHA, UTC timestamp,
status, expected/attempted/passed counts, provider/SQL IDs and deltas, timings, capture
plan hash and fixed stop reasons. Never store capture bearer tokens, operator/service
secrets, raw tickets, raw wire bodies or arbitrary provider receipt text. Provider
receipt references in stored case evidence are hashed. Secret artifacts remain in
protected input files. If the database/schema itself is unavailable, persistence
cannot be promised; the process fails instead of creating a fake result elsewhere.

Statuses: RUNNING, PASS, FAIL, BLOCKED, INCOMPLETE, INCONCLUSIVE. A missing Git SHA
is null and BLOCKED. Infrastructure failures or interrupted partial external effects
are not passes. A killed process can leave RUNNING, honestly indicating no final
verification; investigate provider/operations before any retry. Exit codes are 0
for completed PASS, 1 for correctness FAIL, and 2 for incomplete/blocked/inconclusive.
The final stdout Markdown table contains only actual measured outcomes and is ready
to paste into slides; it includes the run ID, SHA and unmeasured labels.

- GET /v1/eval-runs?limit=20&status=PASS returns same-tenant history and cursor.
- GET /v1/eval-runs/{id} returns sanitized detailed evidence.
- Both require a real operator session; agent keys and cross-tenant IDs are denied.
- `/metrics/` is built from the user-selected Stitch source at
  `stitch_intentlock_operator_console/metrics_intentlock/`. It authenticates through
  the existing session API, fetches actual eval_runs, renders empty states and uses
  the Cryptographic Assurance Console palette. No static benchmark figures or
  sample business screens are shipped as runtime Metrics data.

Run code tests separately:

```sh
.venv/bin/python -m pytest -q
npm run build --prefix web
```

A unit-test pass does not imply that 60 live denials, 40 live refunds or the actual
bypass baseline have been performed. Real results appear only after the configured
live command is executed with actual captures and credentials.
