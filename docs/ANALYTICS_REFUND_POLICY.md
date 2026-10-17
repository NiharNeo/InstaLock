# Analytics and business refund policies

Analytics and Refund policy are part of the existing Stitch business workspace.
No mock trends, business records or model-generated policy decisions are used.

## Business rules

An authenticated operator can publish structured rules at `/v1/refund-policy`
(GET and CSRF-protected PUT):

- A refund window in whole days, 1–3650, starting at **Razorpay payment creation**
  time. A 10-day policy allows `now < created_at + 10*86400`. At the exact cutoff
  or later, the gateway denies `REFUND_WINDOW_EXPIRED`. A missing/future trusted
  date denies `PAYMENT_DATE_UNAVAILABLE`. This is elapsed time, not calendar days
  or delivery date. It applies to the whole payment, not individual product units.
- A cumulative maximum refund amount. UI input is INR converted through exact
  decimal-string/BigInt arithmetic to integer paise; API values must be integers.
  The base YAML deployment ceiling cannot be exceeded or relaxed by business rules.
- Partial refunds allowed, or only the entire remaining refundable balance allowed.
  Partial attempts under the latter rule deny `PARTIAL_REFUND_NOT_ALLOWED`.

An unset field adds no extra restriction; immutable deployment safety policy,
strict original-payment destination, balance checks, tenant scope, reservation,
resource versions and human grant requirements still apply. No example 10-day
policy is activated automatically. Product category/condition exceptions and
shipping/delivery windows require item-level authorization and trusted fulfillment facts.
The connected store now supplies real catalog/category sales; this does not yet
add product-specific refund restrictions to the payment-level authorization contract.
Free-form customer text cannot supply those facts or change the rules.

Each publish writes an immutable revision and content hash, atomically moves the
business head and appends a signed receipt. The effective policy hash includes
both base YAML version and exact business revision. Concurrent/stale editors deny
`POLICY_EDIT_CONFLICT`; changes during unresolved PENDING operations deny
`POLICY_OPERATIONS_PENDING`. Tenant user-row locks fence policy publication against
approval and executor reservation. The prior revision remains in history.

Proposal, preview, grant receipts, approval and isolated executor reservation/dispatch
all check current policy. Old approved proposals/grants fail `POLICY_CHANGED`.
Pending proposals can be refreshed under the new revision, but require a new live
review and human approval. Crossing a deadline after approval still denies at
execution. Reconciliation checks actual provider outcomes first and never treats a
new policy as permission to repeat an already dispatched refund.

The gateway gives the isolated agent the actual structured rules, policy version,
trusted provider payment timestamp and current server time, separately from masked
customer text. The prompt tells Gemini to follow them. The model's agreement is
not an authorization decision: gateway/executor checks enforce them independently.

## Actual analytics

`GET /v1/analytics?days=7|30|90` is operator-authenticated and tenant-scoped. It
returns daily activity and refund volume, completed/failed/pending operation counts,
financial authorization denial reasons/rule IDs, actual model outcomes, recorded
token totals, p95 model latency, dated tickets and current mapped-payment balances.
Days are calendar bins in Asia/Kolkata; the current day is partial. Refund trends
are attributed to operation creation time and include only currently DONE operations.
Model p95 uses nearest-rank recorded call latency, not gateway overhead.

Charts have tooltips and exact daily tables. Missing observations are not projected.
Console polling receipts are excluded from financial decision charts. Decision
counts include repeated stages/attempts and are not counts of unique refund requests
or attacks. Mapped payment balances are all-time cached provider observations, not
merchant-wide revenue. They can include refunds performed outside IntentLock.

The query aggregates all applicable rows, not the console's latest-50 lists. It
fails `ANALYTICS_RANGE_TOO_LARGE` above 100,000 source rows per category, instead
of silently truncating. Unsafe aggregated money totals also deny. Monetary API
values remain integer paise, including after aggregation.

New support tickets receive a real server submission timestamp. Existing unknown
submission dates remain NULL and are reported as missing coverage. Provider payment
creation dates are learned only from actual Razorpay responses. A trusted metadata
sync can fill existing mapped resources; historical dates are never guessed.

## Run and validate

```sh
.venv/bin/pytest -q
cd web && npm run build
```

Deploy migration `0011` before recreating API/executor workers, retain the existing
ledger/secret volumes, rebuild the isolated agent to use its new policy prompt,
and refresh real payment metadata through the trusted executor. Back up the live
ledger first. Do not publish an example policy or execute a refund as a deployment
probe. Use the existing operator/SSO session to review and publish actual rules.
