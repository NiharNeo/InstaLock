# Connected demonstration store

The existing Stitch source now includes `operator_live/Storefront.tsx`. The store
is `/store/<existing-support-channel>`; catalog data is never embedded in UI code.
The operator's **Store catalog** page creates products and displays category sales.
The store is a test-mode demonstration and does not promise physical fulfillment.

## Payment and refund journey

1. Add an operator-authored catalog product to the bag. The browser sends only
   product IDs, quantities and a checkout idempotency key. Price/category/name
   snapshots come from the current tenant's database catalog.
2. The credential-isolated executor creates an actual Razorpay Test Mode order.
   An ambiguous order-creation response is not retried. A reserved checkout remains
   pending for investigation; a new checkout requires a new customer action.
3. The customer completes Razorpay Standard Checkout themselves. The returned
   HMAC signature uses the **stored provider order ID** and payment ID. A real
   provider GET must confirm captured status, exact amount, INR and order binding.
   Only then are Order/Payment/Resource records created in the existing ledger.
4. A captured-payment webhook can recover the same mapping. **Check payment
   status** also queries actual provider order payments, so an interrupted browser
   callback does not fabricate success or require another charge.
5. **My orders & support → Ask for a refund** binds the ticket to the captured
   order and the purchased product. Amount must fit both that line's paid value
   and the order's current remaining balance. The raw ticket is redacted through
   existing intake. Purchased category/price and requested amount are supplied
   separately to Gemini as structured context; user prose cannot change them.
6. The agent proposes; the operator previews the real payment and exact amount,
   approves once, and the existing grant/policy/executor pipeline refunds the
   original payment method. Existing receipt and analytics pages observe it.

Store support does not create grants or provider refunds. Current authorization
remains **payment-level**, not line-item refund accounting: category sales show
purchased gross line totals, and partial payment refunds are not allocated across
categories by guesswork. Product-specific refund policies still require a further
versioned item-level authorization contract. No stock/shipping/fulfillment system
is claimed. Unpaid baskets create no sales. Historical provider payments without
catalog lines stay outside category sales. Paid snapshots survive catalog changes.

## Privacy and safety

Anonymous purchase history uses a cryptographically generated HttpOnly SameSite
browser cookie; the database stores only its hash. Clearing cookies loses access
to that browser's purchases. No email/order-ID lookup exposes another shopper's
orders. Customer support remains available through the existing business channel.
Mutations enforce exact allowed origins and JSON body bounds. Public commerce
has no route to operator approval or executor credentials. Shared database rate
limits conservatively aggregate gateway peers behind a reverse proxy; the demo
is not a high-volume multi-customer deployment. Additional per-client edge rate
limits are required before a larger public launch.

## Run and test

```sh
.venv/bin/pytest -q
(cd web && npm run build)
docker build -t intentlock-local-api:latest .
docker build -f web/Dockerfile -t intentlock-local-web:latest .
docker build -f Dockerfile.agent -t intentlock-local-agent:latest .
.venv/bin/python -m tools.ops.local_stack backup
docker compose -f .runtime/docker/compose.yaml up -d --wait --wait-timeout 120
```

Migration 0012 is additive. Keep the existing ledger and both secret volumes.
Explicit catalog creation uses the operator UI, or `python -m
app.commerce.catalog_cli --operator <existing-operator> --name ... --category ...
--description ... --price-paise <integer>` inside the trusted gateway. This is an
administrative authoring command, not a startup seeder.

## Temporary public prototype

`tools/ops/storefront-compose.yaml` exposes the store and authenticated operator
workspace through Cloudflare. `/internal`, dotfiles and runtime paths remain
blocked at ingress. `/v1` reaches the gateway and retains tenant/session/service
authentication, CSRF and signed-grant checks. The public root is the operator
workspace; `/store/<channel>` is the customer store. Set STORE_CHANNEL to a real existing database channel. Start the
tunnel, inspect its assigned HTTPS origin, then save that **exact** origin as
STORE_PUBLIC_ORIGIN in protected gateway config; run local_stack prepare and
recreate gateway. Never use wildcard origins or expose ports 8000/8001.

The temporary URL is not permanent hosting: it requires this computer, Docker,
tunnel and agent credentials to remain online and can change on restart. The
link permits public catalog/test purchases and the operator sign-in page. The
ledger and operator APIs remain authenticated. Set DEPLOYMENT_ORIGIN and
STORE_PUBLIC_ORIGIN to this exact HTTPS origin, and PUBLIC_STORE_CHANNEL to the
existing active database channel. Update Google OAuth origins/callback allowlists
without deleting the local entries. The old local operator UI forwards to the
canonical public workspace, so secure cookies and CSRF use one origin.
Do not submit this as an always-on deployment without stating that limitation.

## Permanent deployment recommendation

Use a Docker-capable VM, such as a DigitalOcean Droplet, with persistent disk,
2 GB RAM or more as an initial sizing assumption. This preserves the isolated
services and single shared SQLite ledger without forcing separate ephemeral
filesystem services. The account, billing approval and server SSH access must be
provided by the owner; no hosting purchase is made automatically.

1. Create the VM with an SSH key and point a domain's DNS to it. Permit 80/443 and
   restrict SSH. Install Docker/Compose from official sources.
2. Transfer source and protected runtime configuration over SSH, outside Git and
   image build contexts. Restore the **live ledger backup** and its existing
   signing/encryption keys into named volumes using the documented local Docker
   backup/cutover procedure. Do not restore the retired native database. Use one
   writer deployment; do not run two live stacks against divergent ledgers.
3. Update protected gateway configuration `DEPLOYMENT_ORIGIN=https://<domain>`
   and `STORE_PUBLIC_ORIGIN=https://<domain>`. Run local_stack prepare on that
   server so paths refer to its files. Maintain secret-file 0600 ownership and
   operator/agent scope; renew expired machine credentials administratively.
4. Build the three images and start the protected Compose stack. Then run:

   ```sh
   PUBLIC_HOST=<domain> docker compose -f tools/ops/public-compose.yaml up -d
   ```

   Caddy terminates HTTPS and forwards only to web. Gateway/executor remain
   unpublished. Persist Caddy certificate volumes and ledger backups.
5. Add `https://<domain>` and `https://<domain>/v1/auth/callback` to the existing
   Google OAuth web application. Keep invite-only identities; do not open operator
   signup to reviewers. Set Razorpay webhook URL to
   `https://<domain>/v1/webhooks/razorpay` with its existing protected signing secret.
6. Verify migration head, all container readiness, signed receipt chain, a real
   Razorpay test payment, matching operator-approved refund, provider dashboard,
   webhook delivery, category totals, cross-shopper isolation and denied private
   endpoints. Confirm credentials remain valid through the planned demonstration.
7. Share `https://<domain>/store/<channel>` with reviewers. Operator workspace is
   `https://<domain>/`, authenticated and invite-only. Provide a recording or
   operator-led walkthrough for approval; never give reviewers signing keys.

Official references:
- https://razorpay.com/docs/payments/payment-gateway/web-integration/standard/
- https://docs.digitalocean.com/products/droplets/how-to/create/
- https://caddyserver.com/docs/automatic-https

## Requests that do not reach approval

The dashboard shows **Incoming customer requests** before the model has produced
an approval proposal. Customer tickets are ordered by actual submission time;
model failure, retry wait and uncertain submission are distinct from completion.
For Gemini 3.8 Flash the agent requests low thinking and allows 4096 total output
tokens. The old 1024-token cap could be consumed by internal thinking and return
MAX_TOKENS with no usable tool call. Truncated or invalid calls still deny.

Model transport/provider errors receive at most three automatic attempts, with
30/60-second backoff, a fresh lease and a separate recorded call/deny receipt for
each attempt. Invalid proposals are dropped, not auto-approved. A lost proposal
submission response is SUBMISSION_UNCERTAIN / REVIEW_REQUIRED and is never
resubmitted automatically because the first proposal may have committed.

An operator can retry an exhausted or historical model failure from Customer
tickets. `/v1/tickets/<id>/retry` requires operator authentication, tenant scope,
CSRF and an empty body. Any existing proposal for the payment's order blocks this
conservative manual recovery. Retrying only requeues model work: it does not
issue a grant, approve a proposal or call Razorpay refunds. Previous failed model
calls and their signed receipts remain in history.

During the October 17 demo recovery, Gemini 3.8 returned live HTTP 503 high-demand
errors. The protected agent configuration was switched to the verified available
`gemini-3.5-flash-lite`, with its documented minimal thinking level. This is an
explicit deployment configuration change, not an automatic authorization fallback.
The model transport timeout is bounded at 90 seconds (10-second connect), within
the 300-second ticket lease. Strict validation and approval requirements remain.

The store header/footer link to the canonical operator URL. The signed-in operator
header and Store catalog page link back to the actual database channel’s store.
The public login page also exposes the deliberately published storefront link.
Changing the ephemeral tunnel hostname requires updating deployment origins and
Google OAuth entries again. Do not restart the tunnel unnecessarily.
