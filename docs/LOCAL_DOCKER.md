# Local Docker deployment

The local Docker workspace runs at **http://127.0.0.1:8080/**. Only the web port is
published. Gateway, executor, agent and reconciler communicate on the private
Compose network. A persistent ledger and two isolated secret volumes are
retained across restarts; agent has no mounts or privileged environment variables.

This deployment uses existing real service configuration in `.runtime/`, which is
ignored by Git and Docker build context. Never print or commit its generated
Compose file: it includes environment-injected service credentials. All generated
secret/config files are protected on the host. Stage policy is non-secret and
readable in containers; its parent `.runtime/` remains private on the host.

## Initial migration from the native local stack

Build actual images before stopping the working native services:

```sh
docker build -t intentlock-local-api .
docker build -f Dockerfile.agent -t intentlock-local-agent .
docker build -f web/Dockerfile -t intentlock-local-web .
.venv/bin/python -m tools.ops.local_stack prepare
```

`prepare` reads the actual protected `gateway-env.json`, `executor-env.json` and
`agent-env.json`; it never creates tenants, orders, tickets, captures or grants.
It requires test-mode Razorpay keys, matching policy and receipt keys, and matching
executor transport credentials. The generated agent environment has exactly its
four allowed settings; extra privileged settings in an input file are not passed.

Before copying the database, stop the native gateway/executor/agent/reconciler and
confirm that no pending operation or approved handoff is in flight. Then snapshot:

```sh
.venv/bin/python -m tools.ops.local_stack snapshot
```

This uses SQLite's consistent backup API on the actual ledger and checks integrity.
It refuses a nonexistent source database or a native source marked retired after cutover. The snapshot is not used for evaluation:
after migration, the named volume is the authoritative live database.

Initialize volumes **once**. Set `PROJECT_DIR` to the real absolute checkout path:

```sh
PROJECT_DIR="$PWD"
docker run --rm --user 0 --network none \
  --mount type=volume,src=intentlock_local_ledger,dst=/data \
  --mount type=volume,src=intentlock_local_gateway_secrets,dst=/gateway-secrets \
  --mount type=volume,src=intentlock_local_executor_secrets,dst=/executor-secrets \
  --mount "type=bind,src=$PROJECT_DIR/.runtime/docker,dst=/import,readonly" \
  --mount "type=bind,src=$PROJECT_DIR/tools/ops/initialize_volumes.py,dst=/initialize.py,readonly" \
  --entrypoint python intentlock-local-api /initialize.py

docker compose -f .runtime/docker/compose.yaml up -d --wait --wait-timeout 150
```

The short-lived initializer is the only root administrative step. It sets UID
10001 and mode 0600 for actual key files/database, then exits. Runtime services
run as their image's unprivileged users with capabilities dropped. Existing ledger
files or changed secrets cannot be overwritten. The generated volumes are marked
external, so ordinary Compose teardown does not delete them.

## Routine operation

```sh
docker compose -f .runtime/docker/compose.yaml ps
docker compose -f .runtime/docker/compose.yaml up -d --wait
# Stop services, retaining ledger and secrets:
docker compose -f .runtime/docker/compose.yaml down
```

Containers restart automatically while Docker Engine is running. Docker Desktop
must be running after a machine reboot. Do not start the retired native workers
against `.runtime/intentlock.db`; that file is now a pre-cutover source/rollback
artifact, not the live database. Run provisioning/admin tools inside the trusted
containers against `/data/intentlock.db`. Do not re-import the source snapshot over
an active volume, and do not discard the original key backups.

Public technical `/health/live` reports process liveness. `/health/ready` verifies
real database/schema access, audit-key access and the authenticated gateway to
executor readiness link. These probes cannot authorize actions, do not contact
Razorpay and do not create business records or authorization receipts. They do not
prove model quota, provider refund balance or internet availability.

The web proxy routes exactly `/v1/webhooks/razorpay` to the executor; all webhook
signatures remain mandatory. A local HTTP address is not reachable by Razorpay:
a public HTTPS ingress/tunnel and actual dashboard webhook registration are still
required for real webhook delivery. No fake webhook is sent as deployment proof.

### Temporary webhook-only HTTPS ingress

With the local stack running, start the separate demo ingress:

```sh
docker compose -f tools/ops/webhook-compose.yaml up -d
docker compose -f tools/ops/webhook-compose.yaml logs tunnel
```

Append `/v1/webhooks/razorpay` to the actual HTTPS `trycloudflare.com` address
printed in the tunnel logs. Register that URL in the Razorpay **Test Mode**
dashboard using the existing executor webhook secret from its protected secret
file. Do not use the API key secret as the webhook secret. Subscribe to
`payment.authorized`, `payment.captured`, `payment.failed`, `refund.created`,
`refund.processed`, and `refund.failed`. The executor accepts only authenticated
events for its configured account and already mapped payments.

The ingress allows only POST to the exact webhook path, rejects query strings,
limits request bodies to 128 KiB, and strips cookies and Authorization headers.
All other paths return 404; the operator console, support form and execution API
remain local. The tunnel container has no ledger, signing or provider secrets and
shares only an isolated edge network with the proxy. The proxy additionally joins
the existing trusted stack network to reach the executor. Neither container
publishes a host port. Override `INTENTLOCK_NETWORK` for a different existing
Compose network name.

This is a temporary demo URL: restarting the tunnel process can change it and
requires updating the dashboard registration. It has no production availability
guarantee. To stop just the public ingress:

```sh
docker compose -f tools/ops/webhook-compose.yaml down
```

An unsigned request rejected with `BAD_SIGNATURE` proves route/signature
enforcement only. It does not count as verified provider webhook history; that
requires an actual Razorpay delivery and a persisted `WEBHOOK_APPLIED` event.

## Live-ledger backup

```sh
.venv/bin/python -m tools.ops.local_stack backup
```

This runs SQLite online backup inside the actual gateway container, streams only
the binary backup into a new mode-0600 host file under `.runtime/backups/`, and
checks integrity. It neither prints database contents nor copies the retired
native source. Keep the existing protected encryption/signing key backups with
the ledger backup for recovery. Do not upload backups or generated Compose files
to GitHub. No recurring backup automation is created by this command.

## Evaluation readiness

`tools.eval.preflight` is a technical census of the actual ledger and running
health endpoint. It persists a **BLOCKED readiness record**, not a benchmark pass.
It issues no grants and attempts no refunds. A real full-suite capture plan, a
refundable mapped payment, another real tenant/executor and verified webhook
history must still be prepared. Supply actual `EVAL_TENANT_ID`,
`EVAL_GATEWAY_URL` and build provenance in a trusted administrative environment.
The full financial suite and unsafe bypass baseline require their own explicit
human approval and a test-account budget; readiness never implies that approval.
