# Business workspace

The main product remains in `stitch_intentlock_operator_console/operator_live/`.
The React/Vite entrypoint mounts that source. Overview, Approvals, Payments,
Customer tickets, Refund activity, Connections, Audit trail and Workspace settings
all use actual authenticated tenant data. No sample records are created.

## Google Workspace or company SSO

The gateway implements the OpenID Connect authorization-code flow with S256 PKCE,
a browser-bound, single-use 10-minute state, a nonce, pinned RS256 ID-token
verification, issuer/audience/expiry/authorized-party validation and verified
email. Only explicitly invited active operators with owned active signing keys
can sign in. A verified email domain does not enroll a business. The provider's
subject is pinned at first successful login; a different subject cannot take over
an existing invitation. There is no public signup, password collection or automatic
signing-key generation on login. An authenticated session cannot replace explicit
refund approval.

Configure these **gateway-only** values from a real Google OAuth or company OIDC
application, using environment variables or a protected secret file:

- `OIDC_ISSUER`: the exact HTTPS issuer (Google: `https://accounts.google.com`).
- `OIDC_CLIENT_ID`: the real client identifier.
- `OIDC_CLIENT_SECRET` **or** `OIDC_CLIENT_SECRET_FILE` (mode 0600/0400).
- `OIDC_DISPLAY_NAME`: your identity provider's user-facing label.

Register the exact `APP_ORIGIN` + `/v1/auth/callback` in the identity provider.
For the current loopback deployment this is
`http://127.0.0.1:8080/v1/auth/callback`. Register Google users as test users if
the real OAuth application's consent configuration requires it. Production must
use HTTPS. The login button remains visibly unavailable without configuration.

Invite actual existing operators through trusted administration:

```sh
python -m app.auth.sso_cli --email "$OPERATOR_EMAIL" \
  --operator-id "$OPERATOR_ID" --kid "$OPERATOR_KID" --issuer "$OIDC_ISSUER"
```

The invitation references existing tenant/user/signing-key rows. A new business
still requires administrator provisioning of its tenant policy, signing identity,
agent scope and dedicated executor. Requests cannot choose or create a tenant.
Revoking `sso_identities.active` blocks new SSO logins; revoke existing
`operator_sessions` as well for immediate session termination.

For generated local Docker configuration, add actual OIDC values to the protected
`gateway-env.json`, run `tools.ops.local_stack prepare`, and copy the staged
`oidc-client-secret` into the existing gateway secret volume as UID 10001/mode
0600 using trusted administration. Recreate only the gateway. Do not rerun ledger
initialization or replace the live database. Agent and executor do not receive
OIDC credentials. Keep access logs disabled on any external reverse proxy in front
of the callback; authorization codes must not be retained in log URLs.

## Razorpay connection plugin

Connections reports the real configured merchant account from the authenticated
executor RPC. `CONFIGURED` describes deployed configuration, not an assertion of
API availability, balance, successful OAuth, or webhook delivery. The separate
signed webhook count comes from actual verified event rows. No API key, grant,
SSO token or provider secret is returned by these workspace endpoints.

The setup button persists an idempotent, CSRF-protected setup request for the
session's tenant. It does **not** activate or switch a merchant account. API keys
remain environment/secret-file configuration in a dedicated test-mode executor.
The current deployment supports its explicitly configured Razorpay merchant;
self-service onboarding of arbitrary merchants is not enabled.

For one-click merchant attachment, IntentLock needs a real Razorpay Partner OAuth
application and per-business executor routing/secret provisioning. Those Partner
credentials were not supplied. No simulated authorization screen or connected
state stands in for them. Additional provider plugins must implement the trusted
payment/refund boundary, tenant routing and reconciliation before being offered
as active connections. The agent never selects credentials or a merchant.

## Customer workflow

Use Payments to find the exact provider payment and order. Each row links directly
to its Razorpay dashboard transaction and, when the workspace has exactly one
active support channel, a support form bound to that order. Multiple channels
require explicit selection; the UI does not guess. Cached balances are labeled as
such. Approval always reads live provider state again. Provider refunds show their
actual references and dashboard links in Refund activity.

Workspace list limits are explicit: latest 50 workflow records and up to 100 mapped
payments. Overview metrics summarize those bounded lists, not all-time totals.

## First-time Google OAuth setup

1. Open Google Cloud Console and create or select your actual project.
2. Open Google Auth Platform. Configure Branding with the real application name,
   support email and developer contact. Choose your Audience. For an external app
   in Testing, add each actual operator's Google account as a test user.
3. In Clients, create a **Web application** OAuth client. Add exactly
   `http://127.0.0.1:8080/v1/auth/callback` to Authorized redirect URIs for this
   local development instance. This server flow does not need a browser SDK or
   additional Google API scopes; it requests only `openid email profile`.
4. Download the actual client configuration privately. Save the client secret in
   a protected file outside the repository's tracked files, mode 0600. Do not
   paste it into chat, browser storage, or `.env.example`.
5. Configure gateway issuer `https://accounts.google.com`, the actual client ID,
   the protected secret path and display name `Google Workspace`.
6. Invite the actual operator email using the SSO CLI above and its existing
   operator ID/signing kid. Configure/restart the gateway, then use Continue with
   Google Workspace in a regular supported browser such as Safari or Chrome.
   Google's policies may reject sign-in inside embedded browser views.
7. Verify the authenticated business name, then review a payment. SSO does not
   issue a refund grant; the exact refund still needs the operator's approval.

Google reference: https://developers.google.com/identity/openid-connect/openid-connect
and https://developers.google.com/identity/protocols/oauth2/web-server.
Production requires its own HTTPS callback and production consent configuration;
do not reuse a temporary webhook tunnel as the business SSO origin.

## Recovering a stale proposal

If a later refund or provider update advances the payment's version, an older
proposal cannot be approved. The Approvals page marks known version mismatches
and offers **Refresh proposal**. This authenticated, CSRF-protected action
re-fetches live payment state, checks policy, and creates a new unapproved proposal
with only `resource_version` updated. The original action and digest remain
immutable, its status becomes `SUPERSEDED`, and both the stale denial and new
proposal are receipted in the same transaction. Concurrent refreshes create at
most one replacement. Refresh cannot modify amount, destination, payment, actor,
tenant or tool, cannot refresh approved proposals, and never issues a grant.
The replacement requires a new live preview and explicit human approval.
