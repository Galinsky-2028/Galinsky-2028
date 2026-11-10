# Deployment and operator runbook

**Current placement:** the owner authorized connected-account migration on 9 November 2026. Use [the current resources and handoff](CONNECTED_WORKSPACE_20261109.md). Exact-project IDs and creation instructions below describe the superseded account; do not provision there.

## Resource placement

The user's designated Render project is `prj-db57fnm7bikc739783q0`; the assigned Neon project is `soft-bread-25523698`. These are identifiers, not passwords. The Render create-service connector accepts only a workspace and cannot assign an environment, so do not use it for this campaign. Instead use the official Render REST API through the reviewed manual GitHub Actions workflow in `docs/operations/RENDER_EXACT_PROJECT.md`. It verifies the exact project ID and the environment's matching projectId before any create request and supplies the password secret atomically. A Render project belongs to a workspace, but the service must be created in the actual project's environment, never left unassigned in workspace root. Both approved preview services have already been deployed in the designated project; verify their current live state before creating new services. Never substitute another project's database.

## Public preview

**Private password is mandatory before deployment.** First follow the verified-project REST workflow in `docs/operations/RENDER_EXACT_PROJECT.md` (requires owner-provided GitHub Actions secrets; don't use the workspace-only integration). Deploy the public preview only as a Node Web Service using `render.yaml`, never as a static site/CDN: build `npm ci && npm run build:web`, start `npm run preview:serve`, and set a 24+ character `PREVIEW_ACCESS_PASSWORD` Render secret (32+ random characters recommended). Without the secret the server refuses to start. Keep auto-deploy off and preview noindex. Render must be configured inside the owner-designated project, not Phillip's workspace. See `docs/operations/PRIVATE_PASSWORD_PREVIEW.md` for exact steps and HTTP tests. Confirm all eight routes, 404, assets, three issue video panels, mobile navigation, reduced motion and donation disclosures only AFTER entering the password. A successful build is not a successful deployed HTTP check.

## Portal/API

Create a separately authorized Node service with build `npm ci && npm run build:portal`, start `npm start`. Set `NODE_ENV=production`, assigned staging-branch `DATABASE_URL`, exact HTTPS `PUBLIC_ORIGIN` and `PORTAL_ORIGIN`, and the mandatory `PREVIEW_ACCESS_PASSWORD` on this service too. The password protects all portal/API endpoints including `/healthz` and `/readyz`; do not configure an unauthenticated HTTP health probe expecting 200. Keep all release flags false initially. Use separate staging and production secrets; never paste them into GitHub source or a public issue.

Run `npm run db:migrate` as an explicit deployment step using the assigned database. Migrations acquire a lock and use transactions. Preview/test databases must be separate branches or local instances. Restore an actual backup before claiming recoverability.

## Verified-email activation

Review terms/privacy/consent and sender setup. Configure `MAIL_PROVIDER=resend`, a verified `MAIL_FROM`, `RESEND_API_KEY`, random 32-byte base64 `DELIVERY_KEY` and high-entropy `LOGIN_PEPPER`. Choose and test exactly one delivery mode:
- `MAIL_DELIVERY_MODE=inline`: runs a real PostgreSQL-leased Resend outbox consumer *inside the existing volunteer portal instance* when signup is enabled. There is no third paid worker required; leases and Resend's stable idempotency key handle restart/retry. The portal checks real database readiness before starting the loop, and SIGTERM stops it cleanly. A free Render web service may sleep: **do not claim guaranteed round-the-clock prompt delivery without an observed delivery test, uptime monitoring, and an appropriate service plan.**
- `MAIL_DELIVERY_MODE=external`: start and verify a separately provisioned real queue worker using `npm run worker` and operational logs, retry test and test sender, with its own lifecyle/alerts.

Both modes require `MAIL_WORKER_OPERATIONAL_APPROVED=true` **only after** the operator verifies that the real worker is configured to run, tests sender domain DNS and delivery to a real permitted mailbox, observes claim/finish and idempotent retry, and confirms terms/privacy approval. This is NOT a bypass flag: do not set it to make tests pass. Without both a tested mode and operational acceptance, production startup rejects `SIGNUP_ENABLED=true`.

Only then enable `SIGNUP_ENABLED=true` on the real portal and update the public portal origin. Request a real test link, verify it in the initiating browser, test expiration/replay and check actual deliveries and unsubscribe preferences. Do not claim this happened from the synthetic transport tests.

## Materials

Reconcile source texts from the original user-supplied volunteer archive. Record actual author/reviewer identities and revision-specific approval. Add approved volunteer-facing records to `content/materials/current.json`; run `npm run materials:publish`. Search, read and download them with a newly verified volunteer account. Two authorized humans must sign each exact published revision with independently held Ed25519 private keys. Add their public verification keys through reviewed source changes. Verify via `npm run materials:verify` before `npm run materials:publish`. Unreviewed or unsigned historical files remain blocked. See `docs/operations/STAFF_PUBLICATION.md`. Full online multi-factor staff administration remains a separate release gate.

## Videos and issue links

Edit each issue in `content/public/site.json`. A YouTube URL or 11-character ID is validated; no unrelated placeholder ID is allowed. Set the reviewed transcript and real canonical issue website URLs. Rebuild, check captions and verify no third-party request before activation. The Kirk-Evers bill needs its actual approved source file and accessible publication workflow before linking a download.

## Feature release

Staff identity now has a maintained WebAuthn implementation: follow `STAFF_PASSKEYS.md`, apply migration 016, verify the deployed owner journey, then enable `STAFF_IDENTITY_ENABLED` on the existing portal. `DONATIONS_ENABLED` and `PROTECTED_CONTENT_ENABLED` remain independently gated until their adapters and release prerequisites are satisfied. A flag never replaces a working implementation.

## Recovery and incident behavior

Rotate compromised session/identity delivery credentials using a documented migration; changing the lookup pepper or delivery key without migration can make historical records unusable. Pause signup if email delivery or its worker fails. Preserve minimal diagnostic codes, not personal data. Revoke account sessions through the account lifecycle; sensitive future records require their own key-aware recovery policy. Roll back the public deployment independently of the account database. Record schema compatibility before rolling back the API.
