# Card contribution controls — 10 November 2026

This is a source-bound AI review of a TEST-only backend increment, under the owner's review policy. It does not approve fundraising, claim completed recurring donor service, or record an actual processor transaction.

The former automatic live Checkout entry is unconditionally unavailable, including when every former environment approval and evidence JSON is supplied. TEST Checkout remains available for the existing isolated sandbox journeys. The native Stripe subscription API cannot supply the campaign's required checks before every future collection, so this implementation does not create subscriptions or guess unsupported `subscription_data.pause_collection` fields.

## Implemented boundary

`025_card_mandates.sql` records prospective consent, immutable documented contributor approvals, due installment reservations, append-only policy/revision/audit records and durable provider commands. Hosted setup saves a card and collects billing/reporting information; it collects no contribution. A signed callback, fresh private processor lookup, actual credit funding/no wallet, approved issuer source rules and explicit current staff source review precede a mandate. Financial billing identity is intentionally processed and sealed with the dedicated treasury key; no E2EE claim applies.

The exact documented contributor revision is a treasury ID. Email/name matching never automatically merges contributors. The current treasury policy must approve the actual card source and environment, election limits, accounting rules and expiry; a separate documentary card policy binds its exact version and supplies election cutoffs, terms, maximum schedules/installments, issuer countries and reservation bounds. No committee facts or legal limits are inferred.

Calendar installments preserve the original monthly anchor through short months. Early, expired or missed monthly periods are not caught up. Under the existing global finance-journal lock, each authorization and capture checks current contributor revision, mandate status/version, terms/policies, open treasury casework, posted allocations across all channels and every active card reservation. Arithmetic uses exact integers. Other cash posting and cancellation cannot overtake the bounded processor dispatch while that lock is held.

A command and one-time dispatch claim commit before financial I/O. A processing claim is not a retry lease. Timeouts, crashes and malformed/mismatched responses keep the attempt unresolved and retain its reservation; no automatic replacement PI, charge or subscription is created. Current owner/treasurer role, actual ordinary session and fresh staff passkey are reloaded using the transaction's own database client. This avoids authorization by a stale MFA stamp or connection-pool deadlock.

The first installment uses a standalone `capture_method=manual` PaymentIntent with `confirm=false`; later monthly installments may use explicit off-session confirmation. The donor's bank confirmation cannot capture funds. Every authorization/capture re-reads the actual saved credit method. Capture is a separate exact-amount `final_capture=true` operation. Inspection and confirmed void are available after dispatch expiry. Donor bank client secrets leave the provider adapter only through the explicit confirmation accessor; ordinary command output, audit and persistent records exclude them.

Authenticated callbacks are minimized and bound to the original period, authorization command, customer/method, amount, environment, policy/mandate digests and confirmation mode. They cannot create a contributor, mandate or authorization. A second terminal capture event is acknowledged without another journalable capture. Signed capture retains reserved room until the existing treasury journal atomically matches the exact event, contributor revision, amount and election; a mere successful HTTP response does not release it. Late nonterminal callbacks cannot roll back captured/journaled state.

Staff POST APIs provide bounded cursor pages, explicit billing review, policies, approvals, period reservations, one-time TEST dispatch/reconciliation and future-schedule cancellation. Exact body schemas, current session/role/passkey, origin, CSRF and no-store responses apply. No live executor is installed. Actual deployed volunteer-only credentials have no new financial privileges.

## Provider contract reviewed

Stripe's official OpenAPI repository was inspected at immutable commit `f1ec696a9d04d25caaa7b1af4be6e6fecd5f5c85`, `openapi/spec3.json`, SHA-256 `7cff4cc46d0654101a36a3302f7544640f5f73e4f3cad6f264f0e23c19fa1776`. The adapter pins API version `2026-09-30.endive`. Reviewed contracts include Checkout setup/customer creation, expanded SetupIntent/payment method, manual PaymentIntent creation, capture `amount_to_capture`/`final_capture`, cancellation and current payment-method retrieval. SetupIntent usage is checked on retrieval; unsupported Checkout `setup_intent_data.usage` is not sent. USD bounds are 50 through 99,999,999 integer cents.

## Verification and remaining implementation

Unit tests exercise calendar/aggregate/expiry rules, test/live isolation, fixed endpoints, bounded response parsing, metadata/method binding, manual versus automatic capture, first-bank-confirmation separation, lost responses, no retries and secret minimization. The real isolated PostgreSQL/HTTP test runs all migrations and current staff authentication. Six concurrent mandates compete for the same remaining allowance; exactly one reserves it. Later cash posting blocks capture. Cancellation blocks collection. A lost authorization and a lost capture cannot be dispatched twice. Signed callbacks reject mismatches/replays and preserve private canaries; an exact signed journal posting releases the held reservation atomically. Ordinary sessions, missing CSRF, foreign origins and revoked staff sessions fail closed.

This increment does **not** install the prospective public setup form, donor-only recovery/cancellation/payment-method UI, bank-confirmation page, controlled refund adaptation for monthly PI references, staff review UI or an operational due-period worker. Those are real remaining software for G28-044. The former receipt/Stripe-portal implementation remains useful for existing TEST Checkout records. New monthly commitments remain disabled until the complete supported donor path and all command/remedy integration pass end-to-end tests. Actual staff mail, approved treasury/merchant evidence and credentials remain separate activation inputs; no email or financial transaction was performed in this review.

## Monthly donor service — 15 November 2026 addendum

PRs #165 and #166 add the remaining G28-044 software, still **TEST only**. The donor pages appear only when **all** of the following are set: private preview mode, Stripe TEST settings, `G28_TREASURY_SANDBOX_ACTIONS_ENABLED=true`, `G28_RECURRING_TEST_ENABLED=true`, and a database on the website service. No deployed service sets them today.

- **Prospective setup (`/donate/monthly`):**
  - The page shows the published installment maximum, the general-election cutoff, the five eligibility statements already used for one-time gifts, and the terms version from the current card policy.
  - Each browser form maps to one deterministic enrollment, so a replayed submission never creates a second commitment.
  - Card entry happens only on Stripe's hosted setup page, reached through an explicit link. No campaign page loads a script.
- **Recovery:** each setup shows a 120-bit recovery code once. Only its SHA-256 digest is stored. The donor can recover the schedule from any device without a volunteer account. A replay never shows or binds a new code.
- **Donor self-service (`/donate/monthly/manage`):** uses an HttpOnly, signed browser link plus a CSRF token.
  - The page shows the schedule, the next possible gift date and each month's state, never billing identity or processor identifiers.
  - **Cancellation** is idempotent and stops all future authorizations and captures. Unsent reservations are released. An attempt already at the processor stays reserved until treasury reconciles it exactly.
  - **Card change** starts a replacement setup bound to the existing schedule. After signed and staff-verified review, `POST /api/staff/finance/card/mandates/:id/replace-method` replaces the saved card. It cannot widen the amount, frequency, election, cutoff or count, and it needs documentary evidence. A replacement setup cannot start a second schedule.
- **Bank confirmation:** only the staff-prepared on-session first installment can be confirmed. The server confirms that exact intent with a return URL and accepts only a `stripe.com` bank page. Confirmation can at most authorize. A donor return can never record collected funds, and capture remains a separate staff step with fresh checks.
- **Monthly remedies:**
  - treasury refunds of a captured installment re-verify the exact TEST intent, period metadata and captured amount before calling the processor;
  - signed refund and dispute events are matched to the installment;
  - an over-refund is rejected.
- **Due-period processing** (`processDue`, a 15-minute loop only where TEST card actions and a database exist):
  - marks installments due or missed; a missed month is never caught up;
  - releases expired reservations that were never sent;
  - completes finished schedules;
  - shows staff a due queue (`POST /api/staff/finance/card/due`).

  It never contacts the processor. Every authorization and capture still needs owner or treasurer authority and a fresh passkey.

Still external to software:
- the campaign-approved text of the **monthly contribution terms** (the card policy's `termsVersion` names it; the site does not invent it);
- the treasurer's card policy;
- a staff identity with a passkey;
- `STRIPE_SECRET_KEY` (TEST) with `DATABASE_URL` on the website service;
- the TEST flags above;
- migration 026 on the target database.

Live processing remains unavailable.
