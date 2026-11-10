> 10 November 2026 source update: protected recipient/device reporting, encrypted attachments/replies, local recovery, exact encrypted export and legal-hold-aware retention are now implemented. See [the reviewed application profile](PROTECTED_PROFILE.md). Hosted activation still requires real staff identity and named recipients; the historical implementation observations below are superseded for these flows.

# Security and privacy boundaries

## Standard basis

The referenced upstream repository is `neophilism/End-To-End-Everywhere-Security-Architecture-Standard`. The inspected source head was `6ec85d51f9207da31f0e90fd8a7c82ffff8448f6`, development toward 0.9.0-rc.2 after Audit v2. This is an inspected source reference, not an approved production profile or certification. Recheck the corrected component/data-flow contracts and review gates before implementing protected-content adapters.

## Data flows

| Flow | Actual boundary | Claim and limitations |
|---|---|---|
| Campaign pages, images and bill when published | Public static origin | Intentionally public; no private E2EE claim. |
| Video activation | Visitor intentionally opens YouTube privacy-enhanced player | External provider sees the connection; no iframe or remote thumbnail before activation. |
| Volunteer sign-in email | Browser to account service to configured Resend recipient | Declared account-delivery processing. Email stored as server-encrypted delivery metadata plus keyed lookup; the service can decrypt it. This is NOT E2EE. |
| Login token and browser binding | High-entropy one-use link plus initiating browser HttpOnly cookie | Hashed tokens, 15-minute expiry, explicit POST, atomic consumption. Browser binding means a link opened on another device must be requested again there. |
| Account session and consent | Host-only HttpOnly cookie; state writes require exact origin and CSRF token | Server-authorized access. Session metadata remains service-readable. |
| Current volunteer materials | Authenticated API checks published state, audience and exact reviewed revision | Controlled distribution, not secrecy from the authorized account service. No archive bundled into public JavaScript. |
| Planning worksheets | In-memory browser state; explicit user download/print | No campaign submission or persistence. The user controls downloaded copies; instructions prohibit private supporter/evidence data. |
| Sensitive reports, notes and recipient-encrypted records | Not released | Server rejects before body parsing. A ciphertext table is not an E2EE implementation. |
| Staff actions | Not released | Volunteer identity never becomes staff authority. No static bearer admin key or fake browser role. |
| Contributions | Not released | No card field, processor request, receipt or paid-state claim. Supplied disclosure text is preserved. |

## Threats and operational requirements

Enforce separate public and account origins. Account UI loads only its own scripts; payment and video scripts are not trusted to handle volunteer records. Production startup rejects missing DB, signup delivery configuration and attempts to enable unavailable adapters. Exact recipient origins are configured, not constructed from forwarded Host headers.

The current app does not trust proxy headers. Before production, prove the exact authorized reverse-proxy IP/CIDR configuration and shared edge rate policy; do not enable a blanket or hop-count trust setting. The conservative local IP bucket can otherwise throttle multiple real clients behind a proxy. Record that deployment decision and test direct-origin spoofing.

No request bodies, cookies, emails, verification URLs, encryption keys or protected payloads are logged. Jobs store encrypted account-delivery envelopes. Terminal job results clear envelopes; closure deletes queued delivery records and all sessions. A delivery already handed to the provider cannot be recalled, and provider retention must be disclosed and configured.

Static source delivered to a browser remains part of the browser trust boundary. CSP reduces common injection risks but does not prove safety against a malicious source publisher, compromised browser or authorized recipient. Identity recovery, device replacement, key changes, export authorization and independently reviewed protocol choices are still future implementation gates.

Before launch: dependency audit, authenticated/unauthenticated route matrix, origin/CSRF/token replay/expiry tests, actual proxy and delivery tests, least-privilege DB credentials, secret rotation and backup/restore rehearsal, privacy notices matching actual provider behavior, independent accessibility/security review.
