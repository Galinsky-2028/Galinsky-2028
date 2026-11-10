# Ratcheted protected-content integration review

10 November 2026. Source implementation and synthetic local browser/HTTP evidence only. Production intake and setup remain disabled by `loadConfig`. Migration 024 has not been applied to connected Neon. No production staff keys, private messages, provider credentials or independent audit are claimed.

The versioned `/api/protected/v2` adapter replaces the static OpenPGP prototype. The prototype is registered only with an explicit nonproduction test flag that deployment configuration cannot produce. Confidential intake is rejected before JSON parsing when closed; a separate narrow metadata allowlist permits future device bootstrap without opening submissions.

## Authority and delivery

Migration 024 stores public root/device proof histories, globally retired raw-key identities, current routing approval/quarantine and one-time public MLS packages. Account login, staff grants and administrative quarantine cannot forge root signatures. Account closure quarantines delivery without inventing a signed revocation. Identity replacement archives the previous root and withdraws its devices; it transfers no approval or verification.

Every transition checks its exact predecessor and next sequence. Identical signed event retries acknowledge without reapplying; altered event IDs or archived identities fail. Key packages are irreversibly burned when reserved, including abandoned or expired reservations. Lost publication acknowledgements may retry identical IDs/bytes without resetting their used/reserved/expired state. Fresh init keys and RFC KeyPackageRefs are checked independently of package labels.

Record creation, replies, reads and exports recheck original device generation, current signed identity state, current recipient scope and staff role/fresh passkey where applicable. Authorization and directory writes use one PostgreSQL transaction/client and a shared grant lock; waiting transactions cannot exhaust the pool and deadlock their lock holder. Exports require original-device signing proof. Holds, 90-day expiry and account closure act on ciphertext and declared routing metadata.

The browser validates signed identity histories from genesis and persistent local anchors. Independent two-party numeric comparison is required before sending or replying. Verification is stored inside the encrypted vault, invalidated on changed roots or failed chain/rollback checks, and does not revive merely because an old digest matches. Incoming signed but independently unverified reporters remain visibly unverified; reading their message does not approve a confidential reply. The client compares the claimed package roster against independently checked root-certified MLS signing keys before encryption, rather than trusting directory or package response labels.

## Local custody and failure handling

IndexedDB contains authenticated ciphertext, account/device identifiers and generation counters. Separate root, device and MLS private keys, private packages, contacts, pending drafts and thread states are inside the Argon2id vault. Opaque registered vault sessions prevent copied session objects or toggling an active flag from reviving a locked master. Cross-tab Web Locks plus IndexedDB compare-and-swap serialize updates. Missing supported locking fails closed. Lock broadcasts contain metadata only; UI hiding, inactivity, unmount and explicit locking clear displayed plaintext and the active vault session. JavaScript/OS erasure remains best effort.

Enrollment persists an encrypted pending device before public proof submission. A lost response retries the exact signed transition. Another browser creates its own private keys and shares only a public, device-signed enrollment request. The existing root device independently compares its fingerprint and signs that exact request. The new device receives no account-root private key, old thread keys or staff approval.

Message delivery persists before-state, after-state and the exact signed ciphertext frame before HTTP. Lost acknowledgements retry identical bytes. A competing reply restores the saved pre-send state, authenticates the winning frame and preserves the losing plaintext as an encrypted local draft for explicit resend. Successful acknowledgement removes the old pending epoch state. Unresolved pending epoch keys expire after 24 hours when the client is unlocked/operating; idle active UI checks each minute. A locked or offline browser cannot promise forensic timed deletion. Expiry erases usable thread state and preserves a local draft; it does not falsely assert an uncertain message was never accepted.

Attachment master keys, filenames and manifests stay inside MLS payloads. The outer frame contains authenticated encrypted chunks only. Explicit local decryption downloads an inert octet-stream `.bin` file; no inline execution/preview or remote scanner upload occurs. Ciphertext lengths and delivery metadata are observable.

## Actual verification

- Real Fastify/PostgreSQL integration: bootstrap, CSRF, fresh staff passkey, approval scope, signature/event replay, immutable message retry, one-time package burn/expiry, actual MLS report/reply, original-device export, outsider denial, saturated-pool concurrency, hold and purge.
- Real Chromium/IndexedDB/Web Locks: encrypted-only disk, private-key/passphrase/report/filename egress canaries, lost enrollment and message acknowledgements, mutual root verification, actual encrypted attachment and reply, concurrent reply reconciliation, public device linking with no inherited history, cross-tab lock and mobile React view clearing.
- Malicious delivery response: replacing the recipient package and MLS signing key without changing its pinned root is rejected before report ciphertext is produced.
- Existing core suites cover actual MLS ratchets, attachment fixtures, failed-message state preservation, identity raw-key nonreuse, vault integrity and opaque-session locking.

This review is AI-assisted, owner-authorized and source-bound, not an independent human audit or certification. The endpoint transparency/TLS deployment obligations, policy selection and remaining device lifecycle UI must still be completed before activation. G28-044 recurring future-charge enforcement and missing actual staff/mail/merchant inputs remain separate work; this change does not enable them.
