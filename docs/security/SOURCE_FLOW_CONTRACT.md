# Source-bound security and privacy contract

Assessment date: 1 November 2026. Source basis:
`4be888089106a0e36acc238ae7d1d8713059a2a6` in Galinsky-2028.
`security/source-flow-contract.json` is the machine-readable companion to this
review. It supplements the older discovery inventory; it does not replace the
upstream component-inventory schema 0.2 or issue certification.

The selected E2EESA **1.0.0 engineering standard** is
`Galinsky-Labs/End-To-End-Everywhere-Security-Architecture-Standard` at exact commit
`b137a3d1cb54900204ff13c7694ed00a50c00141`. The upstream immutable manifest digest, selected profile refs and
product source constants are machine-checked in `security/e2eesa-release-lock.json`
and `security/verify-e2eesa-release.mjs`. The source-flow contract's old
`sourceCommit` remains historical mapping provenance; its current source blob
hashes are still checked in CI. Migrating this reference does not change the
protected feature flag or create a production conformance assertion.

## Scope and integrity

The contract enumerates 168 checked-in executable/source files under apps,
packages and scripts, plus migration SQL. Every path has its exact Git blob
identity and a component owner. It maps 46 declared database tables and their
columns, including subsequent ADD COLUMN migrations, and six other storage
boundaries. JSON record semantics remain defined by the pinned validators and
stores; a JSONB column is not evidence that arbitrary narrative is permitted.
The flow entries identify data, recipients, authorization, egress, storage,
retention and source evidence across 17 component groups and 22 flows.

`tests/security-contract.test.mjs`, automatically included by `npm test`, rejects
unreviewed added/removed/renamed/modified source, changed table fields, missing
recipient/lifecycle/evidence mappings and removal or downgrading of protected
obligations. The integrity-control module excludes only itself from its own
source hash to avoid a self-referential digest; its implementation is instead
bound by the PR head and adversarial tests. No generator automatically approves
new source. A failing binding requires review of the actual change and its flow,
then an explicit contract update; do not regenerate hashes as a substitute for
review or remove the test to pass CI.

This is code/DDL coverage, not proof of deployed configuration, third-party
transitive implementations, binary build artifacts, infrastructure logs, actual
database privileges or complete runtime coverage. Existing coverageComplete,
reviewed, implementation/testing completion and independent-review status are
not promoted. No status or registry acceptance is inferred from this document.

## Profile and claims decisions

| Data boundary                                                                                  | Decision                                                                        | Production claim                                                |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| Approved pages, portraits, media and explicit published sharing cards                          | Public disclosure; allow only approved projection                               | No private E2EE claim                                           |
| Volunteer identity, delivery, consent, sessions and account exports                            | Account service can process plaintext; delivery envelopes are decryptable by it | Encryption at rest/TLS is not E2EE                              |
| Current materials, drafts and private policy-source downloads                                  | Authenticated controlled distribution; server remains trusted                   | Restricted access is not secrecy from the server                |
| Operational teams, tasks, training, structured help and staff grants                           | Explicit scoped server-readable business processing                             | No sensitive report narrative permitted                         |
| Hosted checkout, ledger, treasury vault, reconciliation and controlled exports                 | Intentionally disclosed regulated processing with separate live gates           | Neither processor encryption nor server vault is recipient E2EE |
| Local worksheets and explicit user downloads                                                   | Device/user controlled                                                          | No remote protected submission or cryptographic recovery claim  |
| Recipient enrollment, confidential submissions, attachments, key recovery and protected export | Exact eligible production profile/adapter unavailable; keep disabled            | No production E2EE or certification claim                       |

No protocol/profile identifier is guessed. Before protected enablement, retain
the exact applicable reviewed profile, implementation and upstream remediation
pins; host/endpoint obligations; authenticated recipient/device authority;
interoperability/adversarial tests; and source/build/configuration/runtime-bound
AI security review evidence. External expert review and certification remain
separate, honestly pending stages, not blanket prerequisites to unrelated
engineering or a replacement for concrete controls.

The current guard in `apps/api/src/config.mjs` rejects
PROTECTED_CONTENT_ENABLED=true. The API's onRequest boundary rejects
/api/protected/ before parsing request bodies. An encrypted_records table is a
schema placeholder, not an installed protocol. A structured category-only help
request must never be reclassified as a confidential incident channel.

## Threat model and recovery

| Threat                                                                | Required boundary and evidence                                                                                                                                                                                                                                 |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Compromised source publisher, browser extension or recipient endpoint | Browser-delivered JavaScript and the endpoint remain trusted. CSP helps against injection, not a malicious publisher. Never promise protection from a party that can replace the cryptographic client.                                                         |
| Session theft, cross-origin writes and privilege escalation           | Host-only HttpOnly session; exact origin/CSRF on writes; server object authorization; current grant and fresh passkey where required. Review realm must never become staff authority.                                                                          |
| Email/account recovery silently grants protected history              | Account recovery restores account authentication only. Recipient-device/key reauthorization, historic access and future recipient expansion require distinct explicit protocol authority. No server escrow shortcut.                                           |
| Recipient change/revocation                                           | Fail closed until exact authenticated manifest/device rules exist. Revocation cannot recall already decrypted messages, screenshots, archives or exported copies.                                                                                              |
| Sensitive content leaks through help, analytics, email or logs        | Help accepts exact category/area only. Analytics accepts allowlisted codes and bounded values, never raw typed fields/URLs/DOM text. Email uses fixed account templates. Diagnostic output must contain only safe event metadata.                              |
| Unauthorized export or confused recipient                             | Account export is self-scoped and no-store, excluding login/delivery secrets and other accounts. Treasury export requires scoped fresh-MFA finance authority, bounded range/purpose, exact byte digest/audit and safe CSV. Protected export stays unavailable. |
| Draft/media exposure                                                  | Public reads use explicit publication/security-barrier projections and current revision/rights/expiry checks. Private source credentials and drafts must never enter static assets or public ZIPs.                                                             |
| Duplicate/uncertain financial effect                                  | Signed raw-body webhooks, deduplication and ordering; no uncertain automatic authorization retry. Hosted card boundary and financial live approval remain separate from this contract.                                                                         |
| Recovery archive bypasses deletion or authorization                   | Separate operator key, authenticated archive and isolated restore. Restore needs account-deletion/revocation reconciliation; a decryptable backup is not recipient E2EE or proof of a live restore rehearsal.                                                  |
| Service/operator/provider observes plaintext metadata                 | Explicit recipient/egress entries disclose this. Provider retention, proxy/log configuration and real DB grants need environment evidence; do not turn an unobserved control into a passing claim.                                                             |

## Retention and egress review

The JSON storage entries enumerate each table's field names, authority,
retention and disposal behavior. Expiry of a login/session is distinct from
physical pruning. Terminal mail envelopes are cleared; terminal jobs have a
30-day prune and delivery events a 90-day prune when maintenance runs.
Suppression and audit history do not have a demonstrated universal expiry.

Visitor rows older than 30 days are removed on later start ingestion (at most
daily), with event cascade. An idle database has no proven scheduled cleanup
from that code alone. Do not advertise an unconditional 30-day deletion SLA.
Account closure cascades owned records and scrubs coordination references;
staff offboarding and financial retention remain separate. Withdrawing help
changes its state; it is not deletion. Immutable editorial/media histories,
operator archives, provider copies and user downloads need their own custody
and lifecycle decisions.

| External recipient or destination                                  | Allowed material                                                      | Excluded material                                                                          |
| ------------------------------------------------------------------ | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Configured Resend account-delivery provider                        | Destination email, expiring login link, fixed account notice          | Confidential reports, protected attachments, supporter narratives                          |
| Visitor-activated YouTube player / user-selected share destination | Explicit public video/page and ordinary connection metadata           | Volunteer account or protected record access                                               |
| Allowlisted private GitHub source API                              | Server-authenticated read of the designated policy source             | Browser exposure of source credential; inferred public publication                         |
| Approved hosted payment provider                                   | Intentional sandbox/authorized checkout and signed financial events   | Site-owned card entry or unapproved live financial effects                                 |
| Operator deployment/log/backup destination                         | Explicit approved artifact or restricted operational metadata/archive | Ambient authority to deploy, buy resources, disclose credentials or publish private source |

The server observes ordinary transport metadata even when application analytics
stores no IP/account identifier. The review-auth schema contains nullable IP and
user-agent fields; inspect actual library/runtime writes and configuration
before claiming they are never persisted. This record deliberately preserves
that uncertainty.

## Reviewer and release handoff

1. Run npm test and npm run check, preserving existing integration, build,
   browser, dependency audit and secret-scan gates. Retain the actual PR head
   and test reports; local Node 24 is not the pinned Node 22 runtime.
2. Review every source-binding failure against changed data fields, recipient
   authority, egress, storage and disposal. Review nested JSON validators as
   well as SQL columns. Keep exact source pins, not mutable branch links.
3. Exercise protected pre-parser rejection, unknown feature/profile rejection,
   negative field/attachment inputs, object/role/CSRF checks, export scoping and
   source-to-public projection. Contract tests alone cannot prove runtime safety.
4. For the intended deployment, prove actual origin/proxy configuration, least
   database grants, provider accounts, log redaction/access/retention, worker
   pruning, archive custody and tested restore. Missing evidence is reported as
   missing, never as a generic certification or independent-review blocker.
5. Protected-content enablement still requires the exact protocol, recipient and
   cryptographic implementation evidence above. Continue public and other
   approved software work while those concrete conditions remain unavailable.

Local validation passed 18 tests: the 13 contract regressions, two existing
inventory checks and three existing structured-help checks. The focused ESLint
10.13.0 run and Prettier 3.9.10 checks passed. These ran on Node 24.22.1, outside
the repository's pinned Node 22 runtime; no full application, database,
cross-browser, deployed integration or upstream conformance pass is claimed.
Hosted checks must be inspected for the exact committed head before any
accepted-merge claim.


## Integration reconciliation — 1 November 2026

After the source-bound contract was introduced in #144, subsequent accepted
changes #142, #145 and #146 and the volunteer navigation work in #147 changed
the recorded source tree. A combined CI run correctly rejected the old baseline
at the *source coverage* stage. This invalidated downstream mutation-test
expectations before their intended failure points were reached; it was not
evidence that E2EESA protection had been turned on.

The integration review reconciled **ten** source entries: full-surface role
navigation and detail routing in `apps/portal/src/main.tsx`; browser-coverage
preflight in `scripts/verify.mjs`; V2 signed publishing and approved-reading
boundaries in `packages/core/content.mjs`, `material-publication.mjs`,
`staff-review.mjs` and `scripts/publish-materials.mjs`; the new
`packages/core/material-approval.mjs` under the materials component; and
defensive public-document and PNG admission changes in
`packages/core/policy-documents.mjs`, `safe-policy-document.mjs` and
`campaign-image.mjs`. Those paths, component assignments and exact Git blobs
are now covered. No database migration or declared SQL field changed.
Browser-facing styles and tests remain outside the executable source scope.

The review retains the documented component trust boundaries and flow
classifications. Volunteer navigation introduces no new recipients, PII fields,
background export or external egress. V2 publishing and document changes tighten
release admission without introducing a protected profile. Protected
enrollment/submission/attachment/recovery/export remain blocked, and production
E2EE, certification and runtime verification claims stay **false**. The
`sourceCommit` binds the source snapshot prior to this inventory-only update.
This is a source-level integration review, **not** an independent security
assessment, runtime penetration test or certification. Combined-head tests must
still pass before release.
