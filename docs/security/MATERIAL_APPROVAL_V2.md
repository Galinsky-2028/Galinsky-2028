# Exact material revision approval

## Finding and change

On 1 November 2026, an isolated reproduction against source
`4be888089106a0e36acc238ae7d1d8713059a2a6` accepted a signed material release after
its description and category were changed without a new signature. The old
digest bound id, revision, title, body, audience and status, while additional
metadata could affect volunteer lists, search or future video routing.

The V2 digest also binds description, category, YouTube identifier and author.
The existing Ed25519 signature statement uses the distinct
`G28-SIGNED-MATERIAL-V2` domain. No cryptographic primitive, signer registry or
recipient authority changes. Publication still requires two active, distinct,
role-appropriate signing identities, current signature dates and exact revision
metadata. Private signing material stays off the application server.

Publication validates optional descriptions, categories and canonical video
identifiers. Changes or deletion of signed metadata invalidate the approval.
The publisher records `material_publish_signed_v2` in its existing audit event.

Read-time checks previously accepted a matching revision and any truthy review
label, without requiring an author, an independent reviewer or a valid date.
One shared approval predicate now applies to publication, volunteer list/search,
reader/download, bookmarks and reading acknowledgment. Missing or malformed
identities/dates, self approval (including whitespace padding), future review
dates, non-positive/non-integer revisions and stale approval revisions fail
closed. Account verification must be the boolean true, and publication scopes
must be an actual array.

This predicate checks metadata consistency. It does not claim that a database
read independently verifies signer cryptography. Signed release validation
remains the admission boundary, and the authorized database/application server
remain trusted for stored content. Material access never grants regulated
activity or staff authority.

## Compatibility and operator handoff

V1 approvals cannot authorize a V2 release. Re-sign the exact reviewed content
with the existing authorized author/reviewer process before publishing a new
revision. Do not copy old signatures into the new release, bypass signature
verification, automatically approve content, provision fictitious signers or
republish an older revision. The existing strictly-newer revision and atomic
database transaction rules remain in force.

The inspected repository's current material release and signer registry are
empty. This is a source observation, not evidence that a deployed database has
no material rows or that any real operator is provisioned. An existing stored
record lacking valid author/reviewer/date metadata becomes unavailable until
correctly reviewed and republished; the reader does not synthesize approval.
Existing valid historical approval dates do not acquire a new age expiry at
read time; the existing signed-publication freshness rule still governs new
admission.

## Evidence

The baseline reproduction used generated fixture keys and accepted tampered
description/category metadata. Regression tests now reject metadata changes and
deletions, explicit legacy V1 statements, self/missing/malformed approval and
invalid field types. HTTP injection tests verify that invalid approvals cannot
reach list, reader, download, bookmark or reading-acknowledgment routes.
Existing positive fixtures now contain complete independent dated approvals;
no assertions or access controls were weakened.

Local validation passed 127 tests across the core, publication, signature,
reading, approval and in-memory HTTP API suites, with zero failures or skips.
This used Node 24.22.1 and exact repository-pinned runtime packages in an
isolated credential-free sandbox. It is not the pinned Node 22 full build,
PostgreSQL integration or three-engine browser result. Inspect current-head
GitHub Actions before a merge or broader release claim.
