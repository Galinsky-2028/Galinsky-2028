# Two-person staff publication — signed offline operator workflow

**Owner-directed exception, 9 November 2026:** the campaign owner expressly selected an owner-authorized, AI-reviewed reading release from the supplied normalized source edition. That specific workflow uses `content/materials/owner-release.json` and exact complete-record digests through `validateConfiguredMaterialRelease`, with no human-signature claim. See `docs/evidence/VOLUNTEER_MATERIAL_REVIEW_20261109.md`. The process below remains the default for independently signed staff releases and still applies to actual field-activity authorization; do not invent keys or signatures to apply it to the owner exception.

This operational feature **does not enable web-based staff login**, and does not claim to authenticate reviewers automatically. It supplies a concrete, tamper-detecting publication and role-approval boundary until a separately reviewed multi-factor staff identity UI exists. The HTTP `/api/admin/*` endpoint remains unavailable.

## Key provisioning (human-operated)

An authorized administrator confirms each human author's and reviewer's identity off-band. Generate an Ed25519 key locally using `umask 077; openssl genpkey -algorithm ed25519 -out author-private.pem`, and export its public PEM with `openssl pkey -in author-private.pem -pubout -out author-public.pem`. Repeat on the *reviewer's own* device. Never commit/upload private keys or share them with a build, Render or the campaign database.

After operator verification and appropriate GitHub code review, list **public** keys in `content/materials/staff-keys.json`. Each entry needs unique `id` (`staff-...`), stable non-email `subject`, `role` (`author` or `reviewer`), `active:true`, and `publicKeyPem`. A single person cannot be both author and reviewer for one release. Revocation means marking a key inactive and reviewing recent releases separately; git/DB administrators remain a distinct trust boundary.

## Document review

Prepare one JSON record with id, title, body, positive revision, `status:"published"`, `audience:"volunteer"`, `author` subject, and `review` with another subject, exact revision, UTC timestamp and date. Author and reviewer must each *actually read the exact text* before signing. Record canonical signatures:
```sh
node scripts/sign-material-review.mjs material.json author-private.pem author staff-author-example
node scripts/sign-material-review.mjs material.json reviewer-private.pem reviewer staff-reviewer-example
```
Use the same reviewer timestamp as `review.at`, and copy their signature objects into `approvals.author` and `approvals.reviewer`. The signature commits to material ID, revision, title, entire body, audience, status, role, key ID and UTC signing time. Altering any one invalidates approval. A reviewer cannot rubber-stamp an author identity they control, and expired/revoked keys cannot be used.

Place only the reviewed records in `content/materials/current.json` and run `node scripts/verify-material-release.mjs`. Publication remains blocked when the registry has no trusted keys or the material list is empty.

With authorized operator database access and a tested migration/backup, run `npm run materials:publish`. It verifies signatures again, takes a transaction advisory lock, refuses stale revisions, writes only approved volunteer material, and writes a per-material audit event with exact digest and actor IDs. Test against a *staging branch* before any authorized production release.

## Limits

This is staff **editorial approval infrastructure**, not a full staff dashboard, workforce identity proofing, training certification, election authority, independent accessibility review, or end-to-end encrypted submission. Do not relax `STAFF_IDENTITY_ENABLED`, `PROTECTED_CONTENT_ENABLED`, or `DONATIONS_ENABLED` on this basis. A compromised database administrator/GitHub maintainer can still alter trusted key sets; protect repo write permissions and require human code review.
