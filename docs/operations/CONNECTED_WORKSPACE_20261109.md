# Connected-account deployment and handoff

The owner authorized using the connected Render/Neon accounts, a fresh database and retirement of accessible superseded resources. Private access, free plans, cryptographic requirements and transaction controls remain in force.

## Current resources and verified release

- Render workspace `tea-dbl0kcbm8hqs738ptf3g`.
- Website `srv-dbp6n18m7kps73a0kpsg`: https://galinsky2028-website.onrender.com.
- Volunteer API/portal `srv-dbp6n661egvs73b7pspg`: https://galinsky2028-volunteers.onrender.com.
- Both existing Node web services use the free plan in Ohio. Automatic deploy is off. A public static-site replacement would bypass private access and is not authorized.
- Both are live on merged PR158, commit `eaf0c430c68195fea16f2aa4edec64ac8d598408`. Exact-head CI `42797090386` passed on `53d582fe84ee292523628dfea8bb6bccc0f389a8`. Exact deployment IDs and observations are in `docs/evidence/CONNECTED_RELEASE_20261110.json`.
- Startup probes verified installed HTTP/configuration/assets: 69 website checks and 23 portal checks. External unauthenticated health requests returned401. These observations are not an independent authenticated hosted-browser or staff/financial transaction rehearsal.
- Neon project `calm-moon-73214448`, database `galinsky2028`, primary branch `br-damp-heart-bexv8utq`; migration validation branch `br-odd-river-bedrj1su`.
- Migration024 passed on validation and primary, bringing recorded migrations to30. Protected identity count was0 at verification. Migration SQL SHA256 is recorded in the release evidence.

This is a fresh database; inaccessible old accounts/data were not claimed migrated. The installed login `g28_portal_runtime_volunteer` uses the narrow `volunteer` profile in `scripts/runtime-role-permissions.mjs`, without inherited roles, DDL or role creation. Current permission checks deny protected records, public protected identity tables and treasury donors. Materials/modules are read-only; scoped passkey accounts, preferences, progress, bookmarks and acknowledgements retain their existing permissions.

## Private access and available volunteer functions

Both services retain HTTP Basic protection with username `preview`. An authorized owner can retrieve or replace `PREVIEW_ACCESS_PASSWORD` privately in Render. Do not copy it into source, reports, chat or screenshots. This release did not rotate credentials or bypass the gate.

Passkey registration/sign-in is enabled inside the private volunteer portal. Passkeys are bound to its new hostname. Nineteen source-edition guides were released using the explicitly owner-authorized AI review, with exact record hashes and append-only publication audit. Details: `docs/evidence/VOLUNTEER_MATERIAL_REVIEW_20261109.md`. Materials access does not authorize regulated activities or create verifier approvals.

The earlier hosted passkey/material journey at release `4599245d56a43c64653d229ee1e61dcb84bc3a8f` exercised registration, search, filters, downloads, persistent bookmarks/acknowledgements, orientation and closure; its synthetic accounts were removed. The current release has separate exact-source CI and runtime-probe evidence as described above.

## Remaining activation and software conditions

Verified email/staff administration requires an actual mailbox, transactional sender, delivery callback secret and operational mail path. No email ownership, staff identity, recipient key, verifier or campaign legal/merchant approval is fabricated. Coordination, regulated tasks, confidential intake and financial processing remain independently gated.

Ratcheted protected delivery, local encrypted custody and signed device authority are implemented in PR157. The subsequent root/linked-device lifecycle and controlled-export source is covered by `docs/security/RATCHETED_PROTECTED_DEVICE_LIFECYCLE.md`; its merge/deployment is separate from this release. Protected runtime remains disabled pending the pinned hardened-web release, authenticated log/witness/update and transport controls and actual staff/recipient setup. The source no-backup candidate does not silently select an active user recovery policy.

Current concrete work and counts are maintained in `registry/prs.json` and `docs/evidence/CURRENT_IMPLEMENTATION_REVIEW.md`. Recurring future-charge enforcement remains separate software work. Actual approved outreach tools and campaign-specific treasurer/merchant release are external inputs. No live processing or paid infrastructure was authorized by these deploys.

GitHub deployment/acceptance workflows previously held old-account secrets. Update their configuration privately before using them against these new services; do not replace current preview credentials merely to run a test.

## Retirement and operator constraints

The two old Render services were deleted after the replacement release passed verification (Actions run `42735201769`). Old Neon project `soft-bread-25523698` returns404 through the connected account; deletion cannot be claimed. Do not invoke historical provisioning files or portfolio-wide cleanup to recreate/delete unrelated resources.

Host Node24 is used for local engineering; CI/Render use Node22.23.3. Use `ASTRO_TELEMETRY_DISABLED=1` and a writable task-local XDG configuration directory for local builds. Preserve exact deployed source and migration evidence, private credentials and all transaction controls.
