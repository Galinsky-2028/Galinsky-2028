# Connected-account deployment and handoff

Owner instruction, 9 November 2026 (America/New_York): use the connected Render workspace and connected Neon account; create a fresh database; delete superseded services/database if accessible. This supersedes the historical existing-service-only placement restriction for this migration. It does not authorize charges or fabricated publication/security approvals.

## Current resources

- Render workspace: `tea-dbl0kcbm8hqs738ptf3g`.
- Website: `srv-dbp6n18m7kps73a0kpsg`, https://galinsky2028-website.onrender.com.
- Volunteer API/portal: `srv-dbp6n661egvs73b7pspg`, https://galinsky2028-volunteers.onrender.com.
- Both are Node web services on the free plan in Ohio; automatic deploy is off. Do not deploy the website as a static site, which bypasses its private gate.
- New Neon project: `calm-moon-73214448`, database `galinsky2028`, primary branch `br-damp-heart-bexv8utq`. This is a fresh database, with no claim that old accounts/content were migrated.
- Migration-validation branch: `br-odd-river-bedrj1su`. All 27 checked-in migrations passed there before application to the primary branch.
- Portal SQL login: `g28_portal_runtime_volunteer`, without inherited roles, DDL, role creation, staff grants, editorial or treasury access. The `volunteer` profile in `scripts/runtime-role-permissions.mjs` is the reproducible grant definition. Materials/modules are read-only; passkey accounts, preferences, task progress, bookmarks and acknowledgments have the scoped DML needed by the application. Account closure/export retain their existing cleanup/read permissions.

The original broad portal role was rejected by automatic approval review. It was not installed. A narrower volunteer-only profile was installed and its denied staff/treasury/editorial privileges were verified through PostgreSQL permission checks.

## Access and activation

Both services retain HTTP Basic protection, username `preview`. The new high-entropy password is stored only in each service's Render `PREVIEW_ACCESS_PASSWORD` environment variable; an authorized owner can retrieve or replace it in the Render Dashboard. Do not copy it into source, reports or chat. Passkey registration/sign-in is enabled inside the protected volunteer portal. Passkeys are bound to the new portal hostname; old-origin credentials do not silently migrate.

Email-link signup, staff administration, coordination, help intake, protected narratives/attachments and donations remain disabled. No verified email sender, current approved materials, treasurer/merchant release or installed reviewed protected-content protocol has been invented. These are actual remaining release/software inputs, not a second acceptance ceremony for merged PRs.

The GitHub deployment workflows previously used secrets from the old account. Update their secret configuration privately before relying on the updated live-acceptance workflows against the new services. Old provisioning request files and exact-project scripts remain historical; do not invoke them to recreate services in the superseded account.

## Retirement

The connected Render account returns 404 for both old services; the connected Neon account returns 404 for `soft-bread-25523698`. Absence through these credentials does not prove deletion. A manually dispatched `retire-old-render.yml` can audit then delete only the two exact old campaign services using the existing GitHub-held old Render credential if it still works. It verifies both identities/placements before deletion and cannot select databases, projects or new services. Never use the older portfolio-wide cleanup workflow for this request.

## Verification and remaining work

Local source checks, unit tests and both production builds were run. Node 24 is supplied by this execution environment; deployed services and GitHub CI use the pinned Node 22.23.3. Browser verification uses Chromium and a synthetic WebAuthn authenticator against the deployed portal, with the environment proxy CA explicitly trusted.

Public launch remains incomplete: final issue videos/captions and canonical destinations, approved current volunteer materials/training, protected recipient/device encryption and recovery, treasury reconciliation/exception/recurring-donor workflows and configured staff/mail delivery remain separately tracked in `registry/prs.json` and `docs/evidence/CURRENT_IMPLEMENTATION_REVIEW.md`. No full-platform completion or public fundraising release is claimed.
