# Volunteer material publication boundary

**9 November 2026 owner update:** the owner explicitly authorized an AI-reviewed reading release from `source-edition-1`. `current.json` now contains nineteen reconciled guides with exact approval/provenance binding in `owner-release.json`. See `docs/evidence/VOLUNTEER_MATERIAL_REVIEW_20261109.md`. This replaces the initial empty-library state; it does not approve raw historical guidance, unrelated launch policies, regulated activity or protected submissions. The normal two-party staff-signature path remains available for other releases.

`archive-manifest.json` inventories all 36 source Markdown documents from the supplied September 2026 package, with titles, original names and SHA-256 hashes. It deliberately contains no document bodies. The original user-supplied package remains outside tracked/public files in `source-inputs/`; it must be placed in authorized campaign storage before the fresh-agent handoff is considered complete.

`current.json` contains only actual approved volunteer-facing publication records. It starts empty: none of the historical records is silently promoted to current campaign guidance. The Garden and Cornerstone need reconciliation, Kirk-Evers needs an approved kit, and other issue kits are not launch positions.

`npm run materials:publish` validates the entire current manifest and imports it transactionally into the assigned database. It rejects missing approvals, self-review, duplicate IDs, stale or same-version replacements, and empty import attempts. The command is an operator workflow, not a substitute for staff identity and the planned editorial interface. No anonymous HTTP publication route exists.

General materials access requires a verified volunteer account. This is authenticated distribution, not a claim of E2EE. Sensitive submissions and staff administration remain disabled.
