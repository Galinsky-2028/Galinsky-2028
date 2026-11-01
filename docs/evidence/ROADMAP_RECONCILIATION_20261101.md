# November 1, 2026: source-bound roadmap and GitHub acceptance reconciliation

## Evidence and decisions

Repository: `neophilism/Galinsky-2028`.
Reviewed merged application source: `6d6c7aab464f89bc716e7a18cdd2227771285c59`
(the release of PR #147). Full application CI for the PR head:
[run 41359919156](https://github.com/neophilism/Galinsky-2028/actions/runs/41359919156),
**success** including unit tests, HTTP/PostgreSQL integration, Astro/React builds,
Chromium/Firefox/WebKit real-HTTP journeys, reviewer-account checks and the
production dependency audit. On Nov 1, both Render previews completed with
status **live** on the merged SHA:

- Website: service `srv-db5teuajnfac73bm8pug`,
  deploy `dep-dbjsbbk9v7es73b11490`.
- Volunteer portal: service `srv-db5v0lfavr4c73a62870`,
  deploy `dep-dbjsbc3bc2fs73do1j20`.

The GitHub PR snapshot was fetched from the complete paginated `state=all`
REST results (142 unique PRs #1 through #147; 134 merged, 8 closed
without merge and zero open at the observation). No inference from a stale
dashboard or the numeric PR ID was used.

## Reviewed full-scope acceptance

These five packages were marked full-scope complete only after separately
reviewing their acceptance criteria against the source, merged PR, successful
combined CI and live protected preview. Their dedicated merged PRs explicitly
carry the matching work-unit identifier.

| Package | Dedicated accepted PR | Verified scope |
|---|---|---|
| G28-002 | #142 | Reproducible CI and three browser engines; source/boundary tests cannot be silently skipped; dependency audit repaired at #147 |
| G28-003 | #143 | Shared navigation, responsive design and accessible keyboard/browser navigation; role-card repairs from #147 are included in the released build |
| G28-005 | #144 | Source-linked privacy/security and protected-flow obligations, fail-closed unknown profiles; final integrated source hashes and review reconciled in #147 |
| G28-006 | #145 | Versioned draft/material publication, independent review, current revision and source-bound admission; tested against the combined application |
| G28-007 | #146 | Safe editorial document/media validation, rights/type/provenance checks; browser and security regression suite on combined build |

**Scope limitation:** acceptance of G28-005 is for *defining and enforcing a
fail-closed source-bound security contract*, not for delivering protected
cryptographic submissions or certifying E2EE. G28-021/022/023/034 and
other identified protected-data, treasury and production activation gaps remain
separate, explicitly unfinished. The source contract does not claim audited
production runtime coverage or independent certification.

Additional accepted contributions were mapped to the corresponding packages:
#136–141 (review, QR, sharing and monitoring), #142–146, and #147
(volunteer role cards and the application security/CI integration). The
`prs` list indicates only a fully evidenced package; `contributingPrs`
never paints a package as complete. Previously accepted PR mappings were
preserved. A merged PR is accepted even if its target package remains open.

## Progress interpretation

72 total current approved packages (60 original, 12 additions).
Before this reconciliation, the source reported 8 fully accepted packages,
50 other implemented, 11 in progress with software gaps, 3 not started.
After review, there are **13 fully scoped accepted, 46 other software
implemented, 10 still in progress and 3 not started**.
Thus **59/72 contain implemented software**, but only **13/72 have the
stronger full-package acceptance**. The bar representing full-package
acceptance must never be described as a percent of code written.

The live preview deployment is not a general public launch. Public signup,
real donations, protected submissions and external approvals remain disabled
unless verified and independently authorized. No status in this report is
an instruction to enable them.

## Reconciliation validation

The canonical registry and its mirror (`docs/PR_REGISTER.json`) and delivery
facts (`docs/evidence/DELIVERY.json`) must pass
`tests/acceptance-registry.test.mjs` and
`scripts/validate-pr-registry.mjs`; complete CI must remain green.
Engine Room consumes the canonical `registry/prs.json` and must show the
separate software-implementation and full-acceptance facts without presenting
unaccepted contributions as green.
