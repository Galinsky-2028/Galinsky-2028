# Dependency audit repair — 2026-11-01

A full-branch GitHub Actions audit of the earlier merged website found
production dependency advisories in the pinned Fastify, fast-uri, Undici
and Vite versions. This is distinct from the role-card UI issue.

On Node 22.23.3, a one-shot, branch-only workflow updated the committed
package manifest and lockfile to Fastify 5.12.7 and Vite 8.3.5, and applied
safe production transitive patch updates (fast-uri 4.2.3 and Undici 8.12.3).
It then passed `npm ci --ignore-scripts` and
`npm audit --omit=dev --audit-level=high`. No broad `--force`
downgrade or replacement of ESLint was accepted.

The temporary workflow removed itself from the same branch after committing
the verified manifest and lockfile. The final combined-head application,
PostgreSQL, browser and release verification remains authoritative; a
passing dependency audit alone does not authorize a production launch.
Protected-data and donation activation controls are unchanged.
