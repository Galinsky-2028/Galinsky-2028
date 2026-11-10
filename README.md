# Galinsky 2028

**Current connected-account deployment (9 November 2026):** website https://galinsky2028-website.onrender.com and volunteer platform https://galinsky2028-volunteers.onrender.com. Both retain private password protection. The volunteer service uses a fresh connected-account Neon database and supports device-passkey registration/sign-in; email/staff, protected reports and live donations remain disabled. See [current deployment and access handoff](docs/operations/CONNECTED_WORKSPACE_20261109.md). The older resource/status notes below are historical and do not establish current availability.

Implementation of the approved Phillip Galinsky for America campaign website and volunteer application. The public design preserves the approved portrait, colors, composition and illustrations. Each launch issue has its large top-of-page video component.

**LIVE PRIVATE PREVIEW ONLY (11 October 2026):** The website is available at https://galinsky-2028-private-preview.onrender.com behind the server-side HTTP Basic password gate in `docs/operations/PRIVATE_PASSWORD_PREVIEW.md`. Username: `preview`; password: the existing confidential Render `PREVIEW_ACCESS_PASSWORD` originally supplied by GitHub Actions secret `G28_PREVIEW_ACCESS_PASSWORD`. Never commit or print it. Verified unauthenticated and wrong-password HTTP 401 responses plus authenticated page access in [live acceptance run 38164974556](https://github.com/neophilism/Galinsky-2028/actions/runs/38164974556). This is **not a public campaign launch**: verified email signup, payments, staff administration, sensitive submissions and approved field activities are not activated. The separate real volunteer portal/API is deployed and password-protected. Auto-deploy is off.

**Render service is already created:** [galinsky-2028-private-preview](https://dashboard.render.com/web/srv-db5teuajnfac73bm8pug) lives in the designated [Galinsky 2028 project](https://dashboard.render.com/project/prj-db57fnm7bikc739783q0), environment `evm-db57fnm7bikc739783qg`. The exact-project GitHub Actions creation succeeded [run 38164605594](https://github.com/neophilism/Galinsky-2028/actions/runs/38164605594); Render deployment `dep-db5tev2jnfac73bm8sn0` is live. Consult [the provisioning runbook](docs/operations/RENDER_EXACT_PROJECT.md) for recreation or credential rotation. Other Render services remain unassigned by user choice; no relocation is required.

**Real volunteer portal/API:** https://galinsky-2028-volunteer-portal.onrender.com ([Render service](https://dashboard.render.com/web/srv-db5v0lfavr4c73a62870)), in the same designated project/environment and protected by the same private-preview password. Its Neon staging database is connected and `/readyz` passed live verification ([run 38181063632](https://github.com/neophilism/Galinsky-2028/actions/runs/38181063632)). Public volunteer role links now open the actual portal, not a browser-only simulation. It provides account-backed role preferences, tasks and reading acknowledgments, plus real account-data export and global logout (PR #41). Accounts cannot be created until verified mail infrastructure is enabled. Current approved volunteer-materials publication is still pending.

**Current package acceptance (13 October 2026):** **8 accepted, 46 in progress, 7 not started**, from 61 planned work packages. Separately, 82 GitHub PRs were merged. See the [package-by-package acceptance audit](docs/evidence/ACCEPTANCE_AUDIT_20261013.md). This is not a live public campaign or payment release.

**Start here:** [implementation status](docs/IMPLEMENTATION_STATUS.md), [complete development plan](docs/DEVELOPMENT_PLAN.md), [61-package register](docs/PR_REGISTER.json), [agent rules](AGENTS.md), [deployment runbook](docs/operations/DEPLOYMENT.md).

## Run and verify

Use the Node version in `.nvmrc` and the committed lockfile.

```sh
npm ci
npm run check
npm run typecheck
npm test
npm run test:api
npm run build
npm run dev
```

`npm run dev` serves the built public website on port 4321. `npm start` serves the built volunteer application and API on port 4322. Without a database it uses an explicit development-only in-memory store. Production refuses that fallback. Copy `.env.example` into your local environment; Node does not silently load an arbitrary environment file. For local development use `node --env-file=.env apps/api/src/server.mjs` after setting the required values.

Database tests need an isolated loopback Postgres instance and `TEST_DATABASE_URL`; they must never target the assigned Neon production project. CI supplies that isolated database. `npm run test:browser` requires installed Playwright Chromium, Firefox and WebKit and exercises real local HTTP sign-in, cookie, library and logout flows using synthetic mail and material fixtures.

`npm run build:offline` is a dependency-free public-page rendering fallback for inspection. It is not a replacement for the Astro/Vite production build or application testing.

## Layout

- `apps/web`: Astro public marketing site, original design assets and small interactive scripts.
- `apps/portal`: React/TypeScript volunteer workspace, account UI, role guide, library and local worksheets.
- `apps/api`: Fastify application, explicit runtime configuration, Postgres storage and durable account-email worker.
- `packages/core`: tested validation, consent, publication, activity authorization and finance boundary rules.
- `content/public`: approved public templates and issue/video configuration.
- `content/materials`: source manifest and current approved publication input; no full historical archive in the public build.
- `db/migrations`: versioned transactional database schema.
- `docs`: full plan, decisions, security boundaries, evidence and handoff.

## Important current boundaries

The preview does not accept payments or collect sensitive volunteer reports. Signup requires verified email delivery configuration. The current materials list is intentionally empty until the historical package is reconciled and actually reviewed. Staff identity, sensitive-content E2EE, fundraising integration and several planned operations workflows still require implementation and review; setting a boolean cannot enable them.

The original 36-document source package remains an authorized source input, not a browser download. Its manifest is tracked, not its full bodies. This project does not claim E2EESA certification. Public material, account-delivery metadata, sensitive content and financial disclosure have separate boundaries.

The Render Blueprint remains a configuration source; actual deployment evidence is linked above. Both the password-protected public preview and real volunteer portal/API are deployed. Email signup, published current volunteer materials, staff administration, donations, sensitive reporting, regulated activity modules, and public production release remain separate implementation/release gates.

## End-to-End Everywhere progress

The canonical [security/e2eesa-status.json](security/e2eesa-status.json) records standard implementation, complete testing and independent expert review separately. Engine Room reads it automatically from GitHub. All initial stages are pending; existing profile locks and approved decisions remain authoritative. Read [adoption and independent-account instructions](docs/E2EESA_ADOPTION.md), and run `python3 scripts/validate_e2eesa_status.py`. Record validation does not establish product security or certification.
