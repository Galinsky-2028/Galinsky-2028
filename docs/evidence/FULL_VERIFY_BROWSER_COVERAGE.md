# Full verification requires complete browser coverage

Scope: G28-002, mandatory CI and reproducible verification.
Reviewed baseline: `8607f12b9b0b15bbc1457eea6cc5fd9866e62399`.

The reviewer browser runner intentionally accepts `G28_BROWSER_ENGINES` for focused debugging. Previously, `npm run verify` inherited a reduced selection without checking it. An isolated orchestration regression with `G28_BROWSER_ENGINES=chromium` returned success after all 14 mocked commands, even though the reviewer gate would cover only one engine. This was a coverage-reporting gap; the regression does not claim any browser actually ran.

Full verification now rejects reduced, duplicate, unsupported and malformed selections before launching any command. The unset/empty default and complete distinct three-engine selections remain supported, including whitespace and order variations accepted by the focused runner. The focused runner itself is unchanged. All existing database, build, audit, secret and browser gates remain required.

Validation: 25 focused Node tests passed with zero skips in a credential-free isolated snapshot using Node v24.22.1. This differs from the project-pinned Node v22.23.3, so it is not full project acceptance. The real CLI rejection test launches no npm subprocess and makes no database connection. Formatting was checked with the pinned Prettier 3.9.10. Exact committed-head hosted CI remains authoritative for the supported runtime, PostgreSQL integration and actual three-engine journeys.

No deployment, live campaign operation, payment action or production data access is part of this change.
