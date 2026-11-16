# Protected reporting: release authenticity, transparency and activation gate

Status, 15 November 2026: **implemented in source and tested; the gate is closed in every deployment** because `security/release-trust.json` pins no keys. This is an AI-reviewed engineering control under the owner's security-review policy. It is not an independent audit and not an E2EESA conformance claim.

## What now guards `PROTECTED_CONTENT_ENABLED=true`

`apps/api/src/config.mjs` calls `protectedActivationReadiness` in `packages/core/release-authenticity.mjs` and refuses to start (503 `protected_unavailable`, listing every missing condition) unless **all** of the following hold:

1. **Signed release of the installed bytes.** `dist/release-evidence.json` carries a release statement signed with Ed25519 by a key pinned in `security/release-trust.json`. The statement binds the exact source commit (`RENDER_GIT_COMMIT`), build roots and the SHA-256 closure digest of every file in `dist/portal` (`security/web-release-closure.mjs`). A single changed, added or removed byte fails.
2. **Anti-rollback.** The statement's `sequence` must be at least the pinned `minimumSequence`. Raising the floor makes every older signed release unusable.
3. **Transparency inclusion.** The statement's RFC 9162 leaf hash must be included, by Merkle inclusion proof, at a checkpoint (`origin\nsize\nroot\n`) of the pinned log origin.
4. **Independent witnesses.** The checkpoint must be signed by the pinned log key **and** cosigned by at least `witnessQuorum` (minimum two) distinct pinned witness keys. One key cannot hold two roles. Duplicate signatures are rejected.
5. **Transport observation.** The signed statement must state, for the exact portal origin, that TLS 1.3 only was observed with fallback refused, within the last 30 days.
6. **Operations.** `STAFF_IDENTITY_ENABLED=true` (verified staff), and `G28_PROTECTED_RECOVERY_POLICY` explicitly set to `no-backup` or `encrypted-recovery`.

No environment variable can stand in for a signature, proof, witness or observation. `security/verify-e2eesa-release.mjs` (run in CI) fails if this guard is removed. It reports `protected-intake-blocked` while no trust roots are pinned.

## Browser-side delivery controls (portal)

- Every JS and CSS file is bound by SHA-384 Subresource Integrity. One inline import map carries an `integrity` entry for **every** JavaScript chunk, including lazily imported protected-reports and cryptography chunks (`apps/portal/release-integrity.mjs`). Chromium was verified to refuse a substituted lazy chunk.
- The document's Content-Security-Policy allows only same-origin scripts plus that exact import map by SHA-256. A document with any other inline script is refused (`apps/api/src/static.mjs`).

**Residual risk (stated honestly):** the import map and CSP arrive with the same HTML document. They protect against a substituted or corrupted chunk and against deploying an unwitnessed build, but not against a fully compromised origin that serves a different document. Same-origin code cannot defend against that.

## Outside verifier

`tools/release-verifier/verify-published-release.mjs` checks a published release without trusting the server.

**How to run it.** Use your own reviewed checkout and your own copy of the trust policy:

```bash
node tools/release-verifier/verify-published-release.mjs https://<portal origin> \
  --trust <your release-trust.json> --user preview --password-env PREVIEW_PASSWORD
```

**What it does:**
1. Downloads `/.well-known/g28-release.json`, the evidence that `apps/api/src/static.mjs` publishes from `dist/release-evidence.json`.
2. Re-downloads every listed portal file and rebuilds the closure digest from the bytes it received.
3. Verifies the pinned release signature, the anti-rollback floor, log inclusion, the witness quorum, and the freshness and origin of the TLS observation.
4. Confirms that the page's import-map and SRI table binds every downloaded script and stylesheet.

**Coverage and limits:**
- `tests/release-verifier.test.mjs` covers an honest release and each tampering case: a changed chunk, a changed page, a rogue-key signature, a missing witness, unsafe paths, rollback and plain HTTP.
- It verifies what one client downloaded at one time. A browser extension that runs the same checks on every page load remains an optional future step.

## Operator procedure (owner inputs required)

1. The owner creates an Ed25519 release key **outside GitHub and Render** and pins its public SPKI (base64 DER) and `keyId` (SHA-256 hex of the DER) in `security/release-trust.json` through a reviewed PR.
2. The owner selects a transparency log and at least two independently operated witnesses, and pins `logOrigin`, `logKey` and `witnessKeys`.
3. For each release, after `npm run build:portal` on the exact deployed commit:
   - `G28_RELEASE_SIGNING_KEY_FILE=… node security/release-evidence.mjs statement <sequence> transport.json`
   - submit the `leaf` to the log and obtain the proof and the witness-cosigned checkpoint;
   - `node security/release-evidence.mjs assemble statement.json log-entry.json > dist/release-evidence.json` (the evidence includes the file manifest the outside verifier needs)
   - `node security/release-evidence.mjs verify` must print `"ok": true`.
4. Only then, with verified staff and a chosen recovery policy, may `PROTECTED_CONTENT_ENABLED=true` be set. Startup re-verifies everything.

## Tests

`tests/release-authenticity.test.mjs` covers inclusion proofs for every leaf of trees of size 1 to 17, a full positive release, and fail-closed cases: changed bytes, rollback, a single witness, a duplicate signature, a forged log, an unpinned release key, a modified statement, a wrong index, a wrong origin, a stale observation, TLS fallback, a wrong log origin and a wrong schema. It also covers trust-policy validation (quorum, key-id binding, role reuse, non-Ed25519 keys) and confirms that the committed policy keeps the deployed gate closed. `tests/portal-release-integrity.test.mjs` covers SRI, the import map and CSP.
