# Owner-authorized volunteer reading release

## Authority and honest attribution

On 9 November 2026 (America/New_York), the owner supplied the repository's `content/materials/source-edition-1` URL for completing the volunteer platform and expressly instructed: **“Use an owner-authorized, AI-reviewed release.”** This is an explicit exception to the two-human-signature publication process for this reading release. No author/reviewer key, human identity, signature, legal approval, training certification or field authorization has been invented.

The owner also supplied YouTube video `dpQulJS-R50` for temporary use while the final issue videos are unfinished. All three issue pages label it as temporary, load no YouTube iframe before consent, and suppress the temporary source in production publication mode.

## Source review and reconciliation

The normalized source texts exist in the repository; the initial connected-account handoff incorrectly reported them unavailable. The source directory was missed during the initial inspection. Their presence and source status were verified on commit `a5eb39ed41750e245a07046be67089e2139d1496`.

The AI editorial review read the universal core, all twelve role playbooks, Garden/Cornerstone historical kits, campaign messaging, facilitator orientation and forms/templates. The review compared policy summaries with current `content/public/pages/{kirk-evers,garden,cornerstone}.html`, and orientation/forms with their actual application definitions. Original source metadata remains unreviewed; the raw archive was not automatically promoted to current guidance.

The release has nineteen separately versioned records:

- `universal-core`: the current Justice for All principle and three-issue scope replace the broader historical pillars.
- `role-network`, `role-digital`, `role-issue`, `role-canvass`, `role-phone`, `role-host`, `role-recruit`, `role-captain`, `role-ballot`, `role-voter`, `role-fundraising`, `role-skills`: all twelve roles, with current operating restrictions. Restricted-role first actions are preparation/practice. The personal-network guide removes its old private contact list and per-person political-concern notes. The fundraising guide was rewritten to prohibit solicitation/custody while contributions remain closed.
- `policy-kirk-evers`, `policy-garden`, `policy-cornerstone`: derived from the current campaign-page text, without importing unverified historical detail, guessed bills, benefits, enrollment programs or canonical domains. Kirk–Evers has its own current reading guide rather than a fictional source-edition kit.
- `first-hour-orientation`: matches the actual three-question account knowledge check and distinguishes completion from authorization.
- `forms-and-practice`: covers all twelve actual browser-local worksheets. It removes the old incident-narrative/roster collection pattern and explicitly excludes supporter identities, private evidence and signatures.
- `campaign-messaging`: current three-issue scope, claim levels, correction procedure and draft/publication boundaries; no extra launch policies or active donation invitation.

Internal document 00, unrelated policy kits 16–30, website/editorial input 34 and duplicate compiled manual 35 are excluded. The original normalized edition remains unchanged. Each current record retains exact source paths, source SHA-256 values and commit provenance, and links its sources for readers.

## Publication and security review

`content/materials/owner-release.json` records the literal owner instruction, reading-only scope, source commit, AI reviewer and a canonical SHA-256 of every complete current record (object-key order is normalized; body bytes and array order remain bound). `validateConfiguredMaterialRelease` accepts this explicitly attributed path only when all exact record bytes and revisions match that manifest. Missing/mixed modes, changed bodies/provenance/review actors, future/stale authorization, invented human review and activity-authorization claims fail closed. Ordinary records still require the existing two-party staff signatures; that path is preserved and tested.

This manifest relies on authorized Git/source/operator custody. It is not a cryptographic signature by the owner and does not protect against a malicious repository administrator who can change both code and the manifest. The owner expressly chose this workflow; that limitation is not hidden behind a claim of independent review.

Read access continues to require a verified volunteer session and a published, reviewed record. Bookmarks and reading acknowledgments remain bound to the current material revision/content digest. Publishing does not create activity modules, grant staff scopes, open mail signup, activate payments or enable protected narratives/attachments. No public asset/JavaScript bundle contains the volunteer library.

Validate with `npm run materials:verify`, unit/authorization/tamper tests, PostgreSQL integration and production builds. Test publication against the isolated release-validation branch before the new primary, then verify real hosted search, reading, download, bookmark and acknowledgment using a synthetic passkey account and remove that account afterward. Record the actual deployment and hosted outcome separately; preparation alone is not a live-publication claim.

## Actual hosted outcome

The release is published and verified on runtime commit `4599245d56a43c64653d229ee1e61dcb84bc3a8f`. All nineteen live body fingerprints matched the reviewed source; nineteen publication audit events exist. Real hosted passkey registration, library search/category filters, download, bookmark persistence, revision-bound reading acknowledgment, orientation, mobile reading and synthetic account closure passed. The three temporary video controls passed consent/disconnect/fallback checks. `docs/evidence/CONNECTED_RELEASE_20261109.json` records exact deployment IDs and the remaining disabled functions. No independent-human, legal, provider-playback or E2EESA certification claim is made.
