// Staff monthly-giving screens against the real API, PostgreSQL and portal build.
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { chromium } from 'playwright';
import { createApp } from '../../apps/api/src/app.mjs';
import { PostgresStore, databasePool } from '../../apps/api/src/postgres-store.mjs';
import { registerPortal } from '../../apps/api/src/static.mjs';
import { CardContributionStore } from '../../apps/api/src/card-contribution-store.mjs';
import { RecurringCardService, newRecoveryCode } from '../../apps/api/src/card-recurring-service.mjs';
import { MANUAL_CAPTURE_PROFILE } from '../../packages/core/stripe-manual-capture.mjs';
import { randomToken, tokenHash } from '../../packages/core/auth.mjs';
import { fixturePolicy, fixtureDonor, evidenceContent, evidence } from '../helpers/treasury-fixtures.mjs';

const base = process.env.TEST_DATABASE_URL;
if (!base) {
  console.log('Monthly giving browser journey needs the isolated TEST_DATABASE_URL.');
  process.exit(0);
}
assert(['localhost', '127.0.0.1'].includes(new URL(base).hostname));
const db = 'g28_monthly_browser_' + randomBytes(5).toString('hex'),
  admin = databasePool(base),
  url = new URL(base);
url.pathname = '/' + db;
await admin.query('CREATE DATABASE ' + db);
const pool = databasePool(url.href),
  store = new PostgresStore(pool),
  owner = randomUUID(),
  ownerKey = tokenHash(owner),
  token = randomToken(),
  csrf = randomToken(),
  now = Date.now(),
  origin = 'http://localhost:4488';
const config = {
    staffIdentity: true,
    adminLoginReady: true,
    adminOwnerEmailKey: ownerKey,
    portalOrigin: origin,
    publicOrigin: 'http://localhost:4487',
    treasuryKey: randomBytes(32).toString('base64'),
  },
  app = createApp({ store, config }),
  cards = new CardContributionStore({ store, config }),
  recurring = new RecurringCardService({ cards });
registerPortal(app, origin);
let browser;
try {
  for (const file of (await readdir('db/migrations')).filter((x) => x.endsWith('.sql')).sort())
    await pool.query(await readFile('db/migrations/' + file, 'utf8'));
  await pool.query(
    "INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'synthetic',now(),'synthetic')",
    [owner, ownerKey],
  );
  const hash = tokenHash(token);
  await pool.query(
    'INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',
    [hash, owner, csrf, new Date(now + 86400000)],
  );
  await store.withStaffSecurity(owner, (s) => {
    s.credentials = [{ id: 'fixture' }];
    s.sessions = { [hash]: { credentialId: 'fixture', expires: now + 900000 } };
  });
  const staff = await store.session(hash, now);
  await store.saveFinanceEvidence(
    { id: randomUUID(), filename: 'synthetic.txt', mediaType: 'text/plain', content: Buffer.from(evidenceContent).toString('base64') },
    owner,
    config.treasuryKey,
  );
  const parent = fixturePolicy(now);
  parent.electionLimits = { primary: 100000, general: 100000 };
  await store.saveFinancePolicy(parent, owner, now);
  const donor = { ...fixtureDonor(), occupation: 'Synthetic occupation', employer: 'Synthetic employer' };
  await store.saveFinanceDonor(donor, 0, owner, config.treasuryKey);
  await cards.savePolicy(staff, {
    id: randomUUID(),
    version: 1,
    profile: MANUAL_CAPTURE_PROFILE,
    parentPolicyId: parent.id,
    parentPolicyVersion: 1,
    validUntil: parent.validUntil,
    electionEnds: {
      primary: new Date(now + 25 * 86400000).toISOString(),
      general: new Date(now + 25 * 86400000).toISOString(),
    },
    maxInstallments: 12,
    maxSchedulesPerDonor: 12,
    reservationSeconds: 300,
    termsVersion: '2026-11-16-synthetic-only',
    allowedCardCountries: ['US'],
    evidenceDigest: evidence,
  });
  // A donor-saved TEST card with a signed setup receipt, verified with a fake processor.
  async function savedCard(replacesMandateId = null) {
    const suffix = randomBytes(8).toString('hex'),
      request = {
        id: randomUUID(),
        clientReference: 'attempt_' + randomBytes(16).toString('hex'),
        amountCents: 2500,
        frequency: 'monthly',
        election: 'general',
        endAt: new Date(now + 20 * 86400000).toISOString(),
        maxInstallments: 3,
        termsVersion: '2026-11-16-synthetic-only',
        consentDigest: 'c'.repeat(64),
        attestations: { eligibleResidency: true, ownFunds: true, age18: true, notFederalContractor: true, personalCreditCard: true },
      };
    await recurring.beginSetup(request, { recoveryCode: newRecoveryCode(), replacesMandateId });
    await cards.recordSetup(request.id, 'cs_test_' + suffix);
    await pool.query(
      "INSERT INTO g28.stripe_webhook_receipts(event_id,event_sha256,session_id,livemode,event_type) VALUES($1,$2,$3,false,'checkout.session.completed')",
      ['evt_synthetic' + suffix, 'e'.repeat(64), 'cs_test_' + suffix],
    );
    await cards.verifyEnrollment(staff, request.id, {
      verified: async () => ({
        sessionId: 'cs_test_' + suffix,
        setupIntentId: 'seti_' + suffix,
        customerId: 'cus_' + suffix,
        paymentMethodId: 'pm_' + suffix,
        card: { funding: 'credit', issuerCountry: 'US' },
        billing: {
          name: 'SYNTHETIC_MONTHLY_BROWSER_DONOR',
          email: 'synthetic@example.test',
          street: '1 Synthetic Street',
          city: 'Test',
          region: 'ZZ',
          postal: '00000',
          country: 'US',
          occupation: 'Synthetic occupation',
          employer: 'Synthetic employer',
        },
      }),
    });
    return request;
  }
  const first = await savedCard();
  await app.listen({ host: 'localhost', port: 4488 });
  browser = await chromium.launch({
    headless: true,
    ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH, args: ['--no-sandbox'] }
      : {}),
  });
  const context = await browser.newContext({ baseURL: origin });
  await context.addCookies([{ name: 'g28-local', value: token, url: origin, httpOnly: true, sameSite: 'Lax' }]);
  const page = await context.newPage(),
    errors = [],
    external = [],
    posts = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('request', (r) => {
    if (new URL(r.url()).origin !== origin) external.push(r.url());
    if (r.method() === 'POST' && r.url().includes('/card/')) posts.push(new URL(r.url()).pathname);
  });
  await page.goto('/admin');
  await page.getByRole('heading', { name: 'Monthly card schedules.' }).waitFor();
  const card = page.locator(`[data-enrollment="${first.id}"]`);
  await card.waitFor();
  assert.equal(await page.getByText('SYNTHETIC_MONTHLY_BROWSER_DONOR').count(), 0, 'billing stays closed until opened');
  await card.getByRole('button', { name: 'Review billing identity' }).click();
  await page.getByText('SYNTHETIC_MONTHLY_BROWSER_DONOR').waitFor();

  // A wrong confirmation phrase never reaches the server.
  const before = posts.length;
  await card.getByLabel('Documented contributor ID').fill(donor.id);
  await card.getByLabel('Contributor revision').fill('1');
  await card.getByLabel('Documentary evidence').selectOption(evidence);
  await card.getByLabel('Type “approve exact documented card mandate”').fill('approve');
  await card.getByRole('button', { name: 'Approve schedule' }).click();
  assert.equal(posts.length, before);
  await card.getByLabel('Type “approve exact documented card mandate”').fill('approve exact documented card mandate');
  await card.getByRole('button', { name: 'Approve schedule' }).click();
  await page.getByText('Schedule approved.').waitFor();

  // The due queue comes from the operational processing.
  await recurring.processDue();
  await page.reload();
  await page.getByRole('heading', { name: 'Due installments (1)' }).waitFor();
  const dueItem = page.locator('[data-due]').first();
  await dueItem.getByLabel('Type “reserve exact due installment”').fill('reserve exact due installment');
  await dueItem.getByRole('button', { name: 'Reserve installment' }).click();
  await page.getByText(/Installment reserved against current limits/).waitFor();
  const period = page.locator('[data-period]').first();
  await period.getByLabel('Type “prepare exact authorize”').fill('prepare exact authorize');
  await period.getByRole('button', { name: 'Prepare authorize' }).click();
  await page.getByText('Command recorded. Dispatch it once below.').waitFor();
  const command = page.locator('[data-command]').first();
  await command.getByLabel('Type “dispatch exact TEST command once”').fill('dispatch exact TEST command once');
  await command.getByRole('button', { name: 'Dispatch once' }).click();
  await page.getByRole('alert').filter({ hasText: /TEST processor actions are disabled/ }).waitFor();

  // Replacement card approval.
  const mandateId = (await pool.query('SELECT id FROM g28.card_mandates')).rows[0].id;
  await pool.query("UPDATE g28.card_periods SET reservation_active=false,status='voided'");
  await savedCard(mandateId);
  await page.reload();
  const schedule = page.locator(`[data-mandate="${mandateId}"]`);
  await schedule.getByLabel('Documentary evidence').selectOption(evidence);
  await schedule
    .getByLabel('Type “replace exact saved card for future installments”')
    .fill('replace exact saved card for future installments');
  await schedule.getByRole('button', { name: 'Approve card replacement' }).click();
  await page.getByText('Saved card replaced for future installments.').waitFor();
  await schedule.getByText('v2').waitFor();
  await schedule.getByLabel('Type “cancel exact future schedule”').fill('cancel exact future schedule');
  await schedule.getByRole('button', { name: 'Cancel schedule' }).click();
  await page.getByText('Schedule cancelled. No new authorizations or captures.').waitFor();
  assert.equal((await pool.query('SELECT status FROM g28.card_mandates WHERE id=$1', [mandateId])).rows[0].status, 'cancelled');
  await page.setViewportSize({ width: 360, height: 800 });
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  assert.deepEqual(errors, []);
  assert.deepEqual(external, []);
  console.log('Monthly giving staff browser: billing review, guarded approval, due queue, reserve, prepare, disabled dispatch, card replacement, cancellation, mobile and zero external egress passed.');
} finally {
  await browser?.close();
  await app.close();
  await store.close();
  await pool.end().catch(() => {});
  await admin.query('DROP DATABASE ' + db);
  await admin.end();
}
