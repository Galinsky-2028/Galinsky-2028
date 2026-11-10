import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { readFile, readdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright';
import { createApp } from '../../apps/api/src/app.mjs';
import { PostgresStore, databasePool } from '../../apps/api/src/postgres-store.mjs';
import { registerPortal } from '../../apps/api/src/static.mjs';
import { randomToken, tokenHash } from '../../packages/core/auth.mjs';
import { fixtureDonor, evidenceContent, evidence } from '../helpers/treasury-fixtures.mjs';
const base = process.env.TEST_DATABASE_URL;
if (!base) {
  console.log('Treasury browser journey needs the isolated TEST_DATABASE_URL.');
  process.exit(0);
}
assert(['localhost', '127.0.0.1'].includes(new URL(base).hostname));
const db = 'g28_finance_browser_' + randomBytes(5).toString('hex'),
  admin = databasePool(base),
  url = new URL(base);
url.pathname = '/' + db;
await admin.query('CREATE DATABASE ' + db);
const pool = databasePool(url.href),
  store = new PostgresStore(pool),
  account = randomUUID(),
  ownerKey = tokenHash(account),
  token = randomToken(),
  csrf = randomToken(),
  now = Date.now(),
  origin = 'http://localhost:4478',
  dir = await mkdtemp(join(tmpdir(), 'g28-finance-browser-'));
const config = {
    staffIdentity: true,
    adminLoginReady: true,
    adminOwnerEmailKey: ownerKey,
    portalOrigin: origin,
    publicOrigin: 'http://localhost:4477',
    treasuryKey: randomBytes(32).toString('base64'),
  },
  app = createApp({ store, config });
registerPortal(app, origin);
let browser;
try {
  for (const file of (await readdir('db/migrations')).filter((x) => x.endsWith('.sql')).sort())
    await pool.query(await readFile('db/migrations/' + file, 'utf8'));
  await pool.query(
    "INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'synthetic',now(),'synthetic')",
    [account, ownerKey],
  );
  const hash = tokenHash(token);
  await pool.query(
    'INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',
    [hash, account, csrf, new Date(now + 86400000)],
  );
  await store.withStaffSecurity(account, (s) => {
    s.credentials = [{ id: 'fixture' }];
    s.sessions = { [hash]: { credentialId: 'fixture', expires: now + 900000 } };
  });
  await app.listen({ host: 'localhost', port: 4478 });
  browser = await chromium.launch({
    headless: true,
    ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH, args: ['--no-sandbox'] }
      : {}),
  });
  const context = await browser.newContext({ baseURL: origin, acceptDownloads: true });
  await context.addCookies([
    { name: 'g28-local', value: token, url: origin, httpOnly: true, sameSite: 'Lax' },
  ]);
  const page = await context.newPage(),
    errors = [],
    external = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('request', (r) => {
    if (new URL(r.url()).origin !== origin) external.push(r.url());
  });
  await page.goto('/admin');
  await page.getByRole('heading', { name: 'Campaign accounting.', exact: true }).waitFor();
  const section = (name) =>
    page.locator('details').filter({ has: page.locator('summary', { hasText: name }) });
  const files = section('Private source documents');
  await files.locator('summary').first().click();
  await files
    .locator('input[type=file]')
    .setInputFiles({
      name: 'synthetic-evidence.txt',
      mimeType: 'text/plain',
      buffer: Buffer.from(evidenceContent),
    });
  await files.getByRole('button', { name: 'Store private source document' }).click();
  await page.getByText(/Private evidence stored. Reference/).waitFor();
  const rules = section('Treasurer-approved rules and accounting mapping');
  await rules
    .getByLabel('Rules valid until (UTC)')
    .fill(new Date(now + 30 * 86400000).toISOString().slice(0, -1));
  await rules.getByLabel('Approved rules evidence').selectOption(evidence);
  await rules.getByLabel('Primary election aggregate limit (USD)').fill('1000.00');
  await rules.getByLabel('General election aggregate limit (USD)').fill('1000.00');
  await rules.getByLabel('Approved remedy deadline (days)').fill('30');
  await rules.locator('select[name=deadlineBasis]').selectOption('received_at');
  await rules.getByLabel('Minimum follow-up interval (days)').fill('3');
  await rules.getByLabel('Maximum follow-ups', { exact: true }).fill('2');
  await rules.getByLabel('Source identifier', { exact: true }).fill('cash-test');
  await rules
    .getByLabel('Actual accounting/import system identifier')
    .fill('synthetic-browser-accounting');
  await rules.getByLabel('Approved accounting mapping evidence').selectOption(evidence);
  await rules
    .getByLabel('Type “approve these treasury rules”')
    .fill('approve these treasury rules');
  await rules.getByRole('button', { name: 'Approve and save next rules version' }).click();
  await page.getByText('Approved rules saved as an immutable new version.').waitFor();
  const contributor = section('Source-verified contributor identity');
  await contributor.locator('summary').first().click();
  const d = fixtureDonor();
  await contributor.getByLabel('Documented legal name').fill(d.name);
  for (const field of ['street', 'city', 'region', 'postal', 'country'])
    await contributor.getByLabel(field, { exact: true }).fill(d[field]);
  await contributor.getByLabel('Contributor identity source').selectOption(evidence);
  await contributor.getByRole('button', { name: 'Save verified contributor revision' }).click();
  const saved = page.getByText(/Contributor reference .* revision 1/);
  await saved.waitFor();
  const donorId = (await saved.innerText()).match(/Contributor reference ([a-f0-9-]{36})/)[1];
  const journal = section('Append a financial source event');
  await journal.locator('summary').first().click();
  await journal.locator('select[name=source]').selectOption('cash-test');
  await journal
    .getByLabel('Immutable source or accounting correction reference')
    .fill('synthetic-browser-gift');
  await journal.getByLabel('Amount (USD)', { exact: true }).fill('10.00');
  await journal.getByLabel('Documented contributor reference').fill(donorId);
  const received = new Date(now - 60000).toISOString().slice(0, -1);
  await journal.getByLabel('Made date/time (UTC)').fill(received);
  await journal.getByLabel('Received date/time (UTC)').fill(received);
  await journal.getByLabel('Source or final processor outcome evidence').selectOption(evidence);
  await journal
    .getByLabel('Type “record verified source evidence”')
    .fill('record verified source evidence');
  await journal.getByRole('button', { name: 'Append verified financial event' }).click();
  await page.getByText(/Review exceptions: missing_information/).waitFor();
  const gift = (await pool.query("SELECT state FROM g28.treasury_gifts WHERE source='cash-test'"))
    .rows[0].state;
  assert.equal(gift.grossCents, 1000);
  await journal.getByLabel('Event type').selectOption('fee');
  await journal.getByLabel('Original gift').selectOption(gift.id);
  await journal.locator('select[name=source]').selectOption('cash-test');
  await journal
    .getByLabel('Immutable source or accounting correction reference')
    .fill('synthetic-browser-fee');
  await journal.getByLabel('Amount (USD)', { exact: true }).fill('1.00');
  await journal.getByRole('button', { name: 'Append verified financial event' }).click();
  await page.getByText('Fees $1.00', { exact: false }).waitFor();
  const report = section('Approved accounting export');
  await report.locator('summary').first().click();
  await report
    .getByLabel('Period begins (UTC, inclusive)')
    .fill(new Date(now - 86400000).toISOString().slice(0, -1));
  await report
    .getByLabel('Period ends (UTC, exclusive)')
    .fill(new Date(now + 86400000).toISOString().slice(0, -1));
  await report.getByLabel('Explicitly include authorized contributor identity fields').check();
  await report
    .getByLabel('Type “export approved treasury report”')
    .fill('export approved treasury report');
  const pending = page.waitForEvent('download');
  await report.getByRole('button', { name: 'Download audited accounting export' }).click();
  const download = await pending,
    file = join(dir, 'report.json');
  await download.saveAs(file);
  const exported = JSON.parse(await readFile(file, 'utf8'));
  assert.equal(exported.totals.netCents, 900);
  assert.equal(exported.records.length, 2);
  assert.equal(exported.environment, 'test');
  assert.equal(exported.system, 'synthetic-browser-accounting');
  assert.equal(exported.includesIdentity, true);
  const stored = JSON.stringify(
    (
      await pool.query(
        'SELECT encrypted_envelope FROM g28.treasury_donors UNION ALL SELECT encrypted_envelope FROM g28.treasury_evidence',
      )
    ).rows,
  );
  assert(!stored.includes(d.street));
  assert(!stored.includes(evidenceContent));
  await page.setViewportSize({ width: 360, height: 800 });
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  assert.deepEqual(errors, []);
  assert.deepEqual(external, []);
  console.log(
    'Treasury browser: private evidence, approved source policy, contributor revision, cash/fee journal, audited identity export, mobile and zero external egress passed.',
  );
} finally {
  await browser?.close();
  await app.close();
  await store.close();
  await admin.query('DROP DATABASE ' + db);
  await admin.end();
  await rm(dir, { recursive: true, force: true });
}
