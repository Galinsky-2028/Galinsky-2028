import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  donorCapability,
  donorAuthority,
  donorCsrf,
  validDonorCsrf,
  donorCookie,
  stripeDonorRecord,
  stripeDonorPortal,
  donorLoginUrl,
  DONOR_COOKIE,
} from '../packages/core/stripe-donor-service.mjs';
import { checkoutNonceKey, stripeSettings } from '../packages/core/stripe-web-checkout.mjs';
import { createPrivatePreviewServer } from '../apps/web/private-preview.mjs';
const env = {
    PREVIEW_ACCESS_PASSWORD: 'synthetic-private-preview-passphrase',
    G28_PUBLIC_MODE: 'preview',
    G28_STRIPE_TEST_ENABLED: 'true',
    STRIPE_SECRET_KEY: 'sk_' + 'test_' + 'syntheticdonorservice00000',
    G28_STRIPE_RETURN_ORIGIN: 'https://preview.example.test',
    DONATIONS_ENABLED: 'false',
    G28_STRIPE_DONOR_PORTAL_CONFIGURATION: 'bpc_synthetic123',
  },
  settings = stripeSettings(env),
  secret = checkoutNonceKey(env.STRIPE_SECRET_KEY);
const reference = {
  clientRef: 'attempt_' + 'a'.repeat(32),
  sessionId: 'cs_test_syntheticdonor12345',
};
const row = {
  amount_cents: 2500,
  election: 'general',
  payment_state: 'paid',
  livemode: false,
  terms_version: 'synthetic',
};
const checkout = {
  id: reference.sessionId,
  client_reference_id: reference.clientRef,
  livemode: false,
  currency: 'usd',
  amount_total: 2500,
  payment_status: 'paid',
  customer: 'cus_synthetic123',
  payment_intent: {
    latest_charge: { receipt_url: 'https://pay.stripe.com/receipts/payment/synthetic' },
  },
};
const store = {
  donorIntent: async (ref, id) =>
    ref === reference.clientRef && id === reference.sessionId ? row : null,
};
test('donor capabilities bind one checkout without volunteer accounts, expire and separate CSRF contexts', () => {
  const now = 1700000000000,
    cap = donorCapability(secret, reference, now);
  assert.deepEqual(donorAuthority(secret, cap, now), {
    ...reference,
    expires: now + 30 * 86400000,
  });
  assert.equal(donorAuthority(secret, cap, now + 31 * 86400000), null);
  assert.equal(donorAuthority(secret, cap + 'tampered', now), null);
  assert.equal(donorAuthority(Buffer.alloc(32), cap, now), null);
  assert.match(donorCookie(cap), /HttpOnly; Secure; SameSite=Lax/);
  const token = donorCsrf(secret, cap, now);
  assert(validDonorCsrf(secret, cap, token, now));
  assert(!validDonorCsrf(secret, cap, token, now + 901000));
  assert(!validDonorCsrf(secret, cap + 'other', token, now));
  assert.equal(
    donorLoginUrl('https://billing.stripe.com/p/login/synthetic123'),
    'https://billing.stripe.com/p/login/synthetic123',
  );
  assert.equal(donorLoginUrl('https://billing.stripe.com.evil.test/p/login/a'), null);
});
test('donor receipt and portal verify recorded payment, exact Stripe identity and provider destination; no campaign subscription is created', async () => {
  const calls = [],
    transport = async (url, options) => {
      calls.push({ url, options });
      return new Response(
        JSON.stringify(
          url.includes('/billing_portal/')
            ? {
                url: 'https://billing.stripe.com/p/session/synthetic',
                customer: checkout.customer,
                configuration: 'bpc_synthetic123',
                livemode: false,
              }
            : checkout,
        ),
      );
    };
  const record = await stripeDonorRecord({ settings, authority: reference, store, transport });
  assert(record.paid);
  assert.equal(record.recurring, false);
  assert.equal(record.receipt, checkout.payment_intent.latest_charge.receipt_url);
  const url = await stripeDonorPortal({
    settings,
    authority: reference,
    store,
    transport,
    configuration: env.G28_STRIPE_DONOR_PORTAL_CONFIGURATION,
  });
  assert.equal(new URL(url).hostname, 'billing.stripe.com');
  const post = calls.find((c) => c.options.method === 'POST'),
    form = new URLSearchParams(post.options.body);
  assert.equal(form.get('customer'), checkout.customer);
  assert.equal(form.get('configuration'), 'bpc_synthetic123');
  assert.equal(form.get('return_url'), settings.origin + '/donate/manage');
  assert(!calls.some((c) => /\/subscriptions|\/charges|\/refunds|checkout\/sessions$/.test(c.url)));
  await assert.rejects(
    stripeDonorRecord({
      settings,
      authority: { ...reference, sessionId: 'cs_test_somebodyelse123' },
      store,
      transport,
    }),
    (e) => e.code === 'donor_forbidden',
  );
  await assert.rejects(
    stripeDonorRecord({
      settings,
      authority: reference,
      store,
      transport: async () =>
        new Response(
          JSON.stringify({
            ...checkout,
            customer: 'cus_foreign',
            client_reference_id: 'attempt_' + 'b'.repeat(32),
          }),
        ),
    }),
    (e) => e.code === 'donor_identity_mismatch',
  );
  await assert.rejects(
    stripeDonorPortal({
      settings,
      authority: reference,
      store,
      transport: async (url) =>
        new Response(
          JSON.stringify(
            url.includes('/billing_portal/')
              ? {
                  url: 'https://evil.test/',
                  customer: checkout.customer,
                  configuration: 'bpc_synthetic123',
                  livemode: false,
                }
              : checkout,
          ),
        ),
      configuration: 'bpc_synthetic123',
    }),
    (e) => e.code === 'invalid_donor_portal',
  );
  const pending = await stripeDonorRecord({
    settings,
    authority: reference,
    store: { donorIntent: async () => ({ ...row, payment_state: 'pending' }) },
    transport,
  });
  assert.equal(pending.paid, false);
  assert.equal(pending.receipt, null);
});
test('real donor HTTP page is separately authorized and private; portal POST rejects cross-origin, stale CSRF and injected customer IDs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'g28-donor-http-'));
  await writeFile(join(dir, 'index.html'), '<main>Public-safe fixture</main>');
  let calls = 0;
  const server = createPrivatePreviewServer({
    directory: dir,
    env,
    stripeStore: store,
    stripeTransport: async (url) => {
      calls++;
      return new Response(
        JSON.stringify(
          url.includes('/billing_portal/')
            ? {
                url: 'https://billing.stripe.com/p/session/synthetic',
                customer: checkout.customer,
                configuration: 'bpc_synthetic123',
                livemode: false,
              }
            : checkout,
        ),
      );
    },
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port,
    cap = donorCapability(secret, reference),
    csrf = donorCsrf(secret, cap),
    auth = 'Basic ' + Buffer.from('preview:' + env.PREVIEW_ACCESS_PASSWORD).toString('base64');
  const request = (
    path,
    { cookie = cap, origin = settings.origin, body, authorization = auth } = {},
  ) =>
    new Promise((resolve, reject) => {
      const req = httpRequest(
        {
          hostname: '127.0.0.1',
          port,
          path,
          method: body === undefined ? 'GET' : 'POST',
          headers: {
            Authorization: authorization,
            Origin: origin,
            ...(cookie ? { Cookie: DONOR_COOKIE + '=' + cookie } : {}),
            ...(body === undefined ? {} : { 'Content-Type': 'application/x-www-form-urlencoded' }),
          },
        },
        (res) => {
          let text = '';
          res.on('data', (b) => (text += b));
          res.on('end', () =>
            resolve({ status: res.statusCode, headers: res.headers, body: text }),
          );
        },
      );
      req.on('error', reject);
      req.end(body);
    });
  try {
    const page = await request('/donate/manage');
    assert.equal(page.status, 200);
    assert(page.body.includes('Open Stripe receipt'));
    assert(page.body.includes('No volunteer account is needed'));
    assert.match(page.headers['cache-control'], /private, no-store/);
    assert(!page.body.includes(checkout.customer));
    assert(!page.body.includes(env.STRIPE_SECRET_KEY));
    const before = calls;
    assert.equal((await request('/donate/manage', { cookie: 'tampered' })).status, 200);
    assert.equal(calls, before);
    assert.equal((await request('/donate/manage', { authorization: '' })).status, 401);
    const body = new URLSearchParams({ form_token: csrf }).toString();
    assert.equal(
      (await request('/donate/manage/portal', { body, origin: 'https://evil.test' })).status,
      403,
    );
    assert.equal(
      (await request('/donate/manage/portal', { body: 'form_token=invalid' })).status,
      403,
    );
    assert.equal(
      (await request('/donate/manage/portal', { body: body + '&customer=cus_foreign' })).status,
      403,
    );
    const portal = await request('/donate/manage/portal', { body });
    assert.equal(portal.status, 303);
    assert.equal(portal.headers.location, 'https://billing.stripe.com/p/session/synthetic');
    const beforeForget = calls;
    const forgotten = await request('/donate/manage/forget', { body });
    assert.equal(forgotten.status, 303);
    assert.match(forgotten.headers['set-cookie'][0], /Max-Age=0/);
    assert.equal(calls, beforeForget);
  } finally {
    await new Promise((r) => server.close(r));
    await rm(dir, { recursive: true, force: true });
  }
});
