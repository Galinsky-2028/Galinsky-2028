import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createPrivatePreviewServer } from '../apps/web/private-preview.mjs';
import { MANUAL_CAPTURE_PROFILE } from '../packages/core/stripe-manual-capture.mjs';
import { RECOVERY_CODE } from '../apps/api/src/card-recurring-service.mjs';
import {
  monthlyEnabled,
  monthlyCapability,
  monthlyAuthority,
  consentDigest,
} from '../apps/web/recurring-donor.mjs';
import { stripeSettings } from '../packages/core/stripe-web-checkout.mjs';

const password = 'test-preview-password-long-2026',
  ORIGIN = 'https://preview.example.test';
const env = (extra = {}) => ({
  PREVIEW_ACCESS_PASSWORD: password,
  G28_PUBLIC_MODE: 'preview',
  G28_STRIPE_TEST_ENABLED: 'true',
  STRIPE_SECRET_KEY: 'sk_test_12345678901234567890',
  G28_STRIPE_RETURN_ORIGIN: ORIGIN,
  G28_TREASURY_SANDBOX_ACTIONS_ENABLED: 'true',
  G28_RECURRING_TEST_ENABLED: 'true',
  ...extra,
});
const auth = { authorization: 'Basic ' + Buffer.from('preview:' + password).toString('base64') };
const form = (fields) => new URLSearchParams(fields).toString();
const attest = {
  eligibleResidency: 'yes',
  ownFunds: 'yes',
  age18: 'yes',
  notFederalContractor: 'yes',
  personalCreditCard: 'yes',
};

function fakeService() {
  const s = {
    enrollments: new Map(),
    codes: new Map(),
    cancelled: [],
    observed: [],
    period: randomUUID(),
    mandate: null,
    async publicRules() {
      return {
        termsVersion: '2026-11-15-synthetic-only',
        maxInstallments: 6,
        cutoffs: { primary: '2027-03-01T00:00:00.000Z', general: '2027-06-01T00:00:00.000Z' },
      };
    },
    async beginSetup(request, { recoveryCode, replacesMandateId }) {
      assert.match(recoveryCode, RECOVERY_CODE);
      const old = s.enrollments.get(request.clientReference);
      if (old) {
        assert.deepEqual(old.request, request, 'a replay carries the identical consent');
        return { fresh: false };
      }
      s.enrollments.set(request.clientReference, { request, replacesMandateId });
      s.codes.set(recoveryCode, request);
      return { fresh: true };
    },
    cards: { async recordSetup(id, sessionId) { s.lastSetup = { id, sessionId }; } },
    async recover(code) {
      const r = s.codes.get(code);
      return r ? { enrollmentId: r.id, clientReference: r.clientReference } : null;
    },
    owned(id, ref) {
      const e = [...s.enrollments.values()].find((x) => x.request.id === id);
      if (!e || e.request.clientReference !== ref)
        throw Object.assign(Error('no'), { code: 'donor_authority', status: 403 });
      return e;
    },
    async donorView(id, ref) {
      const e = s.owned(id, ref);
      return {
        enrollment: { ...e.request, status: 'verified' },
        schedule: s.mandate,
        mandateId: s.mandate ? 'mandate-id' : undefined,
        installments: s.mandate ? [{ installment: 0, state: 'waiting for your bank confirmation' }] : [],
        confirmation: s.mandate ? { periodId: s.period } : null,
      };
    },
    async donorCancel(id, ref) {
      s.owned(id, ref);
      s.cancelled.push(id);
      return { schedule: 'cancelled' };
    },
    async confirmationTarget(id, ref, periodId) {
      s.owned(id, ref);
      if (periodId !== s.period)
        throw Object.assign(Error('no'), { code: 'card_confirmation_unavailable', status: 409 });
      return {
        periodId,
        paymentIntentId: 'pi_syntheticBBBB',
        approval: {
          attemptId: randomUUID(),
          periodId,
          customerId: 'cus_syntheticAAAA',
          paymentMethodId: 'pm_syntheticAAAA',
          amountCents: 2500,
          environment: 'test',
          policyDigest: 'a'.repeat(64),
          mandateDigest: 'b'.repeat(64),
          confirmationMode: 'on_session',
          expiresAt: new Date().toISOString(),
        },
      };
    },
    async recordConfirmationObservation(periodId, seen) {
      s.observed.push({ periodId, status: seen.status });
    },
  };
  return s;
}

async function start(t, { service = fakeService(), envExtra = {} } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'g28-monthly-'));
  await writeFile(join(dir, 'index.html'), '<!doctype html><title>x</title>');
  const calls = [];
  const transport = async (url, init = {}) => {
    calls.push({ url, init });
    if (url === 'https://api.stripe.com/v1/checkout/sessions') {
      const b = new URLSearchParams(init.body);
      return new Response(
        JSON.stringify({
          id: 'cs_test_SYNTHETICSETUP' + calls.length,
          object: 'checkout.session',
          mode: 'setup',
          livemode: false,
          client_reference_id: b.get('client_reference_id'),
          metadata: {
            g28_profile: MANUAL_CAPTURE_PROFILE,
            g28_enrollment: b.get('metadata[g28_enrollment]'),
            g28_consent: b.get('metadata[g28_consent]'),
            terms_version: b.get('metadata[terms_version]'),
          },
          url: 'https://checkout.stripe.com/c/setup/synthetic',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    if (url.endsWith('/confirm'))
      return new Response(
        JSON.stringify({
          ...intent('requires_action', service),
          next_action: {
            type: 'redirect_to_url',
            redirect_to_url: { url: 'https://hooks.stripe.com/3d_secure/synthetic' },
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    return new Response(JSON.stringify(intent('requires_capture', service)), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  const server = createPrivatePreviewServer({
    directory: dir,
    env: env(envExtra),
    stripeTransport: transport,
    monthlyService: service,
  });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  t.after(async () => {
    await new Promise((ok) => server.close(ok));
    await rm(dir, { recursive: true, force: true });
  });
  return { root: 'http://127.0.0.1:' + server.address().port, calls, service };
}
let lastApproval = null;
function intent(status, service) {
  return {
    id: 'pi_syntheticBBBB',
    object: 'payment_intent',
    livemode: false,
    capture_method: 'manual',
    currency: 'usd',
    amount: 2500,
    customer: 'cus_syntheticAAAA',
    payment_method: 'pm_syntheticAAAA',
    status,
    amount_capturable: status === 'requires_capture' ? 2500 : 0,
    amount_received: 0,
    metadata: lastApproval
      ? {
          g28_profile: MANUAL_CAPTURE_PROFILE,
          g28_attempt: lastApproval.attemptId,
          g28_period: lastApproval.periodId,
          g28_policy: lastApproval.policyDigest,
          g28_mandate: lastApproval.mandateDigest,
          g28_confirmation: 'on_session',
        }
      : {},
  };
}
const post = (root, path, body, headers = {}) =>
  fetch(root + path, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      ...auth,
      origin: ORIGIN,
      'content-type': 'application/x-www-form-urlencoded',
      ...headers,
    },
    body,
  });

test('monthly giving stays closed without every TEST flag, and in production mode', async (t) => {
  const settings = stripeSettings(env());
  assert.equal(monthlyEnabled(env(), settings), true);
  for (const missing of ['G28_RECURRING_TEST_ENABLED', 'G28_TREASURY_SANDBOX_ACTIONS_ENABLED'])
    assert.equal(monthlyEnabled(env({ [missing]: 'false' }), settings), false, missing);
  assert.equal(monthlyEnabled(env({ G28_PUBLIC_MODE: 'production' }), settings), false);
  assert.equal(
    monthlyEnabled(env(), { ...settings, secretKey: 'sk_live_12345678901234567890' }),
    false,
  );
  const { root } = await start(t, { envExtra: { G28_RECURRING_TEST_ENABLED: 'false' } });
  const r = await fetch(root + '/donate/monthly', { headers: auth });
  assert.equal(r.status, 503);
  assert.equal((await fetch(root + '/donate/monthly')).status, 401, 'preview password still applies');
});

test('setup shows the schedule, needs every statement, binds a recovery code and is replay-safe', async (t) => {
  const { root, calls, service } = await start(t);
  const page = await fetch(root + '/donate/monthly', { headers: auth });
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-security-policy'), /script-src 'none'/);
  const html = await page.text();
  assert.match(html, /Stripe test mode/);
  assert.match(html, /No gift is collected after 2027-06-01/);
  assert.equal((html.match(/type="checkbox"/g) || []).length, 6);
  assert.equal((html.match(/<option /g) || []).length, 6, 'months are limited by the published policy');
  const token = html.match(/name="form_token" value="([^"]+)"/)[1];
  const good = { form_token: token, amount: '25', months: '6', agree: 'yes', ...attest };

  const missing = await post(root, '/donate/monthly/setup', form({ ...good, age18: '' }));
  assert.equal(missing.status, 400);
  assert.equal((await post(root, '/donate/monthly/setup', form({ ...good, months: '7' }))).status, 400);
  assert.equal((await post(root, '/donate/monthly/setup', form({ ...good, amount: '25.50' }))).status, 400);
  assert.equal(
    (await post(root, '/donate/monthly/setup', form(good), { origin: 'https://evil.example' })).status,
    403,
  );
  assert.equal(calls.length, 0, 'nothing reaches Stripe for refused forms');

  const first = await post(root, '/donate/monthly/setup', form(good));
  assert.equal(first.status, 200);
  const cookie = first.headers.get('set-cookie');
  assert.match(cookie, /^__Host-g28-monthly=[^;]+; Path=\/donate\/monthly; HttpOnly; Secure; SameSite=Lax/);
  const shown = await first.text();
  const code = shown.match(/G28R-[A-Z0-9-]+/)[0];
  assert.match(code, RECOVERY_CODE);
  assert.match(shown, /href="https:\/\/checkout\.stripe\.com\/c\/setup\/synthetic"/);
  const sent = new URLSearchParams(calls[0].init.body);
  assert.equal(sent.get('mode'), 'setup');
  assert.equal(sent.get('success_url'), ORIGIN + '/donate/monthly/manage');
  const [request] = [...service.enrollments.values()].map((x) => x.request);
  assert.equal(request.amountCents, 2500);
  assert.equal(request.frequency, 'monthly');
  assert.equal(request.election, 'general');
  assert.equal(request.maxInstallments, 6);
  assert.equal(request.endAt, '2027-06-01T00:00:00.000Z');
  assert.equal(request.consentDigest, consentDigest(request));
  assert.equal(service.lastSetup.id, request.id);

  const replay = await post(root, '/donate/monthly/setup', form(good));
  assert.equal(replay.status, 200);
  const replayText = await replay.text();
  assert.match(replayText, /already submitted/);
  assert.doesNotMatch(replayText, /G28R-/, 'a replay never shows a new recovery code');
  assert.equal(service.enrollments.size, 1, 'a replayed click creates no second commitment');

  // Recovery from another browser.
  assert.equal((await post(root, '/donate/monthly/recover', form({ code: 'G28R-WRONG' }))).status, 404);
  const recovered = await post(root, '/donate/monthly/recover', form({ code }));
  assert.equal(recovered.status, 303);
  assert.match(recovered.headers.get('set-cookie'), /__Host-g28-monthly=/);
  const manage = await fetch(root + '/donate/monthly/manage', {
    headers: { ...auth, cookie: recovered.headers.get('set-cookie').split(';')[0] },
  });
  assert.match(await manage.text(), /waiting for the campaign treasury/);
});

test('donor actions need this browser’s capability and CSRF token; cancel, card change and bank confirmation', async (t) => {
  const { root, service, calls } = await start(t);
  const html = await (await fetch(root + '/donate/monthly', { headers: auth })).text();
  const token = html.match(/name="form_token" value="([^"]+)"/)[1];
  const created = await post(
    root,
    '/donate/monthly/setup',
    form({ form_token: token, amount: '25', months: '3', agree: 'yes', ...attest }),
  );
  const cookie = created.headers.get('set-cookie').split(';')[0];
  service.mandate = {
    status: 'active',
    amountCents: 2500,
    frequency: 'monthly',
    election: 'general',
    maxInstallments: 3,
    endAt: '2027-06-01T00:00:00.000Z',
    nextScheduledAt: null,
  };
  const manage = await (await fetch(root + '/donate/monthly/manage', { headers: { ...auth, cookie } })).text();
  const csrf = manage.match(/name="form_token" value="([^"]+)"/)[1];
  assert.match(manage, /Confirm with my bank/);
  assert.match(manage, /Cancel monthly giving/);
  assert.doesNotMatch(manage, /pm_|cus_|pi_/, 'no processor identifiers on donor pages');

  // No capability, a forged capability or a missing CSRF token: refused.
  assert.equal((await post(root, '/donate/monthly/cancel', form({ form_token: csrf, confirm: 'cancel' }))).status, 403);
  const forged = cookie.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A'));
  assert.equal(
    (await post(root, '/donate/monthly/cancel', form({ form_token: csrf, confirm: 'cancel' }), { cookie: forged })).status,
    403,
  );
  assert.equal(
    (await post(root, '/donate/monthly/cancel', form({ form_token: 'x', confirm: 'cancel' }), { cookie })).status,
    403,
  );
  assert.equal(
    (await post(root, '/donate/monthly/cancel', form({ form_token: csrf }), { cookie })).status,
    400,
    'cancelling requires the explicit confirmation box',
  );
  assert.equal(service.cancelled.length, 0);

  // Bank confirmation shows the processor's own page as an explicit link.
  lastApproval = null;
  const original = service.confirmationTarget;
  service.confirmationTarget = async (...args) => {
    const t2 = await original(...args);
    lastApproval = t2.approval;
    return t2;
  };
  assert.equal(
    (await post(root, '/donate/monthly/confirm', form({ form_token: csrf, period: randomUUID() }), { cookie })).status,
    409,
  );
  const confirm = await post(root, '/donate/monthly/confirm', form({ form_token: csrf, period: service.period }), {
    cookie,
  });
  assert.equal(confirm.status, 200);
  assert.match(await confirm.text(), /href="https:\/\/hooks\.stripe\.com\/3d_secure\/synthetic"/);
  const confirmCall = calls.find((c) => c.url.endsWith('/confirm'));
  assert.equal(
    new URLSearchParams(confirmCall.init.body).get('return_url'),
    ORIGIN + '/donate/monthly/confirmed?period=' + service.period,
  );
  const back = await fetch(root + '/donate/monthly/confirmed?period=' + service.period, {
    headers: { ...auth, cookie },
    redirect: 'manual',
  });
  assert.equal(back.status, 303);
  assert.deepEqual(service.observed, [{ periodId: service.period, status: 'requires_capture' }]);

  // Card change: a new setup bound to the existing schedule, with fresh statements.
  assert.equal((await post(root, '/donate/monthly/card', form({ form_token: csrf }), { cookie })).status, 400);
  const change = await post(root, '/donate/monthly/card', form({ form_token: csrf, ...attest }), { cookie });
  assert.equal(change.status, 200);
  assert.equal(change.headers.get('set-cookie'), null, 'the original browser link is kept');
  const replacement = [...service.enrollments.values()].find((x) => x.replacesMandateId);
  assert.equal(replacement.replacesMandateId, 'mandate-id');
  assert.equal(replacement.request.amountCents, 2500);
  assert.equal(replacement.request.maxInstallments, 3);

  const cancelled = await post(root, '/donate/monthly/cancel', form({ form_token: csrf, confirm: 'cancel' }), { cookie });
  assert.equal(cancelled.status, 303);
  assert.equal(service.cancelled.length, 1);
  const forget = await post(root, '/donate/monthly/forget', form({ form_token: csrf }), { cookie });
  assert.match(forget.headers.get('set-cookie'), /Max-Age=0/);
});

test('capabilities are signed, expire and cannot be widened', () => {
  const key = Buffer.alloc(32, 7),
    now = Date.parse('2026-11-15T00:00:00Z');
  const value = monthlyCapability(key, { enrollmentId: randomUUID(), clientReference: 'attempt_' + 'a'.repeat(32) }, now);
  assert.ok(monthlyAuthority(key, value, now));
  assert.equal(monthlyAuthority(Buffer.alloc(32, 8), value, now), null);
  assert.equal(monthlyAuthority(key, value, now + 181 * 86400000), null);
  const [payload, tag] = value.split('.');
  const widened = Buffer.from(
    JSON.stringify({ ...JSON.parse(Buffer.from(payload, 'base64url')), clientReference: 'attempt_' + 'b'.repeat(32) }),
  ).toString('base64url');
  assert.equal(monthlyAuthority(key, widened + '.' + tag, now), null);
});
