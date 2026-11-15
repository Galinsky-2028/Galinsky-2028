import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  StripeManualCapture,
  MANUAL_CAPTURE_PROFILE,
} from '../packages/core/stripe-manual-capture.mjs';
import { requestStripeTestCardRefund } from '../packages/core/stripe-treasury-actions.mjs';
import { installmentWindow, newRecoveryCode, RECOVERY_CODE, recoveryDigest } from '../apps/api/src/card-recurring-service.mjs';

const key = 'sk_test_' + 'x'.repeat(24),
  now = Date.parse('2026-11-15T12:00:00.000Z');
const approval = {
  attemptId: randomUUID(),
  periodId: randomUUID(),
  customerId: 'cus_syntheticAAAA',
  paymentMethodId: 'pm_syntheticAAAA',
  amountCents: 2500,
  environment: 'test',
  policyDigest: 'a'.repeat(64),
  mandateDigest: 'b'.repeat(64),
  confirmationMode: 'on_session',
  expiresAt: new Date(now - 60000).toISOString(),
};
const intent = (status, extra = {}) => ({
  id: 'pi_syntheticBBBB',
  object: 'payment_intent',
  livemode: false,
  capture_method: 'manual',
  currency: 'usd',
  amount: 2500,
  customer: approval.customerId,
  payment_method: approval.paymentMethodId,
  status,
  amount_capturable: status === 'requires_capture' ? 2500 : 0,
  amount_received: 0,
  metadata: {
    g28_profile: MANUAL_CAPTURE_PROFILE,
    g28_attempt: approval.attemptId,
    g28_period: approval.periodId,
    g28_policy: approval.policyDigest,
    g28_mandate: approval.mandateDigest,
    g28_confirmation: 'on_session',
  },
  ...extra,
});
const respond = (body, ok = true) => async (url, init) => {
  respond.calls.push({ url, init });
  return new Response(JSON.stringify(typeof body === 'function' ? body(url, init) : body), {
    status: ok ? 200 : 402,
    headers: { 'content-type': 'application/json' },
  });
};
respond.calls = [];

test('donor bank confirmation uses only the fixed confirm endpoint and the processor’s own page', async () => {
  respond.calls = [];
  const driver = new StripeManualCapture({
    secretKey: key,
    clock: () => now,
    transport: respond(
      intent('requires_action', {
        next_action: {
          type: 'redirect_to_url',
          redirect_to_url: { url: 'https://hooks.stripe.com/3d_secure_2/authenticate/synthetic' },
        },
      }),
    ),
  });
  const r = await driver.donorConfirm(
    approval,
    'pi_syntheticBBBB',
    'https://campaign.example/donate/monthly/confirmed?period=' + approval.periodId,
  );
  assert.equal(r.redirectUrl, 'https://hooks.stripe.com/3d_secure_2/authenticate/synthetic');
  assert.equal(r.seen.status, 'requires_action');
  const call = respond.calls[0];
  assert.equal(call.url, 'https://api.stripe.com/v1/payment_intents/pi_syntheticBBBB/confirm');
  assert.equal(call.init.headers['Idempotency-Key'], 'g28-donor-confirm-' + approval.attemptId);
  assert.equal(new URLSearchParams(call.init.body).get('return_url').startsWith('https://campaign.example/'), true);
  assert.equal(JSON.stringify(r).includes('secret'), false);

  const authorized = new StripeManualCapture({
    secretKey: key,
    clock: () => now,
    transport: respond(intent('requires_capture')),
  });
  assert.equal(
    (await authorized.donorConfirm(approval, 'pi_syntheticBBBB', 'https://campaign.example/x')).redirectUrl,
    null,
  );
});

test('bank confirmation refuses foreign redirect hosts, off-session periods, collected funds and plain HTTP', async () => {
  const make = (body) =>
    new StripeManualCapture({ secretKey: key, clock: () => now, transport: respond(body) });
  await assert.rejects(
    make(
      intent('requires_action', {
        next_action: { type: 'redirect_to_url', redirect_to_url: { url: 'https://stripe.com.evil.test/x' } },
      }),
    ).donorConfirm(approval, 'pi_syntheticBBBB', 'https://campaign.example/x'),
    (e) => e.code === 'card_confirmation_unavailable',
  );
  await assert.rejects(
    make(intent('requires_capture')).donorConfirm(
      { ...approval, confirmationMode: 'off_session' },
      'pi_syntheticBBBB',
      'https://campaign.example/x',
    ),
    (e) => e.code === 'card_confirmation_unavailable',
  );
  await assert.rejects(
    make(intent('succeeded', { amount_received: 2500 })).donorConfirm(
      approval,
      'pi_syntheticBBBB',
      'https://campaign.example/x',
    ),
    (e) => e.code === 'manual_capture_uncertain',
  );
  await assert.rejects(
    make(intent('requires_capture')).donorConfirm(approval, 'pi_syntheticBBBB', 'http://campaign.example/x'),
    (e) => e.code === 'card_confirmation_unavailable',
  );
  await assert.rejects(
    make(intent('requires_capture', { metadata: { ...intent('x').metadata, g28_period: randomUUID() } })).donorConfirm(
      approval,
      'pi_syntheticBBBB',
      'https://campaign.example/x',
    ),
    (e) => e.code === 'manual_capture_uncertain',
    'an intent bound to another installment is refused',
  );
  assert.throws(
    () => new StripeManualCapture({ secretKey: 'sk_live_' + 'x'.repeat(24) }),
    (e) => e.code === 'manual_capture_test_only',
  );
});

test('a monthly installment refund re-verifies the exact captured test intent before refunding', async () => {
  const periodId = randomUUID(),
    commandId = randomUUID();
  const captured = intent('succeeded', {
    amount_received: 2500,
    metadata: { g28_profile: MANUAL_CAPTURE_PROFILE, g28_period: periodId },
  });
  respond.calls = [];
  const ok = await requestStripeTestCardRefund({
    secretKey: key,
    paymentIntentId: 'pi_syntheticBBBB',
    periodId,
    originalAmountCents: 2500,
    amountCents: 1000,
    commandId,
    transport: respond((url) =>
      url.endsWith('/refunds')
        ? { id: 're_synthetic1', amount: 1000, currency: 'usd', payment_intent: 'pi_syntheticBBBB', status: 'pending' }
        : captured,
    ),
  });
  assert.equal(ok.providerReference, 're_synthetic1');
  assert.equal(respond.calls[1].init.headers['Idempotency-Key'], 'g28-treasury-refund-' + commandId);
  const refuse = async (pi, args = {}) =>
    assert.rejects(
      requestStripeTestCardRefund({
        secretKey: key,
        paymentIntentId: 'pi_syntheticBBBB',
        periodId,
        originalAmountCents: 2500,
        amountCents: 1000,
        commandId,
        transport: respond(pi),
        ...args,
      }),
    );
  await refuse({ ...captured, livemode: true });
  await refuse({ ...captured, metadata: { ...captured.metadata, g28_period: randomUUID() } });
  await refuse({ ...captured, status: 'requires_capture', amount_received: 0 });
  await refuse(captured, { amountCents: 2600 });
  await refuse(captured, { secretKey: 'sk_live_' + 'x'.repeat(24) });
});

test('recovery codes have 120 bits, a strict format and are only stored as digests', () => {
  const codes = new Set(Array.from({ length: 200 }, newRecoveryCode));
  assert.equal(codes.size, 200);
  for (const c of codes) assert.match(c, RECOVERY_CODE);
  const one = [...codes][0];
  assert.match(recoveryDigest(one), /^[a-f0-9]{64}$/);
  assert.notEqual(recoveryDigest(one), recoveryDigest([...codes][1]));
});

test('monthly windows keep the anchor day and never extend past the next month or the cutoff', () => {
  const m = {
    id: randomUUID(),
    enrollmentId: randomUUID(),
    donorId: randomUUID(),
    donorVersion: 1,
    environment: 'test',
    customerId: 'cus_syntheticAAAA',
    paymentMethodId: 'pm_syntheticAAAA',
    amountCents: 2500,
    frequency: 'monthly',
    election: 'general',
    firstAt: '2027-01-31T10:00:00.000Z',
    endAt: '2027-03-15T00:00:00.000Z',
    maxInstallments: 3,
    termsVersion: '2026-11-15-synthetic-only',
    consentDigest: 'c'.repeat(64),
  };
  const w1 = installmentWindow(m, 1);
  assert.equal(new Date(w1.at).toISOString(), '2027-02-28T10:00:00.000Z');
  assert.equal(new Date(w1.end).toISOString(), '2027-03-15T00:00:00.000Z');
  const w0 = installmentWindow(m, 0);
  assert.equal(new Date(w0.end).toISOString(), '2027-02-28T10:00:00.000Z');
});
