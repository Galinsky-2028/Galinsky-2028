import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  StripeManualCapture,
  MANUAL_CAPTURE_PROFILE,
  STRIPE_MANUAL_API_VERSION,
} from '../packages/core/stripe-manual-capture.mjs';
const now = Date.parse('2026-11-10T12:00:00.000Z'),
  key = 'sk_test_synthetic_manual_capture_only';
const approval = () => ({
  attemptId: randomUUID(),
  periodId: randomUUID(),
  customerId: 'cus_synthetic12345',
  paymentMethodId: 'pm_synthetic12345',
  amountCents: 2500,
  environment: 'test',
  policyDigest: 'a'.repeat(64),
  mandateDigest: 'b'.repeat(64),
  confirmationMode: 'off_session',
  expiresAt: new Date(now + 60000).toISOString(),
});
const response = (data) =>
  new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' } });
function intent(p, status = 'requires_capture') {
  return {
    object: 'payment_intent',
    id: 'pi_synthetic12345',
    livemode: false,
    capture_method: 'manual',
    amount: p.amountCents,
    amount_capturable: status === 'requires_capture' ? p.amountCents : 0,
    amount_received: status === 'succeeded' ? p.amountCents : 0,
    currency: 'usd',
    customer: p.customerId,
    payment_method: p.paymentMethodId,
    status,
    metadata: {
      g28_profile: MANUAL_CAPTURE_PROFILE,
      g28_attempt: p.attemptId,
      g28_period: p.periodId,
      g28_policy: p.policyDigest,
      g28_mandate: p.mandateDigest,
      g28_confirmation: p.confirmationMode,
    },
    client_secret: 'MUST_NOT_RETURN_CLIENT_SECRET',
    shipping: { name: 'MUST_NOT_RETURN_BILLING' },
  };
}
test('provider-authorized card funds remain uncaptured until an exact separate command; output excludes processor secrets and billing data', async () => {
  const p = approval(),
    calls = [];
  let captured = false;
  const transport = async (url, options) => {
    const body = new URLSearchParams(options.body);
    calls.push({ url, options });
    assert.equal(options.headers['Stripe-Version'], STRIPE_MANUAL_API_VERSION);
    assert.equal(options.redirect, 'error');
    if (url.endsWith('/capture')) {
      assert.equal(body.get('amount_to_capture'), '2500');
      assert.equal(body.get('final_capture'), 'true');
      captured = true;
      return response(intent(p, 'succeeded'));
    }
    assert.equal(body.get('capture_method'), 'manual');
    assert.equal(body.get('payment_method'), p.paymentMethodId);
    assert.equal(body.get('customer'), p.customerId);
    assert.equal(body.get('off_session'), 'true');
    assert.equal(body.get('confirm'), 'true');
    return response(intent(p));
  };
  const driver = new StripeManualCapture({ secretKey: key, transport, clock: () => now }),
    held = await driver.authorize(p);
  assert.equal(captured, false);
  assert.equal(held.amountReceived, 0);
  assert.equal(held.amountCapturable, 2500);
  assert(!JSON.stringify(held).includes('MUST_NOT_RETURN'));
  assert(!JSON.stringify(driver).includes(key));
  const paid = await driver.capture(p, held.id);
  assert.equal(captured, true);
  assert.equal(paid.amountReceived, 2500);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].options.headers['Idempotency-Key'], 'g28-authorize-' + p.attemptId);
  assert.equal(calls[1].options.headers['Idempotency-Key'], 'g28-capture-' + p.attemptId);
});
test('expired/invalid/oversized or live decisions cannot dispatch; stale authorization can still be inspected and voided', async () => {
  const p = approval(),
    calls = [],
    driver = new StripeManualCapture({
      secretKey: key,
      clock: () => now,
      transport: async (url, options) => {
        calls.push(url);
        return response(intent(p, url.endsWith('/cancel') ? 'canceled' : 'requires_capture'));
      },
    }),
    expired = { ...p, expiresAt: new Date(now - 1).toISOString() };
  for (const input of [
    expired,
    { ...p, amountCents: 49 },
    { ...p, amountCents: 100000000 },
    { ...p, environment: 'live' },
    { ...p, cardNumber: 'DO_NOT_ACCEPT_PAN' },
    { ...p, expiresAt: 'not-a-date' },
  ])
    await assert.rejects(driver.authorize(input));
  assert.equal(calls.length, 0);
  assert.equal((await driver.inspect(expired, 'pi_synthetic12345')).status, 'requires_capture');
  assert.equal((await driver.cancel(expired, 'pi_synthetic12345')).status, 'canceled');
  assert.equal(calls.length, 2);
  assert.throws(() => new StripeManualCapture({ secretKey: key, sandbox: false }));
  assert.throws(() => new StripeManualCapture({ secretKey: 'sk_live_synthetic_never_dispatch' }));
});
test('wrong processor identity, auto-capture, altered amount or mode never becomes a successful command and never triggers a retry', async () => {
  for (const mutate of [
    (v) => ({ ...v, capture_method: 'automatic' }),
    (v) => ({ ...v, customer: 'cus_someone_else123' }),
    (v) => ({ ...v, amount: 2600 }),
    (v) => ({ ...v, livemode: true }),
    (v) => ({ ...v, status: 'succeeded', amount_received: 2500, amount_capturable: 0 }),
  ]) {
    const p = approval();
    let calls = 0;
    const driver = new StripeManualCapture({
      secretKey: key,
      clock: () => now,
      transport: async () => {
        calls++;
        return response(mutate(intent(p)));
      },
    });
    await assert.rejects(driver.authorize(p), (e) => e.code === 'manual_capture_uncertain');
    assert.equal(calls, 1);
  }
  const p = approval();
  let attempts = 0;
  const driver = new StripeManualCapture({
    secretKey: key,
    clock: () => now,
    transport: async () => {
      attempts++;
      throw Error('Synthetic lost provider response');
    },
  });
  await assert.rejects(driver.authorize(p), (e) => e.code === 'manual_capture_uncertain');
  assert.equal(attempts, 1, 'a lost response cannot create an automatic new financial attempt');
});
test('bounded streaming rejects a hostile response and cancellation never disguises a captured gift as void', async () => {
  const p = approval();
  let canceled = false;
  const stream = new ReadableStream({
      start(c) {
        c.enqueue(new Uint8Array(200001));
      },
      cancel() {
        canceled = true;
      },
    }),
    driver = new StripeManualCapture({
      secretKey: key,
      clock: () => now,
      transport: async () =>
        new Response(stream, { headers: { 'content-type': 'application/json' } }),
    });
  await assert.rejects(driver.authorize(p), (e) => e.code === 'manual_capture_uncertain');
  assert.equal(canceled, true);
  const paid = new StripeManualCapture({
    secretKey: key,
    clock: () => now,
    transport: async () => response(intent(p, 'succeeded')),
  });
  await assert.rejects(
    paid.cancel(p, 'pi_synthetic12345'),
    (e) => e.code === 'manual_capture_uncertain',
  );
});

test('first installment leaves confirmation to the donor bank and only the explicit authenticated confirmation accessor returns a client secret', async () => {
  const p = { ...approval(), confirmationMode: 'on_session' };
  let posts = 0;
  const driver = new StripeManualCapture({
    secretKey: key,
    clock: () => now,
    transport: async (url, options) => {
      if (url.includes('/payment_methods/'))
        return response({
          object: 'payment_method',
          id: p.paymentMethodId,
          livemode: false,
          customer: p.customerId,
          type: 'card',
          card: { funding: 'credit', wallet: null, country: 'US' },
        });
      const value = {
        ...intent(p, 'requires_confirmation'),
        client_secret: 'pi_synthetic12345_secret_syntheticprivate',
      };
      if (options.method === 'POST') {
        posts++;
        const b = new URLSearchParams(options.body);
        assert.equal(b.get('confirm'), 'false');
        assert.equal(b.has('off_session'), false);
      }
      return response(value);
    },
  });
  assert.equal((await driver.instrument(p, ['US'])).funding, 'credit');
  const created = await driver.authorize(p);
  assert.equal(created.status, 'requires_confirmation');
  assert.equal('clientSecret' in created, false);
  assert.equal('client_secret' in created, false);
  const bank = await driver.clientConfirmation(p, created.id);
  assert.equal(bank.clientSecret, 'pi_synthetic12345_secret_syntheticprivate');
  assert.equal(posts, 1);
  for (const card of [
    { funding: 'debit', wallet: null, country: 'US' },
    { funding: 'credit', wallet: { type: 'apple_pay' }, country: 'US' },
    { funding: 'credit', wallet: null, country: 'CA' },
  ]) {
    const bad = new StripeManualCapture({
      secretKey: key,
      clock: () => now,
      transport: async () =>
        response({
          object: 'payment_method',
          id: p.paymentMethodId,
          livemode: false,
          customer: p.customerId,
          type: 'card',
          card,
        }),
    });
    await assert.rejects(bad.instrument(p, ['US']), (e) => e.code === 'card_instrument_review');
  }
});
