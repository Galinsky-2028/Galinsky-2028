import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { StripeCardSetup } from '../packages/core/stripe-card-setup.mjs';
import { MANUAL_CAPTURE_PROFILE } from '../packages/core/stripe-manual-capture.mjs';
const key = 'sk_test_synthetic_card_setup_only',
  origin = 'https://campaign.example';
function request() {
  return {
    id: randomUUID(),
    clientReference: 'attempt_' + 'a'.repeat(32),
    amountCents: 2500,
    frequency: 'monthly',
    election: 'general',
    endAt: '2026-12-31T00:00:00.000Z',
    maxInstallments: 6,
    termsVersion: '2026-01-01-synthetic-only',
    consentDigest: 'b'.repeat(64),
    attestations: {
      eligibleResidency: true,
      ownFunds: true,
      age18: true,
      notFederalContractor: true,
      personalCreditCard: true,
    },
  };
}
const reply = (data) =>
  new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' } });
function session(b) {
  return {
    id: 'cs_test_synthetic12345',
    object: 'checkout.session',
    mode: 'setup',
    livemode: false,
    client_reference_id: b.clientReference,
    status: 'complete',
    url: 'https://checkout.stripe.com/c/pay/cs_test_synthetic12345',
    customer: 'cus_synthetic12345',
    metadata: {
      g28_profile: MANUAL_CAPTURE_PROFILE,
      g28_enrollment: b.id,
      g28_consent: b.consentDigest,
      terms_version: b.termsVersion,
    },
    setup_intent: {
      id: 'seti_synthetic12345',
      object: 'setup_intent',
      livemode: false,
      status: 'succeeded',
      usage: 'off_session',
      customer: 'cus_synthetic12345',
      metadata: {
        g28_profile: MANUAL_CAPTURE_PROFILE,
        g28_enrollment: b.id,
        g28_consent: b.consentDigest,
      },
      client_secret: 'MUST_NOT_RETURN_SETUP_SECRET',
      payment_method: {
        id: 'pm_synthetic12345',
        object: 'payment_method',
        livemode: false,
        customer: 'cus_synthetic12345',
        type: 'card',
        card: { funding: 'credit', country: 'US', wallet: null },
      },
    },
    customer_details: {
      name: 'Synthetic Billing Person',
      email: 'synthetic@example.test',
      address: {
        line1: '1 Synthetic Lane',
        line2: null,
        city: 'Testville',
        state: 'ZZ',
        postal_code: '00000',
        country: 'US',
      },
    },
    custom_fields: [
      { key: 'occupation', type: 'text', text: { value: 'Synthetic occupation' } },
      { key: 'employer', type: 'text', text: { value: 'Synthetic employer' } },
    ],
  };
}
test('hosted setup records exact consent with no monetary/subscription fields and never returns a processor client secret', async () => {
  const b = request(),
    calls = [],
    driver = new StripeCardSetup({
      secretKey: key,
      origin,
      transport: async (url, o) => {
        calls.push({ url, o });
        return reply(session(b));
      },
    });
  const created = await driver.create(b),
    body = new URLSearchParams(calls[0].o.body);
  assert.equal(body.get('mode'), 'setup');
  assert.equal(body.get('customer_creation'), 'always');
  assert.equal(body.get('billing_address_collection'), 'required');
  assert.equal(body.get('metadata[g28_enrollment]'), b.id);
  assert(
    ![...body.keys()].some((k) =>
      /line_items|amount|subscription_data|payment_intent_data/.test(k),
    ),
  );
  assert(body.get('custom_text[submit][message]').includes('$25.00'));
  assert(body.get('custom_text[submit][message]').includes('2026-12-31'));
  assert.equal(created.sessionId, session(b).id);
  assert(!JSON.stringify(created).includes('SECRET'));
  assert(!JSON.stringify(driver).includes(key));
  const verified = await driver.verified(b, created.sessionId, ['US']);
  assert.equal(verified.customerId, 'cus_synthetic12345');
  assert.equal(verified.billing.occupation, 'Synthetic occupation');
  assert(!JSON.stringify(verified).includes('MUST_NOT_RETURN'));
});
test('processor/session/consent/customer/credit funding/wallet/country mismatches block approval without another request', async () => {
  for (const change of [
    (s) => ({ ...s, mode: 'payment' }),
    (s) => ({ ...s, livemode: true }),
    (s) => ({ ...s, metadata: { ...s.metadata, g28_consent: '0'.repeat(64) } }),
    (s) => ({ ...s, setup_intent: { ...s.setup_intent, usage: 'on_session' } }),
    (s) => ({
      ...s,
      setup_intent: {
        ...s.setup_intent,
        payment_method: { ...s.setup_intent.payment_method, customer: 'cus_someoneelse123' },
      },
    }),
    (s) => {
      s.setup_intent.payment_method.card.funding = 'debit';
      return s;
    },
    (s) => {
      s.setup_intent.payment_method.card.wallet = { type: 'apple_pay' };
      return s;
    },
    (s) => {
      s.setup_intent.payment_method.card.country = 'CA';
      return s;
    },
  ]) {
    const b = request();
    let calls = 0;
    const driver = new StripeCardSetup({
      secretKey: key,
      origin,
      transport: async () => {
        calls++;
        return reply(change(session(b)));
      },
    });
    await assert.rejects(driver.verified(b, 'cs_test_synthetic12345', ['US']));
    assert.equal(calls, 1);
  }
});
test('invalid or card-data-bearing setup input, live credentials and foreign checkout URLs cannot start or redirect a donor flow', async () => {
  let calls = 0;
  const b = request(),
    driver = new StripeCardSetup({
      secretKey: key,
      origin,
      transport: async () => {
        calls++;
        return reply({ ...session(b), url: 'https://untrusted.example/card' });
      },
    });
  await assert.rejects(driver.create({ ...b, cardNumber: 'DO_NOT_ACCEPT_PAN' }));
  await assert.rejects(
    driver.create({ ...b, attestations: { ...b.attestations, ownFunds: false } }),
  );
  assert.equal(calls, 0);
  await assert.rejects(driver.create(b), (e) => e.code === 'card_setup_url');
  assert.throws(() => new StripeCardSetup({ secretKey: 'sk_live_synthetic_forbidden', origin }));
  assert.throws(() => new StripeCardSetup({ secretKey: key, origin: 'http://campaign.example' }));
});
