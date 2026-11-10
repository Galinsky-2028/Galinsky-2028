// Narrow provider primitive, not a treasury approval or recurring scheduler.
// Funds require an explicit separate capture; callers must durably reserve the
// period and recheck current all-channel/policy/mandate authority before each
// authorization/capture. This module never retries an uncertain operation.
import { assert, exactKeys, DomainError } from './validation.mjs';
import { readStripeJson } from './stripe-response.mjs';
import { financeId } from './treasury-workflow.mjs';
export const MANUAL_CAPTURE_PROFILE = 'stripe-manual-capture-v1';
export const STRIPE_MANUAL_API_VERSION = '2026-09-30.endive';
const ROOT = 'https://api.stripe.com/v1/';
const digest = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const money = (value) => Number.isSafeInteger(value) && value >= 50 && value <= 99999999;
const providerId = (value, prefix) =>
  typeof value === 'string' && new RegExp('^' + prefix + '_[A-Za-z0-9]{8,100}$').test(value);
const states = new Set([
  'requires_payment_method',
  'requires_confirmation',
  'requires_action',
  'processing',
  'requires_capture',
  'canceled',
  'succeeded',
]);
export function manualCaptureApproval(input, now = Date.now(), { allowExpired = false } = {}) {
  const p = exactKeys(input, [
    'attemptId',
    'periodId',
    'customerId',
    'paymentMethodId',
    'amountCents',
    'environment',
    'policyDigest',
    'mandateDigest',
    'confirmationMode',
    'expiresAt',
  ]);
  financeId(p.attemptId);
  financeId(p.periodId);
  assert(
    providerId(p.customerId, 'cus') &&
      providerId(p.paymentMethodId, 'pm') &&
      money(p.amountCents) &&
      ['test', 'live'].includes(p.environment) &&
      digest(p.policyDigest) &&
      digest(p.mandateDigest) &&
      ['on_session', 'off_session'].includes(p.confirmationMode),
    'invalid_manual_capture',
    'Use an exact approved card/customer/period and integer USD amount.',
  );
  assert(
    typeof p.expiresAt === 'string' &&
      Number.isFinite(Date.parse(p.expiresAt)) &&
      new Date(p.expiresAt).toISOString() === p.expiresAt &&
      (allowExpired || Date.parse(p.expiresAt) > now) &&
      Date.parse(p.expiresAt) <= now + 300000,
    'manual_capture_expired',
    'The short-lived treasury dispatch decision is missing or expired.',
    409,
  );
  return { ...p };
}
function observe(value, p, expectedId = null) {
  assert(
    value &&
      providerId(value.id, 'pi') &&
      (!expectedId || value.id === expectedId) &&
      value.object === 'payment_intent' &&
      value.livemode === (p.environment === 'live') &&
      value.capture_method === 'manual' &&
      value.currency === 'usd' &&
      value.amount === p.amountCents &&
      value.customer === p.customerId &&
      (value.payment_method === p.paymentMethodId ||
        (value.payment_method === null &&
          ['requires_payment_method', 'canceled'].includes(value.status) &&
          value.amount_received === 0 &&
          value.amount_capturable === 0)) &&
      states.has(value.status) &&
      Number.isSafeInteger(value.amount_capturable) &&
      value.amount_capturable >= 0 &&
      value.amount_capturable <= p.amountCents &&
      Number.isSafeInteger(value.amount_received) &&
      value.amount_received >= 0 &&
      value.amount_received <= p.amountCents &&
      value.metadata?.g28_profile === MANUAL_CAPTURE_PROFILE &&
      value.metadata?.g28_attempt === p.attemptId &&
      value.metadata?.g28_period === p.periodId &&
      value.metadata?.g28_policy === p.policyDigest &&
      value.metadata?.g28_mandate === p.mandateDigest &&
      value.metadata?.g28_confirmation === p.confirmationMode,
    'manual_capture_uncertain',
    'The processor response did not match this exact manual-capture period. Reconcile before another attempt.',
    409,
  );
  // Deliberately exclude client_secret, billing identity, arbitrary provider
  // errors and next_action internals from returned/loggable command results.
  return {
    id: value.id,
    status: value.status,
    amountCents: value.amount,
    amountCapturable: value.amount_capturable,
    amountReceived: value.amount_received,
    customerId: value.customer,
    paymentMethodId: value.payment_method,
    environment: p.environment,
  };
}
export class StripeManualCapture {
  #key;
  constructor({ secretKey, sandbox = true, transport = fetch, clock = Date.now }) {
    // Live wiring is intentionally unavailable until the full authorization,
    // atomic reservation and donor-control adapter has passed its own review.
    assert(
      sandbox === true &&
        typeof secretKey === 'string' &&
        /^sk_test_[A-Za-z0-9_]{12,}$/.test(secretKey),
      'manual_capture_test_only',
      'Only the explicitly configured Stripe TEST capture adapter is installed.',
      503,
    );
    this.#key = secretKey;
    this.transport = transport;
    this.clock = clock;
  }
  async #request(
    path,
    p,
    { method = 'GET', body, idempotency, expectedId, rawResult = false } = {},
  ) {
    assert(
      typeof path === 'string' &&
        /^(?:payment_intents|payment_intents\/pi_[A-Za-z0-9]{8,100}(?:\/capture|\/cancel)?|payment_methods\/pm_[A-Za-z0-9]{8,100})$/.test(
          path,
        ),
      'invalid_manual_endpoint',
      'Use a fixed supported payment-intent endpoint.',
    );
    let response, raw;
    try {
      response = await this.transport(ROOT + path, {
        method,
        headers: {
          Authorization: 'Bearer ' + this.#key,
          'Stripe-Version': STRIPE_MANUAL_API_VERSION,
          ...(body
            ? {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Idempotency-Key': idempotency,
              }
            : {}),
        },
        ...(body ? { body: body.toString() } : {}),
        redirect: 'error',
        signal: AbortSignal.timeout(15000),
      });
      raw = await readStripeJson(response);
    } catch {
      throw new DomainError(
        'manual_capture_uncertain',
        'The processor outcome is unknown. Keep the existing command and reconcile it; do not create another attempt.',
        409,
      );
    }
    if (!response.ok) {
      const candidate = raw?.error?.payment_intent;
      if (candidate) {
        const seen = observe(candidate, p, expectedId);
        assert(
          seen.amountReceived === 0 && seen.status !== 'succeeded',
          'manual_capture_uncertain',
          'Unexpected funds require treasury reconciliation.',
          409,
        );
        return seen;
      }
      throw new DomainError(
        'manual_capture_uncertain',
        'The processor did not provide an authenticated matching intent state. Reconcile before another attempt.',
        409,
      );
    }
    return rawResult ? raw : observe(raw, p, expectedId);
  }
  async authorize(input) {
    const p = manualCaptureApproval(input, this.clock());
    assert(
      p.environment === 'test',
      'manual_capture_test_only',
      'A live period cannot use the TEST adapter.',
      503,
    );
    const body = new URLSearchParams({
      amount: String(p.amountCents),
      currency: 'usd',
      customer: p.customerId,
      payment_method: p.paymentMethodId,
      'payment_method_types[0]': 'card',
      capture_method: 'manual',
      confirm: p.confirmationMode === 'off_session' ? 'true' : 'false',
      'metadata[g28_profile]': MANUAL_CAPTURE_PROFILE,
      'metadata[g28_attempt]': p.attemptId,
      'metadata[g28_period]': p.periodId,
      'metadata[g28_policy]': p.policyDigest,
      'metadata[g28_mandate]': p.mandateDigest,
      'metadata[g28_confirmation]': p.confirmationMode,
    });
    if (p.confirmationMode === 'off_session') body.set('off_session', 'true');
    const seen = await this.#request('payment_intents', p, {
      method: 'POST',
      body,
      idempotency: 'g28-authorize-' + p.attemptId,
    });
    assert(
      seen.amountReceived === 0 && seen.status !== 'succeeded',
      'manual_capture_uncertain',
      'An authorization unexpectedly collected funds. Reconcile without retrying.',
      409,
    );
    return seen;
  }
  async instrument(input, allowedCountries) {
    const p = manualCaptureApproval(input, this.clock());
    assert(
      p.environment === 'test' && Array.isArray(allowedCountries),
      'manual_capture_test_only',
      'Use current TEST source rules.',
    );
    const pm = await this.#request('payment_methods/' + p.paymentMethodId, p, { rawResult: true });
    assert(
      pm.object === 'payment_method' &&
        pm.id === p.paymentMethodId &&
        pm.livemode === false &&
        pm.customer === p.customerId &&
        pm.type === 'card' &&
        pm.card?.funding === 'credit' &&
        pm.card.wallet === null &&
        allowedCountries.includes(pm.card.country),
      'card_instrument_review',
      'The actual current credit-card method and source policy require review. Nothing was captured.',
      409,
    );
    return {
      id: pm.id,
      customerId: pm.customer,
      funding: 'credit',
      issuerCountry: pm.card.country,
    };
  }
  async clientConfirmation(input, id) {
    const p = manualCaptureApproval(input, this.clock());
    assert(
      p.environment === 'test' && providerId(id, 'pi'),
      'invalid_manual_reference',
      'Use this exact TEST intent.',
    );
    const raw = await this.#request('payment_intents/' + id, p, {
        expectedId: id,
        rawResult: true,
      }),
      seen = observe(raw, p, id);
    assert(
      ['requires_confirmation', 'requires_action'].includes(seen.status) &&
        seen.amountReceived === 0 &&
        typeof raw.client_secret === 'string' &&
        raw.client_secret.startsWith(id + '_secret_') &&
        raw.client_secret.length <= 250,
      'card_confirmation_unavailable',
      'The exact original intent is not awaiting bank authentication.',
      409,
    );
    return { paymentIntentId: id, clientSecret: raw.client_secret };
  }
  async inspect(input, id) {
    const p = manualCaptureApproval(input, this.clock(), { allowExpired: true });
    assert(
      p.environment === 'test' && providerId(id, 'pi'),
      'invalid_manual_reference',
      'Use this period’s exact TEST intent.',
    );
    return this.#request('payment_intents/' + id, p, { expectedId: id });
  }
  async capture(input, id) {
    const p = manualCaptureApproval(input, this.clock());
    assert(
      p.environment === 'test' && providerId(id, 'pi'),
      'invalid_manual_reference',
      'Use this period’s exact TEST intent.',
    );
    // No internal retry and no implicit GET-then-charge decision: callers must
    // persist their new authorized command and current reservation before here.
    const body = new URLSearchParams({
        amount_to_capture: String(p.amountCents),
        final_capture: 'true',
      }),
      seen = await this.#request('payment_intents/' + id + '/capture', p, {
        method: 'POST',
        body,
        idempotency: 'g28-capture-' + p.attemptId,
        expectedId: id,
      });
    assert(
      seen.status === 'succeeded' &&
        seen.amountReceived === p.amountCents &&
        seen.amountCapturable === 0,
      'manual_capture_uncertain',
      'The exact capture remains unconfirmed. Reconcile this intent, not a new charge.',
      409,
    );
    return seen;
  }
  async cancel(input, id) {
    const p = manualCaptureApproval(input, this.clock(), { allowExpired: true });
    assert(
      p.environment === 'test' && providerId(id, 'pi'),
      'invalid_manual_reference',
      'Use this period’s exact TEST intent.',
    );
    const seen = await this.#request('payment_intents/' + id + '/cancel', p, {
      method: 'POST',
      body: new URLSearchParams(),
      idempotency: 'g28-void-' + p.attemptId,
      expectedId: id,
    });
    assert(
      seen.status === 'canceled' && seen.amountReceived === 0 && seen.amountCapturable === 0,
      'manual_capture_uncertain',
      'Cancellation is not confirmed. Do not create another authorization.',
      409,
    );
    return seen;
  }
}
