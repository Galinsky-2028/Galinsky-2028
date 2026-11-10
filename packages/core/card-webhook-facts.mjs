// Called only after the existing raw-body signature check. Minimize the
// processor payload before storage: no card, billing or client-secret fields.
import { MANUAL_CAPTURE_PROFILE } from './stripe-manual-capture.mjs';
const uuid = (x) =>
  typeof x === 'string' &&
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(x);
const hash = (x) => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const id = (x, p) => typeof x === 'string' && new RegExp('^' + p + '_[A-Za-z0-9]{8,100}$').test(x);
export function cardWebhookFacts(data, type) {
  if (data.metadata?.g28_profile !== MANUAL_CAPTURE_PROFILE) return null;
  const m = data.metadata;
  if (
    type.startsWith('checkout.session.') &&
    data.object === 'checkout.session' &&
    data.mode === 'setup'
  ) {
    if (
      !uuid(m.g28_enrollment) ||
      !hash(m.g28_consent) ||
      !id(data.id, 'cs_test') ||
      typeof data.client_reference_id !== 'string' ||
      !/^attempt_[a-f0-9]{32}$/.test(data.client_reference_id) ||
      typeof m.terms_version !== 'string'
    )
      return { invalid: true };
    return {
      kind: 'setup',
      enrollmentId: m.g28_enrollment,
      consentDigest: m.g28_consent,
      termsVersion: m.terms_version,
      clientReference: data.client_reference_id,
      sessionId: data.id,
    };
  }
  if (
    !type.startsWith('payment_intent.') ||
    data.object !== 'payment_intent' ||
    !id(data.id, 'pi') ||
    !uuid(m.g28_attempt) ||
    !uuid(m.g28_period) ||
    !hash(m.g28_policy) ||
    !hash(m.g28_mandate) ||
    !['on_session', 'off_session'].includes(m.g28_confirmation) ||
    !id(data.customer, 'cus') ||
    !(id(data.payment_method, 'pm') || data.payment_method === null) ||
    data.capture_method !== 'manual' ||
    data.currency !== 'usd' ||
    !Number.isSafeInteger(data.amount) ||
    data.amount < 50 ||
    data.amount > 99999999 ||
    !Number.isSafeInteger(data.amount_received) ||
    data.amount_received < 0 ||
    data.amount_received > data.amount ||
    !Number.isSafeInteger(data.amount_capturable) ||
    data.amount_capturable < 0 ||
    data.amount_capturable > data.amount ||
    ![
      'requires_payment_method',
      'requires_confirmation',
      'requires_action',
      'processing',
      'requires_capture',
      'canceled',
      'succeeded',
    ].includes(data.status)
  )
    return { invalid: true };
  return {
    kind: 'intent',
    id: data.id,
    attemptId: m.g28_attempt,
    periodId: m.g28_period,
    policyDigest: m.g28_policy,
    mandateDigest: m.g28_mandate,
    confirmationMode: m.g28_confirmation,
    customerId: data.customer,
    paymentMethodId: data.payment_method,
    amountCents: data.amount,
    amountReceived: data.amount_received,
    amountCapturable: data.amount_capturable,
    status: data.status,
  };
}
