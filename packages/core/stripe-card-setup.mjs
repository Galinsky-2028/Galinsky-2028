// Prospective card setup only. A successful setup is not a contribution,
// treasury approval, credit-card ownership proof or authorization to capture.
import { assert, exactKeys, DomainError, email } from './validation.mjs';
import { financeId } from './treasury-workflow.mjs';
import { MANUAL_CAPTURE_PROFILE, STRIPE_MANUAL_API_VERSION } from './stripe-manual-capture.mjs';
import { readStripeJson } from './stripe-response.mjs';
const id = (x, p) => typeof x === 'string' && new RegExp('^' + p + '_[A-Za-z0-9]{8,100}$').test(x);
const ref = (x) => typeof x === 'string' && /^attempt_[a-f0-9]{32}$/.test(x);
const digest = (x) => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const safeText = (x, max) =>
  typeof x === 'string' && x.trim().length > 0 && x.length <= max && !/[\x00-\x1f]/.test(x);
export function cardEnrollmentRequest(input) {
  const b = exactKeys(input, [
    'id',
    'clientReference',
    'amountCents',
    'frequency',
    'election',
    'endAt',
    'maxInstallments',
    'termsVersion',
    'consentDigest',
    'attestations',
  ]);
  financeId(b.id);
  assert(
    ref(b.clientReference) &&
      Number.isSafeInteger(b.amountCents) &&
      b.amountCents >= 50 &&
      b.amountCents <= 99999999 &&
      ['once', 'monthly'].includes(b.frequency) &&
      ['primary', 'general'].includes(b.election) &&
      Number.isSafeInteger(b.maxInstallments) &&
      b.maxInstallments >= 1 &&
      b.maxInstallments <= 120 &&
      (b.frequency !== 'once' || b.maxInstallments === 1) &&
      typeof b.endAt === 'string' &&
      /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(b.endAt) &&
      Number.isFinite(Date.parse(b.endAt)) &&
      new Date(b.endAt).toISOString() === b.endAt &&
      /^\d{4}-\d{2}-\d{2}-[a-z0-9-]{4,40}$/.test(b.termsVersion) &&
      digest(b.consentDigest),
    'invalid_card_enrollment',
    'Use an exact prospective amount, schedule, cutoff and published terms.',
  );
  exactKeys(b.attestations, [
    'eligibleResidency',
    'ownFunds',
    'age18',
    'notFederalContractor',
    'personalCreditCard',
  ]);
  assert(
    Object.values(b.attestations).every((x) => x === true),
    'card_attestations',
    'The actual donor eligibility/source statements are required; they are not verified legal facts.',
  );
  return structuredClone(b);
}
export class StripeCardSetup {
  #key;
  #origin;
  #transport;
  constructor({ secretKey, origin, sandbox = true, transport = fetch }) {
    let u;
    try {
      u = new URL(origin);
    } catch {
      assert(false, 'card_setup_origin', 'Use the approved HTTPS campaign origin.');
    }
    assert(
      sandbox === true &&
        typeof secretKey === 'string' &&
        /^sk_test_[A-Za-z0-9_]{12,}$/.test(secretKey) &&
        u.protocol === 'https:' &&
        u.pathname === '/' &&
        !u.username &&
        !u.password &&
        !u.port &&
        !u.search &&
        !u.hash,
      'card_setup_test_only',
      'Only the configured HTTPS Stripe TEST setup adapter is installed.',
      503,
    );
    this.#key = secretKey;
    this.#origin = u.origin;
    this.#transport = transport;
  }
  async #request(path, body = null, idempotency = null) {
    assert(
      /^(?:checkout\/sessions|checkout\/sessions\/cs_test_[A-Za-z0-9]{8,100}\?expand%5B%5D=setup_intent.payment_method)$/.test(
        path,
      ),
      'invalid_setup_endpoint',
      'Use a fixed card-setup endpoint.',
    );
    let r, value;
    try {
      r = await this.#transport('https://api.stripe.com/v1/' + path, {
        method: body ? 'POST' : 'GET',
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
      value = await readStripeJson(r);
    } catch {
      throw new DomainError(
        'card_setup_uncertain',
        'Card setup could not be confirmed. Keep this original setup reference; do not create another commitment.',
        409,
      );
    }
    assert(
      r.ok,
      'card_setup_uncertain',
      'The processor did not confirm the original card setup.',
      409,
    );
    return value;
  }
  #session(s, b) {
    assert(
      s &&
        id(s.id, 'cs_test') &&
        s.object === 'checkout.session' &&
        s.mode === 'setup' &&
        s.livemode === false &&
        s.client_reference_id === b.clientReference &&
        s.metadata?.g28_profile === MANUAL_CAPTURE_PROFILE &&
        s.metadata?.g28_enrollment === b.id &&
        s.metadata?.g28_consent === b.consentDigest &&
        s.metadata?.terms_version === b.termsVersion,
      'card_setup_mismatch',
      'The processor setup does not match this exact consent and browser request.',
      409,
    );
    return s;
  }
  async create(input) {
    const b = cardEnrollmentRequest(input),
      amount = (b.amountCents / 100).toFixed(2),
      summary = `Save a personal credit card for ${b.frequency === 'monthly' ? 'up to ' + b.maxInstallments + ' monthly gifts of' : 'one gift of'} $${amount}. Election: ${b.election}. Last permitted date: ${b.endAt.slice(0, 10)}. No gift is collected until current campaign review permits it. Card setup is not a donation. Manage or cancel at ${this.#origin}/donate/manage.`;
    const body = new URLSearchParams({
        mode: 'setup',
        currency: 'usd',
        customer_creation: 'always',
        'payment_method_types[0]': 'card',
        billing_address_collection: 'required',
        client_reference_id: b.clientReference,
        success_url: this.#origin + '/donate/manage?card=review',
        cancel_url: this.#origin + '/donate/?card=cancelled',
        'metadata[g28_profile]': MANUAL_CAPTURE_PROFILE,
        'metadata[g28_enrollment]': b.id,
        'metadata[g28_consent]': b.consentDigest,
        'metadata[terms_version]': b.termsVersion,
        'setup_intent_data[metadata][g28_profile]': MANUAL_CAPTURE_PROFILE,
        'setup_intent_data[metadata][g28_enrollment]': b.id,
        'setup_intent_data[metadata][g28_consent]': b.consentDigest,
        'custom_text[submit][message]': summary,
        'custom_fields[0][key]': 'occupation',
        'custom_fields[0][type]': 'text',
        'custom_fields[0][label][type]': 'custom',
        'custom_fields[0][label][custom]': 'Occupation or not employed',
        'custom_fields[0][optional]': 'false',
        'custom_fields[1][key]': 'employer',
        'custom_fields[1][type]': 'text',
        'custom_fields[1][label][type]': 'custom',
        'custom_fields[1][label][custom]': 'Employer or not employed',
        'custom_fields[1][optional]': 'false',
      }),
      s = this.#session(
        await this.#request('checkout/sessions', body, 'g28-card-setup-' + b.id),
        b,
      );
    let u;
    try {
      u = new URL(s.url);
    } catch {
      assert(false, 'card_setup_url', 'The processor did not return its hosted setup page.', 409);
    }
    assert(
      u.protocol === 'https:' &&
        u.hostname === 'checkout.stripe.com' &&
        !u.username &&
        !u.password &&
        !u.port,
      'card_setup_url',
      'Use only the processor-owned hosted setup page.',
      409,
    );
    return { sessionId: s.id, hostedUrl: u.href };
  }
  async verified(input, sessionId, allowedCardCountries) {
    const b = cardEnrollmentRequest(input);
    assert(
      id(sessionId, 'cs_test') && Array.isArray(allowedCardCountries),
      'invalid_card_setup_reference',
      'Use this exact recorded TEST setup.',
    );
    const s = this.#session(
        await this.#request(
          'checkout/sessions/' + sessionId + '?expand%5B%5D=setup_intent.payment_method',
        ),
        b,
      ),
      setup = s.setup_intent,
      pm = setup?.payment_method;
    assert(
      s.id === sessionId &&
        s.status === 'complete' &&
        id(s.customer, 'cus') &&
        setup?.object === 'setup_intent' &&
        id(setup.id, 'seti') &&
        setup.livemode === false &&
        setup.status === 'succeeded' &&
        setup.usage === 'off_session' &&
        setup.customer === s.customer &&
        setup.metadata?.g28_profile === MANUAL_CAPTURE_PROFILE &&
        setup.metadata?.g28_enrollment === b.id &&
        setup.metadata?.g28_consent === b.consentDigest &&
        pm?.object === 'payment_method' &&
        id(pm.id, 'pm') &&
        pm.livemode === false &&
        pm.customer === s.customer &&
        pm.type === 'card' &&
        pm.card?.funding === 'credit' &&
        pm.card.wallet === null &&
        allowedCardCountries.includes(pm.card.country),
      'card_setup_review_required',
      'The exact card mandate, direct personal-credit-card method and current source policy need review. No payment was authorized.',
      409,
    );
    const d = s.customer_details,
      a = d?.address;
    assert(
      !a?.line2 || safeText(a.line2, 240),
      'card_billing_review_required',
      'The processor billing address needs review.',
      409,
    );
    assert(
      d &&
        safeText(d.name, 140) &&
        safeText(d.email, 254) &&
        a &&
        safeText(a.line1, 240) &&
        safeText(a.city, 140) &&
        safeText(a.state, 140) &&
        safeText(a.postal_code, 140) &&
        typeof a.country === 'string' &&
        /^[A-Z]{2}$/.test(a.country),
      'card_billing_review_required',
      'The processor did not supply the required billing identity. Review before creating a treasury contributor.',
      409,
    );
    const fields = s.custom_fields;
    assert(
      Array.isArray(fields) && fields.length === 2 && new Set(fields.map((x) => x.key)).size === 2,
      'card_billing_review_required',
      'Required contributor reporting information is incomplete.',
      409,
    );
    const custom = (key) => {
      const value = fields.find((x) => x.key === key && x.type === 'text')?.text?.value;
      assert(
        safeText(value, 140),
        'card_billing_review_required',
        'Required contributor reporting information is incomplete.',
        409,
      );
      return value;
    };
    // Caller must immediately seal this intentionally processed financial
    // identity; it must not become an ordinary log, queue body or public receipt.
    const street = a.line1 + (a.line2 ? ' ' + a.line2 : '');
    assert(
      street.length <= 240,
      'card_billing_review_required',
      'The processor billing address needs review.',
      409,
    );
    return {
      sessionId: s.id,
      setupIntentId: setup.id,
      customerId: s.customer,
      paymentMethodId: pm.id,
      card: { funding: 'credit', issuerCountry: pm.card.country },
      billing: {
        name: d.name,
        email: email(d.email),
        street,
        city: a.city,
        region: a.state,
        postal: a.postal_code,
        country: a.country,
        occupation: custom('occupation'),
        employer: custom('employer'),
      },
    };
  }
}
