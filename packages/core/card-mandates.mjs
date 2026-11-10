// Business rules for prospective, processor-held card contributions. Financial
// identities are deliberately processed by treasury; this is not E2EE or a
// declaration of legal eligibility. No field here authorizes a provider call.
import { assert, exactKeys } from './validation.mjs';
import { financeId, treasuryPolicy } from './treasury-workflow.mjs';
import { MANUAL_CAPTURE_PROFILE } from './stripe-manual-capture.mjs';
const hash = (x) => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const amount = (x) => Number.isSafeInteger(x) && x >= 50 && x <= 99999999;
const stamp = (x) =>
  typeof x === 'string' &&
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x) &&
  Number.isFinite(Date.parse(x)) &&
  new Date(x).toISOString() === x;
const terms = (x) => typeof x === 'string' && /^\d{4}-\d{2}-\d{2}-[a-z0-9-]{4,40}$/.test(x);
const provider = (x, p) =>
  typeof x === 'string' && new RegExp('^' + p + '_[A-Za-z0-9]{8,100}$').test(x);
const total = (x) => typeof x === 'string' && /^(?:0|[1-9]\d{0,39})$/.test(x);
export function cardContributionPolicy(input, parent, now = Date.now()) {
  const p = exactKeys(input, [
    'id',
    'version',
    'profile',
    'parentPolicyId',
    'parentPolicyVersion',
    'validUntil',
    'electionEnds',
    'maxInstallments',
    'maxSchedulesPerDonor',
    'reservationSeconds',
    'termsVersion',
    'allowedCardCountries',
    'evidenceDigest',
  ]);
  financeId(p.id);
  financeId(p.parentPolicyId);
  const t = treasuryPolicy(parent, now);
  assert(
    p.profile === MANUAL_CAPTURE_PROFILE &&
      p.parentPolicyId === t.id &&
      p.parentPolicyVersion === t.version &&
      Number.isSafeInteger(p.version) &&
      p.version >= 1 &&
      stamp(p.validUntil) &&
      Date.parse(p.validUntil) > now &&
      Date.parse(p.validUntil) <= Date.parse(t.validUntil) &&
      hash(p.evidenceDigest),
    'card_policy_unavailable',
    'Use a current documentary card-control policy bound to the current treasury rules.',
    409,
  );
  exactKeys(p.electionEnds, ['primary', 'general']);
  assert(
    Object.values(p.electionEnds).every(stamp),
    'card_election_rules',
    'Record actual approved election cutoffs; no year or legal limit is inferred.',
  );
  assert(
    Number.isSafeInteger(p.maxInstallments) &&
      p.maxInstallments >= 1 &&
      p.maxInstallments <= 120 &&
      Number.isSafeInteger(p.maxSchedulesPerDonor) &&
      p.maxSchedulesPerDonor >= 1 &&
      p.maxSchedulesPerDonor <= 12 &&
      Number.isSafeInteger(p.reservationSeconds) &&
      p.reservationSeconds >= 60 &&
      p.reservationSeconds <= 3600 &&
      terms(p.termsVersion),
    'card_policy_bounds',
    'Use explicit bounded installments, schedules, dispatch reservations and published terms.',
  );
  assert(
    Array.isArray(p.allowedCardCountries) &&
      p.allowedCardCountries.length >= 1 &&
      p.allowedCardCountries.length <= 249 &&
      new Set(p.allowedCardCountries).size === p.allowedCardCountries.length &&
      p.allowedCardCountries.every((x) => typeof x === 'string' && /^[A-Z]{2}$/.test(x)),
    'card_country_policy',
    'Record the campaign-approved issuer-country list; issuer country does not establish citizenship.',
  );
  return structuredClone(p);
}
export function cardMandate(input) {
  const m = exactKeys(input, [
    'id',
    'enrollmentId',
    'donorId',
    'donorVersion',
    'environment',
    'customerId',
    'paymentMethodId',
    'amountCents',
    'frequency',
    'election',
    'firstAt',
    'endAt',
    'maxInstallments',
    'termsVersion',
    'consentDigest',
  ]);
  for (const key of ['id', 'enrollmentId', 'donorId']) financeId(m[key]);
  assert(
    Number.isSafeInteger(m.donorVersion) &&
      m.donorVersion >= 1 &&
      ['test', 'live'].includes(m.environment) &&
      provider(m.customerId, 'cus') &&
      provider(m.paymentMethodId, 'pm') &&
      amount(m.amountCents) &&
      ['once', 'monthly'].includes(m.frequency) &&
      ['primary', 'general'].includes(m.election) &&
      stamp(m.firstAt) &&
      stamp(m.endAt) &&
      Date.parse(m.endAt) >= Date.parse(m.firstAt) &&
      Number.isSafeInteger(m.maxInstallments) &&
      m.maxInstallments >= 1 &&
      m.maxInstallments <= 120 &&
      (m.frequency !== 'once' || m.maxInstallments === 1) &&
      terms(m.termsVersion) &&
      hash(m.consentDigest),
    'invalid_card_mandate',
    'Use the exact documented contributor revision, saved-card authority, amount, frequency, cutoff and terms.',
  );
  return structuredClone(m);
}
function monthAt(stamp, index) {
  const first = new Date(stamp),
    month = first.getUTCMonth() + index,
    year = first.getUTCFullYear() + Math.floor(month / 12),
    day = Math.min(first.getUTCDate(), new Date(Date.UTC(year, (month % 12) + 1, 0)).getUTCDate());
  return new Date(
    Date.UTC(
      year,
      month % 12,
      day,
      first.getUTCHours(),
      first.getUTCMinutes(),
      first.getUTCSeconds(),
      first.getUTCMilliseconds(),
    ),
  ).toISOString();
}
export function cardInstallmentAt(input, index) {
  const m = cardMandate(input);
  assert(
    Number.isSafeInteger(index) && index >= 0 && index < m.maxInstallments,
    'card_installment_index',
    'Use a current explicit installment number.',
  );
  if (m.frequency === 'once') {
    assert(
      index === 0,
      'card_installment_index',
      'One-time intent cannot create another installment.',
    );
    return m.firstAt;
  }
  return monthAt(m.firstAt, index);
}
export function decideCardInstallment({
  rules,
  treasury,
  mandate,
  index,
  periodId,
  postedCents,
  reservedCents,
  activeSchedules,
  openCaseCount,
  donorVersion,
  now = Date.now(),
}) {
  const p = cardContributionPolicy(rules, treasury, now),
    t = treasuryPolicy(treasury, now),
    m = cardMandate(mandate);
  financeId(periodId);
  assert(
    t.sources.some(
      (s) =>
        s.id === (m.environment === 'test' ? 'stripe-test' : 'stripe') &&
        s.channel === 'card' &&
        s.environment === m.environment,
    ),
    'card_source_unapproved',
    'The current treasury rules do not approve this card source and environment.',
    409,
  );
  assert(
    m.termsVersion === p.termsVersion &&
      m.donorVersion === donorVersion &&
      m.maxInstallments <= p.maxInstallments &&
      Number.isSafeInteger(activeSchedules) &&
      activeSchedules >= 1 &&
      activeSchedules <= p.maxSchedulesPerDonor &&
      openCaseCount === 0,
    'card_review_required',
    'Current contributor, terms, schedule authority or unresolved treasury casework needs review before another payment.',
    409,
  );
  const at = cardInstallmentAt(m, index),
    cutoff = Math.min(
      Date.parse(m.endAt),
      Date.parse(p.electionEnds[m.election]),
      Date.parse(p.validUntil),
      m.frequency === 'monthly' ? Date.parse(monthAt(m.firstAt, index + 1)) : Infinity,
    );
  assert(
    Date.parse(at) <= now && now <= cutoff,
    'card_installment_not_due',
    'The installment is early or its mandate/election/policy expired. No processor attempt is authorized.',
    409,
  );
  assert(
    total(postedCents) && total(reservedCents),
    'card_aggregate_required',
    'Read exact all-channel posted and reserved integer totals under the finance transaction lock.',
    409,
  );
  assert(
    BigInt(postedCents) + BigInt(reservedCents) + BigInt(m.amountCents) <=
      BigInt(t.electionLimits[m.election]),
    'card_contribution_limit',
    'The current all-channel election limit leaves insufficient room. Nothing may be charged.',
    409,
  );
  const expiresAt = new Date(
    Math.min(cutoff, now + p.reservationSeconds * 1000, now + 300000),
  ).toISOString();
  assert(
    Date.parse(expiresAt) > now,
    'card_dispatch_expired',
    'There is no current dispatch window.',
    409,
  );
  return {
    periodId,
    index,
    scheduledAt: at,
    amountCents: m.amountCents,
    election: m.election,
    environment: m.environment,
    donorId: m.donorId,
    donorVersion: m.donorVersion,
    policyId: p.id,
    policyVersion: p.version,
    treasuryPolicyId: t.id,
    treasuryPolicyVersion: t.version,
    expiresAt,
  };
}
