import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  cardMandate,
  cardInstallmentAt,
  decideCardInstallment,
} from '../packages/core/card-mandates.mjs';
import { MANUAL_CAPTURE_PROFILE } from '../packages/core/stripe-manual-capture.mjs';
const now = Date.parse('2026-01-31T12:00:00.000Z');
function inputs() {
  const treasury = {
    id: randomUUID(),
    version: 1,
    validUntil: '2026-12-31T12:00:00.000Z',
    evidenceDigest: 'a'.repeat(64),
    remedyDays: 30,
    deadlineBasis: 'received_at',
    followupDays: 7,
    maxFollowups: 3,
    electionLimits: { primary: 10000, general: 10000 },
    sources: [
      { id: 'stripe-test', channel: 'card', environment: 'test' },
      { id: 'offline-checks', channel: 'check', environment: 'test' },
    ],
    exportSystem: {
      id: 'synthetic',
      evidenceDigest: 'b'.repeat(64),
      columns: [
        'event_id',
        'event_kind',
        'gift_id',
        'source',
        'environment',
        'donor_reference',
        'election',
        'amount_cents',
        'effect_cents',
        'event_received_at',
      ].map((field) => ({ field, header: field })),
    },
  };
  const rules = {
      id: randomUUID(),
      version: 1,
      profile: MANUAL_CAPTURE_PROFILE,
      parentPolicyId: treasury.id,
      parentPolicyVersion: 1,
      validUntil: treasury.validUntil,
      electionEnds: { primary: '2026-12-31T00:00:00.000Z', general: '2026-12-31T00:00:00.000Z' },
      maxInstallments: 12,
      maxSchedulesPerDonor: 2,
      reservationSeconds: 120,
      termsVersion: '2026-01-01-synthetic-only',
      allowedCardCountries: ['US', 'CA'],
      evidenceDigest: 'c'.repeat(64),
    },
    mandate = {
      id: randomUUID(),
      enrollmentId: randomUUID(),
      donorId: randomUUID(),
      donorVersion: 1,
      environment: 'test',
      customerId: 'cus_synthetic12345',
      paymentMethodId: 'pm_synthetic12345',
      amountCents: 2500,
      frequency: 'monthly',
      election: 'general',
      firstAt: '2026-01-31T12:00:00.000Z',
      endAt: '2026-12-30T00:00:00.000Z',
      maxInstallments: 12,
      termsVersion: rules.termsVersion,
      consentDigest: 'd'.repeat(64),
    };
  return {
    rules,
    treasury,
    mandate,
    index: 0,
    periodId: randomUUID(),
    postedCents: '0',
    reservedCents: '0',
    activeSchedules: 1,
    openCaseCount: 0,
    donorVersion: 1,
    now,
  };
}
test('monthly calendar preserves the donor anchor across short months rather than drifting after February', () => {
  const { mandate } = inputs();
  assert.equal(cardInstallmentAt(mandate, 1), '2026-02-28T12:00:00.000Z');
  assert.equal(cardInstallmentAt(mandate, 2), '2026-03-31T12:00:00.000Z');
  assert.equal(
    cardInstallmentAt(
      { ...mandate, firstAt: '2028-01-31T12:00:00.000Z', endAt: '2028-12-31T00:00:00.000Z' },
      1,
    ),
    '2028-02-29T12:00:00.000Z',
  );
  assert.throws(() => cardInstallmentAt({ ...mandate, frequency: 'once', maxInstallments: 1 }, 1));
});
test('all-channel and in-flight reservations constrain a new installment with exact integer arithmetic', () => {
  const base = inputs();
  const decision = decideCardInstallment({ ...base, postedCents: '5000', reservedCents: '2500' });
  assert.equal(decision.amountCents, 2500);
  assert.equal(decision.expiresAt, '2026-01-31T12:02:00.000Z');
  for (const totals of [
    { postedCents: '5001', reservedCents: '2500' },
    { postedCents: '9007199254740993000', reservedCents: '0' },
    { postedCents: '0', reservedCents: '10000' },
  ])
    assert.throws(
      () => decideCardInstallment({ ...base, ...totals }),
      (e) => e.code === 'card_contribution_limit',
    );
});
test('expiry, changed contributor/terms/rules, unresolved cases, early installments and excessive schedules block dispatch', () => {
  const b = inputs();
  assert.equal(decideCardInstallment(b).periodId, b.periodId);
  for (const change of [
    { now: Date.parse(b.rules.validUntil) + 1 },
    { index: 1 },
    { now: Date.parse('2026-04-01T12:00:00.000Z') },
    { openCaseCount: 1 },
    { donorVersion: 2 },
    { activeSchedules: 3 },
    { rules: { ...b.rules, parentPolicyVersion: 2 } },
    { rules: { ...b.rules, termsVersion: '2026-01-02-synthetic-only' } },
    { mandate: { ...b.mandate, endAt: b.mandate.firstAt }, now: now + 1 },
  ])
    assert.throws(() => decideCardInstallment({ ...b, ...change }));
  assert.throws(() => cardMandate({ ...b.mandate, cardNumber: 'DO_NOT_ACCEPT_CARD_DATA' }));
});
