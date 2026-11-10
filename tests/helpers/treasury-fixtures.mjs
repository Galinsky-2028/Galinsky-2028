import { randomUUID, createHash } from 'node:crypto';
import { exportFields } from '../../packages/core/treasury-workflow.mjs';
export const evidenceContent =
  'Synthetic approved treasury evidence — no real contributor or transaction';
export const evidence = createHash('sha256').update(evidenceContent).digest('hex');
export const fixturePolicy = (now = Date.now()) => ({
  id: randomUUID(),
  version: 1,
  validUntil: new Date(now + 30 * 86400000).toISOString(),
  evidenceDigest: evidence,
  remedyDays: 30,
  deadlineBasis: 'received_at',
  followupDays: 3,
  maxFollowups: 2,
  electionLimits: { primary: 1500, general: 1500 },
  sources: [
    { id: 'cash-test', channel: 'cash', environment: 'test' },
    { id: 'stripe-test', channel: 'card', environment: 'test' },
    { id: 'cash-live', channel: 'cash', environment: 'live' },
  ],
  exportSystem: {
    id: 'synthetic-accounting',
    columns: exportFields.map((field) => ({ field, header: field })),
    evidenceDigest: evidence,
  },
});
export const fixtureDonor = () => ({
  id: randomUUID(),
  name: '=SUM(1,2)',
  street: '1 Synthetic Test Street',
  city: 'Test City',
  region: 'TS',
  postal: '00000',
  country: 'US',
  occupation: null,
  employer: null,
  email: null,
  evidenceDigest: evidence,
});
export const fixtureEntry = (donorId, overrides = {}, now = Date.now()) => {
  const id = randomUUID(),
    date = new Date(now - 60000).toISOString();
  return {
    id,
    kind: 'gift',
    giftId: id,
    source: 'cash-test',
    externalReference: 'synthetic-' + id,
    environment: 'test',
    amountCents: 1000,
    donorId,
    election: 'general',
    targetElection: null,
    madeAt: date,
    receivedAt: date,
    evidenceDigest: evidence,
    intentDigest: null,
    outcome: null,
    ...overrides,
  };
};
