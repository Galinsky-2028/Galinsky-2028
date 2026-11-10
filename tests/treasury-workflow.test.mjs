import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import {
  treasuryPolicy,
  treasuryDonor,
  treasuryEntry,
  projectTreasury,
  treasuryNet,
  settlementDocument,
  financeCase,
  advanceFinanceCase,
} from '../packages/core/treasury-workflow.mjs';
import { sealFinanceIdentity, openFinanceIdentity } from '../packages/core/treasury-private.mjs';
import { requestStripeTestRefund } from '../packages/core/stripe-treasury-actions.mjs';
import {
  fixturePolicy,
  fixtureDonor,
  fixtureEntry,
  evidence,
} from './helpers/treasury-fixtures.mjs';
test('financial profiles require actual expiring source/election/deadline/export decisions and preserve distinct contributor authority', () => {
  const now = Date.now(),
    p = treasuryPolicy(fixturePolicy(now), now),
    d = treasuryDonor(fixtureDonor());
  assert.equal(p.sources[0].environment, 'test');
  assert.equal(d.occupation, null);
  assert.throws(() => treasuryPolicy({ ...p, validUntil: new Date(now - 1).toISOString() }, now));
  assert.throws(() =>
    treasuryPolicy({ ...p, sources: [{ id: 'chase', channel: 'card', environment: 'test' }] }, now),
  );
  assert.throws(() =>
    treasuryPolicy(
      {
        ...p,
        exportSystem: { ...p.exportSystem, columns: [{ field: 'card_number', header: 'card' }] },
      },
      now,
    ),
  );
  assert.throws(() => treasuryDonor({ ...d, cardNumber: 'must never be accepted' }));
  const key = randomBytes(32).toString('base64'),
    envelope = sealFinanceIdentity(d.id, 1, d, key);
  assert(!envelope.includes(d.street));
  assert.deepEqual(openFinanceIdentity(d.id, 1, envelope, key), d);
  assert.throws(() => openFinanceIdentity(randomUUID(), 1, envelope, key));
  assert.throws(() => openFinanceIdentity(d.id, 2, envelope, key));
  assert.throws(() => openFinanceIdentity(d.id, 1, envelope, randomBytes(32).toString('base64')));
});
test('append-only projections preserve gross, refunds, fees, disputes, donor intent and election allocations without silently clearing conflicts', () => {
  const now = Date.now(),
    p = treasuryPolicy(fixturePolicy(now), now),
    d = fixtureDonor(),
    gift = treasuryEntry(fixtureEntry(d.id, { amountCents: 2500 }, now), p, now);
  let s = projectTreasury(null, gift);
  const event = (kind, amountCents, extra = {}) =>
    treasuryEntry(
      fixtureEntry(null, { giftId: gift.id, kind, amountCents, ...extra }, now),
      p,
      now,
    );
  s = projectTreasury(s, event('fee', 100));
  s = projectTreasury(s, event('refund', 500));
  assert.equal(treasuryNet(s), 1900);
  assert.equal(s.grossCents, 2500);
  assert.equal(s.allocations.general, 2000);
  s = projectTreasury(s, event('dispute', 500));
  assert.throws(() => projectTreasury(s, event('refund', 1)));
  assert.throws(() => projectTreasury(s, event('dispute_closed', 501, { outcome: 'won' })));
  s = projectTreasury(s, event('dispute_closed', 500, { outcome: 'lost' }));
  assert.equal(s.chargebackCents, 500);
  assert.equal(s.disputedCents, 0);
  assert.equal(treasuryNet(s), 1400);
  s = projectTreasury(
    s,
    event('redesignation', 300, { targetElection: 'primary', intentDigest: evidence }),
  );
  assert.deepEqual(s.allocations, { primary: 300, general: 1200 });
  assert.throws(() =>
    projectTreasury(
      s,
      event('redesignation', 1201, { targetElection: 'primary', intentDigest: evidence }),
    ),
  );
  const newDonor = randomUUID();
  s = projectTreasury(
    s,
    event('reattribution', 1500, { donorId: newDonor, intentDigest: evidence }),
  );
  assert.equal(s.donorId, newDonor);
  assert.equal(s.version, 7);
  assert.throws(() => projectTreasury(s, event('refund', 2501)));
  assert.throws(() => projectTreasury(null, event('refund', 1)));
  s = projectTreasury(s, event('correction', 100, { outcome: 'decrease' }));
  assert.equal(s.grossCents, 2400);
  assert.equal(s.allocations.general, 1100);
  assert.equal(treasuryNet(s), 1300);
  assert.equal(gift.amountCents, 2500, 'the original source event remains unchanged');
  assert.throws(() => event('correction', 100, { source: 'stripe-test', outcome: 'increase' }));
});
test('settlements reconcile exact unique source effects; mismatches remain explicit and cross-mode/duplicate source membership fails', () => {
  const now = Date.now(),
    p = fixturePolicy(now),
    g = treasuryEntry(fixtureEntry(randomUUID(), {}, now), p, now),
    f = treasuryEntry(
      fixtureEntry(null, { kind: 'fee', giftId: g.id, amountCents: 30 }, now),
      p,
      now,
    ),
    input = {
      id: randomUUID(),
      source: g.source,
      environment: 'test',
      externalReference: 'synthetic-payout',
      entryIds: [g.id, f.id],
      grossCents: 1000,
      refundCents: 0,
      feeCents: 30,
      chargebackCents: 0,
      netCents: 970,
      settledAt: new Date(now).toISOString(),
      evidenceDigest: evidence,
    };
  assert(settlementDocument(input, [g, f]).balanced);
  assert.equal(settlementDocument({ ...input, netCents: 969 }, [g, f]).balanced, false);
  assert.throws(() => settlementDocument({ ...input, entryIds: [g.id, g.id] }, [g, g]));
  assert.throws(() => settlementDocument({ ...input, environment: 'live' }, [g, f]));
});
test('finance follow-up uses the approved bounded schedule, immutable version and evidence instead of claiming legal sufficiency', () => {
  const now = Date.now(),
    p = fixturePolicy(now),
    item = financeCase(
      {
        id: randomUUID(),
        giftId: randomUUID(),
        kind: 'missing_information',
        evidenceDigest: evidence,
      },
      p,
      now,
      { receivedAt: new Date(now).toISOString() },
    ),
    first = advanceFinanceCase(
      item,
      { version: 1, action: 'followup', evidenceDigest: evidence },
      now,
    );
  assert.equal(first.followups, 1);
  const oldReceipt=new Date(now-40*86400000).toISOString();
  const overdue=financeCase({id:randomUUID(),giftId:randomUUID(),kind:'missing_information',evidenceDigest:evidence},p,now,{receivedAt:oldReceipt});
  assert.equal(overdue.deadline,new Date(now-10*86400000).toISOString(),'opening an old gift case cannot restart the source-based remedy deadline');
  assert.throws(() =>
    advanceFinanceCase(first, { version: 2, action: 'followup', evidenceDigest: evidence }, now),
  );
  const second = advanceFinanceCase(
    first,
    { version: 2, action: 'followup', evidenceDigest: evidence },
    now + 3 * 86400000,
  );
  assert.equal(second.followups, 2);
  assert.throws(() =>
    advanceFinanceCase(
      second,
      { version: 3, action: 'followup', evidenceDigest: evidence },
      now + 6 * 86400000,
    ),
  );
  const closed = advanceFinanceCase(
    second,
    { version: 3, action: 'close', evidenceDigest: evidence },
    now + 6 * 86400000,
  );
  assert.equal(closed.status, 'closed');
  assert.throws(() =>
    advanceFinanceCase(closed, { version: 4, action: 'review', evidenceDigest: evidence }, now),
  );
});
test('the installed financial executor accepts only original TEST payments and stable idempotent refund commands, never live keys', async () => {
  const commandId = randomUUID(),
    args = {
      secretKey: 'sk_' + 'test_' + 'synthetic0000000000',
      sessionId: 'cs_test_synthetic12345',
      clientReference: 'attempt_' + 'a'.repeat(32),
      originalAmountCents: 1000,
      amountCents: 200,
      commandId,
    },
    calls = [],
    transport = async (url, options) => {
      calls.push({ url, options });
      return new Response(
        JSON.stringify(
          url.endsWith('/refunds')
            ? {
                id: 're_synthetic12345',
                amount: 200,
                currency: 'usd',
                payment_intent: 'pi_synthetic12345',
                status: 'pending',
              }
            : {
                id: args.sessionId,
                livemode: false,
                client_reference_id: args.clientReference,
                amount_total: 1000,
                currency: 'usd',
                payment_status: 'paid',
                payment_intent: 'pi_synthetic12345',
              },
        ),
      );
    };
  assert.equal((await requestStripeTestRefund({ ...args, transport })).status, 'pending');
  assert.equal(calls[1].options.headers['Idempotency-Key'], 'g28-treasury-refund-' + commandId);
  assert.equal(
    new URLSearchParams(calls[1].options.body).get('metadata[g28_treasury_command]'),
    commandId,
  );
  const before = calls.length;
  await assert.rejects(
    requestStripeTestRefund({ ...args, secretKey: 'sk_' + 'live_' + 'synthetic0000000000', transport }),
  );
  assert.equal(calls.length, before);
  await assert.rejects(
    requestStripeTestRefund({
      ...args,
      transport: async () => new Response(JSON.stringify({ id: args.sessionId, livemode: true })),
    }),
  );
});
