import { sealFinanceEvidence } from '../../packages/core/treasury-private.mjs';
import { processOneMailJob } from '../../apps/api/src/worker.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes, createHash, createHmac } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { PostgresStore, databasePool } from '../../apps/api/src/postgres-store.mjs';
import { StripeCampaignStore } from '../../apps/web/stripe-campaign-store.mjs';
import { createApp } from '../../apps/api/src/app.mjs';
import { randomToken, tokenHash } from '../../packages/core/auth.mjs';
import {
  fixturePolicy,
  fixtureDonor,
  fixtureEntry,
  evidence,
  evidenceContent,
} from '../helpers/treasury-fixtures.mjs';
const base = process.env.TEST_DATABASE_URL;
test(
  'all-channel treasury HTTP/SQL, signed remedies, immutable source history, banking, donor mapping and safe uncertain commands',
  { skip: !base },
  async () => {
    assert(['localhost', '127.0.0.1'].includes(new URL(base).hostname));
    const name = 'g28_treasury_' + randomBytes(5).toString('hex'),
      admin = databasePool(base),
      url = new URL(base);
    url.pathname = '/' + name;
    await admin.query('CREATE DATABASE ' + name);
    const pool = databasePool(url.href),
      store = new PostgresStore(pool),
      stripe = new StripeCampaignStore(pool),
      now = Math.floor(Date.now() / 1000) * 1000,
      origin = 'http://localhost:4322',
      ownerKey = tokenHash(randomUUID()),
      config = {
        staffIdentity: true,
        adminLoginReady: true,
        adminOwnerEmailKey: ownerKey,
        portalOrigin: origin,
        publicOrigin: 'http://localhost:4321',
        treasuryKey: randomBytes(32).toString('base64'),
        treasurySandboxActions: true,
        stripeTestKey: 'sk_' + 'test_' + 'syntheticTreasury0000000',
      };
    const clientRef = 'attempt_' + randomBytes(16).toString('hex'),
      sessionId = 'cs_test_synthetic' + randomBytes(8).toString('hex'),
      paymentIntent = 'pi_synthetic' + randomBytes(8).toString('hex'),
      refundId = 're_synthetic' + randomBytes(8).toString('hex'),
      webhookKey = 'whsec_syntheticTreasury0000000000';
    let providerCalls = 0,
      refundCommand;
    const transport = async (path, options) => {
      providerCalls++;
      if (path.endsWith('/refunds')) {
        const b = new URLSearchParams(options.body);
        refundCommand = b.get('metadata[g28_treasury_command]');
        assert.equal(options.headers['Idempotency-Key'], 'g28-treasury-refund-' + refundCommand);
        return new Response(
          JSON.stringify({
            id: refundId,
            amount: 500,
            currency: 'usd',
            payment_intent: paymentIntent,
            status: 'pending',
          }),
        );
      }
      return new Response(
        JSON.stringify({
          id: sessionId,
          livemode: false,
          client_reference_id: clientRef,
          amount_total: 2000,
          currency: 'usd',
          payment_status: 'paid',
          payment_intent: paymentIntent,
        }),
      );
    };
    const app = createApp({ store, config, clock: () => now, financeTransport: transport }),
      send = (who, path, payload = {}) =>
        app.inject({
          method: 'POST',
          url: '/api/staff/finance/' + path,
          headers: who.headers,
          payload,
        });
    async function actor(role) {
      const id = randomUUID(),
        key = role === 'owner' ? ownerKey : tokenHash(id),
        token = randomToken(),
        hash = tokenHash(token),
        csrf = randomToken();
      await pool.query(
        "INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'synthetic',now(),'synthetic')",
        [id, key],
      );
      await pool.query(
        'INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',
        [hash, id, csrf, new Date(now + 86400000)],
      );
      if (role !== 'owner')
        await pool.query(
          "INSERT INTO g28.admin_grants(email_key,role,display_label,granted_by) VALUES($1,$2,'Synthetic finance staff',$3)",
          [key, role, owner.id],
        );
      await store.withStaffSecurity(id, (s) => {
        s.credentials = [{ id: 'fixture' }];
        s.sessions = { [hash]: { credentialId: 'fixture', expires: now + 900000 } };
      });
      return {
        id,
        key,
        hash,
        headers: {
          origin,
          cookie: 'g28-local=' + token,
          'content-type': 'application/json',
          'x-csrf-token': csrf,
        },
      };
    }
    async function webhook(type, object) {
      const id = 'evt_synthetic' + randomBytes(8).toString('hex'),
        raw = Buffer.from(
          JSON.stringify({ id, type, created: now / 1000, livemode: false, data: { object } }),
        ),
        header =
          't=' +
          now / 1000 +
          ',v1=' +
          createHmac('sha256', webhookKey)
            .update(now / 1000 + '.')
            .update(raw)
            .digest('hex');
      const result = await stripe.receiveSignedWebhook({
        raw,
        header,
        secret: webhookKey,
        sandbox: true,
      });
      return { id, raw, header, digest: createHash('sha256').update(raw).digest('hex'), result };
    }
    let owner;
    try {
      for (const file of (await readdir('db/migrations')).filter((x) => x.endsWith('.sql')).sort())
        await pool.query(await readFile('db/migrations/' + file, 'utf8'));
      owner = await actor('owner');
      const treasurer = await actor('treasurer'),
        editor = await actor('editor'),
        auditor = await actor('auditor');
      assert.equal((await send(editor, 'overview')).statusCode, 403);
      assert.equal((await send(auditor, 'overview')).statusCode, 403);
      assert.equal(
        (
          await send(
            { ...owner, headers: { ...owner.headers, 'x-csrf-token': 'wrong' } },
            'overview',
          )
        ).statusCode,
        403,
      );
      assert.equal(
        (
          await send(owner, 'evidence', {
            id: randomUUID(),
            filename: 'synthetic-evidence.txt',
            mediaType: 'text/plain',
            content: Buffer.from(evidenceContent).toString('base64'),
          })
        ).statusCode,
        200,
      );
      const p = fixturePolicy(now),
        policy = await send(owner, 'policies', {
          policy: p,
          confirm: 'approve these treasury rules',
        });
      assert.equal(policy.statusCode, 200, policy.body);
      const d = fixtureDonor();
      let response = await send(owner, 'donors', { donor: d, expectedVersion: 0 });
      assert.equal(response.statusCode, 200, response.body);
      assert.equal(response.json().version, 1);
      assert.equal(
        (
          await send(treasurer, 'donors', {
            donor: { ...d, name: 'Wrong stale update' },
            expectedVersion: 0,
          })
        ).statusCode,
        409,
      );
      const another = { ...d, id: randomUUID() };
      assert.equal(
        (await send(owner, 'donors', { donor: another, expectedVersion: 0 })).statusCode,
        200,
      );
      assert.equal(
        (await pool.query('SELECT count(*)::int AS n FROM g28.treasury_donors')).rows[0].n,
        2,
        'same names never merge donor identities',
      );
      const sql = JSON.stringify((await pool.query('SELECT * FROM g28.treasury_donors')).rows);
      assert(!sql.includes(d.street));
      assert(!sql.includes(d.name));
      const cash = fixtureEntry(d.id, {}, now),
        post = (entry) =>
          send(treasurer, 'journal', { entry, confirm: 'record verified source evidence' });
      response = await post(cash);
      assert.equal(response.statusCode, 200, response.body);
      assert.deepEqual(response.json().issues, ['missing_information']);
      assert.equal((await post(cash)).json().duplicate, true);
      await send(owner, 'donors', {
        donor: { ...d, employer: 'Synthetic employer', occupation: 'Synthetic occupation' },
        expectedVersion: 1,
      });
      assert.equal(
        (await post(cash)).json().duplicate,
        true,
        'replay remains bound to the originally recorded identity revision',
      );
      assert.equal(
        (
          await pool.query(
            'SELECT count(*)::int AS n FROM g28.treasury_donor_revisions WHERE donor_id=$1',
            [d.id],
          )
        ).rows[0].n,
        2,
      );
      await stripe.recordSession({
        clientRef,
        sessionId,
        amountCents: 2000,
        election: 'general',
        livemode: false,
      });
      const captured = await webhook('checkout.session.completed', {
        id: sessionId,
        payment_status: 'paid',
        amount_total: 2000,
        currency: 'usd',
        client_reference_id: clientRef,
        payment_intent: paymentIntent,
        metadata: { election: 'general' },
      });
      assert.equal(captured.result.status, 200);
      const card = fixtureEntry(
        d.id,
        {
          source: 'stripe-test',
          externalReference: captured.id,
          amountCents: 2000,
          receivedAt: new Date(now).toISOString(),
          evidenceDigest: captured.digest,
        },
        now,
      );
      assert.equal((await post({ ...card, evidenceDigest: evidence })).statusCode, 409);
      response = await post(card);
      assert.equal(response.statusCode, 200, response.body);
      assert.equal(response.json().aggregates.general, '3000');
      assert(response.json().issues.includes('excess'));
      assert.equal((await post(card)).json().duplicate, true);
      const fee = fixtureEntry(null, { kind: 'fee', giftId: cash.id, amountCents: 20 }, now);
      assert.equal((await post(fee)).statusCode, 200);
      const settlement = {
        id: randomUUID(),
        source: 'cash-test',
        environment: 'test',
        externalReference: 'synthetic-payout',
        entryIds: [cash.id, fee.id],
        grossCents: 1000,
        refundCents: 0,
        feeCents: 20,
        chargebackCents: 0,
        netCents: 980,
        settledAt: new Date(now).toISOString(),
        evidenceDigest: evidence,
      };
      response = await send(treasurer, 'settlements', settlement);
      assert.equal(response.statusCode, 200, response.body);
      assert(response.json().settlement.balanced);
      assert.equal(response.json().bankConfirmed, false);
      assert.equal(
        (
          await send(treasurer, 'settlements', {
            ...settlement,
            id: randomUUID(),
            externalReference: 'cannot-reuse-effects',
          })
        ).statusCode,
        409,
      );
      const deposit = (n) => ({
        id: randomUUID(),
        settlementId: settlement.id,
        bankReference: 'synthetic-bank-' + n,
        amountCents: n,
        receivedAt: new Date(now).toISOString(),
        evidenceDigest: evidence,
      });
      assert.equal((await send(treasurer, 'deposits', deposit(500))).json().balanced, false);
      assert.equal((await send(treasurer, 'deposits', deposit(480))).json().balanced, true);
      const refundCase = {
        id: randomUUID(),
        giftId: card.id,
        kind: 'refund',
        evidenceDigest: evidence,
      };
      assert.equal((await send(treasurer, 'cases', refundCase)).statusCode, 200);
      const command = {
        id: randomUUID(),
        caseId: refundCase.id,
        caseVersion: 1,
        amountCents: 500,
        evidenceDigest: evidence,
        confirm: 'request this Stripe TEST refund',
      };
      response = await send(treasurer, 'commands/refund-test', command);
      assert.equal(response.statusCode, 200, response.body);
      assert.equal(response.json().ledgerReconciled, false);
      assert.equal(providerCalls, 2);
      assert.equal((await send(treasurer, 'commands/refund-test', command)).json().duplicate, true);
      assert.equal(providerCalls, 2);
      assert.equal(
        (await send(treasurer, 'commands/refund-test', { ...command, id: randomUUID() }))
          .statusCode,
        409,
      );
      assert.equal(
        (await pool.query('SELECT state FROM g28.treasury_gifts WHERE id=$1', [card.id])).rows[0]
          .state.refundedCents,
        0,
      );
      const pending = await webhook('refund.created', {
        id: refundId,
        payment_intent: paymentIntent,
        amount: 500,
        currency: 'usd',
        status: 'pending',
        metadata: { g28_treasury_command: refundCommand },
      });
      assert.equal(pending.result.status, 200);
      assert.equal(
        (
          await pool.query('SELECT 1 FROM g28.financial_provider_events WHERE event_id=$1', [
            refundId,
          ])
        ).rowCount,
        0,
      );
      const refunded = await webhook('refund.updated', {
        id: refundId,
        payment_intent: paymentIntent,
        amount: 500,
        currency: 'usd',
        status: 'succeeded',
        metadata: { g28_treasury_command: refundCommand },
      });
      assert.equal(refunded.result.status, 200);
      assert.equal(
        (
          await stripe.receiveSignedWebhook({
            raw: refunded.raw,
            header: refunded.header,
            secret: webhookKey,
            sandbox: true,
          })
        ).outcome,
        'duplicate',
      );
      const refundEntry = fixtureEntry(
        null,
        {
          kind: 'refund',
          source: 'stripe-test',
          giftId: card.id,
          externalReference: refundId,
          amountCents: 500,
          receivedAt: new Date(now).toISOString(),
          evidenceDigest: refunded.digest,
        },
        now,
      );
      response = await post(refundEntry);
      assert.equal(response.statusCode, 200, response.body);
      assert.equal(
        (
          await send(treasurer, 'commands/' + command.id + '/reconcile', {
            journalEntryId: refundEntry.id,
          })
        ).statusCode,
        200,
      );
      const disputedId = 'dp_synthetic' + randomBytes(8).toString('hex'),
        disputed = await webhook('charge.dispute.created', {
          id: disputedId,
          payment_intent: paymentIntent,
          amount: 500,
          currency: 'usd',
          status: 'needs_response',
        });
      assert.equal(disputed.result.status, 200);
      assert.equal(
        (
          await post(
            fixtureEntry(
              null,
              {
                kind: 'dispute',
                source: 'stripe-test',
                giftId: card.id,
                externalReference: disputedId,
                amountCents: 500,
                receivedAt: new Date(now).toISOString(),
                evidenceDigest: disputed.digest,
              },
              now,
            ),
          )
        ).statusCode,
        200,
      );
      const lost = await webhook('charge.dispute.closed', {
        id: disputedId,
        payment_intent: paymentIntent,
        amount: 500,
        currency: 'usd',
        status: 'lost',
      });
      assert.equal(lost.result.status, 200);
      response = await post(
        fixtureEntry(
          null,
          {
            kind: 'dispute_closed',
            outcome: 'lost',
            source: 'stripe-test',
            giftId: card.id,
            externalReference: lost.id,
            amountCents: 500,
            receivedAt: new Date(now).toISOString(),
            evidenceDigest: lost.digest,
          },
          now,
        ),
      );
      assert.equal(response.statusCode, 200, response.body);
      assert.equal(response.json().gift.chargebackCents, 500);
      const exportInput = {
        from: new Date(now - 86400000).toISOString(),
        until: new Date(now + 86400000).toISOString(),
        environment: 'test',
        format: 'json',
        includeIdentity: true,
        confirm: 'export approved treasury report',
      };
      response = await send(treasurer, 'export', exportInput);
      assert.equal(response.statusCode, 200, response.body);
      assert.deepEqual(response.json().totals, {
        grossCents: 3000,
        refundCents: 500,
        feeCents: 20,
        chargebackCents: 500,
        netCents: 1980,
        primaryAllocatedCents: 0,
        generalAllocatedCents: 2000,
      });
      assert.equal(response.json().records.length, 6);
      assert.equal(
        response.json().records.find((r) => r.event_id === cash.id).employer,
        '',
        'export preserves the exact original donor revision',
      );
      assert(!response.body.includes(config.treasuryKey));
      const csv = await send(owner, 'export', { ...exportInput, format: 'csv' });
      assert.equal(csv.statusCode, 200);
      assert(csv.body.includes('"\'=SUM(1,2)"'));
      const privateExport = await send(treasurer, 'export', {
        ...exportInput,
        includeIdentity: false,
      });
      assert.equal(privateExport.statusCode, 200);
      assert(!privateExport.body.includes(d.street));
      assert(!privateExport.body.includes(d.name));
      const correction = fixtureEntry(
        null,
        { kind: 'correction', giftId: cash.id, amountCents: 100, outcome: 'decrease' },
        now,
      );
      response = await post(correction);
      assert.equal(response.statusCode, 200, response.body);
      assert.equal(response.json().gift.grossCents, 900);
      assert.equal(
        (await pool.query('SELECT document FROM g28.treasury_journal WHERE id=$1', [cash.id]))
          .rows[0].document.amountCents,
        1000,
      );
      const correctedReport = await send(treasurer, 'export', exportInput);
      assert.equal(correctedReport.statusCode, 200, correctedReport.body);
      assert.equal(correctedReport.json().totals.grossCents, 2900);
      assert.equal(correctedReport.json().totals.netCents, 1880);
      const noticeCase = {
        id: randomUUID(),
        giftId: card.id,
        kind: 'missing_information',
        evidenceDigest: evidence,
      };
      await send(treasurer, 'cases', noticeCase);
      assert.equal(
        (
          await send(treasurer, 'cases/' + noticeCase.id, {
            version: 1,
            action: 'notify',
            evidenceDigest: evidence,
          })
        ).statusCode,
        503,
      );
      assert.equal(
        (await pool.query('SELECT version FROM g28.treasury_cases WHERE id=$1', [noticeCase.id]))
          .rows[0].version,
        1,
      );
      await send(owner, 'donors', {
        donor: {
          ...d,
          employer: 'Synthetic employer',
          occupation: 'Synthetic occupation',
          email: 'synthetic-donor@example.test',
        },
        expectedVersion: 2,
      });
      Object.assign(config, {
        mailReady: true,
        deliveryKey: randomBytes(32).toString('base64'),
        pepper: randomBytes(32).toString('hex'),
        mailKey: 'synthetic-mail-key',
        mailFrom: 'Campaign <synthetic@example.test>',
      });
      const queued = await send(treasurer, 'cases/' + noticeCase.id, {
        version: 1,
        action: 'notify',
        evidenceDigest: evidence,
      });
      assert.equal(queued.statusCode, 200, queued.body);
      assert.equal(
        (
          await send(treasurer, 'cases/' + noticeCase.id, {
            version: 1,
            action: 'notify',
            evidenceDigest: evidence,
          })
        ).statusCode,
        409,
      );
      const outbox = (
        await pool.query("SELECT payload_envelope FROM g28.outbox WHERE kind='finance_attention'")
      ).rows;
      assert.equal(outbox.length, 1);
      assert(!JSON.stringify(outbox).includes('synthetic-donor@example.test'));
      let notices = 0;
      const logs = [];
      assert(
        await processOneMailJob({
          store,
          config,
          transport: async (_, options) => {
            notices++;
            const payload = JSON.parse(options.body);
            assert.deepEqual(payload.to, ['synthetic-donor@example.test']);
            assert(!payload.text.includes(card.id));
            assert(!payload.text.includes(d.name));
            assert(payload.text.endsWith(config.publicOrigin + '/donate/manage'));
            return new Response(JSON.stringify({ id: randomUUID() }));
          },
          logger: (line) => logs.push(line),
        }),
      );
      assert.equal(notices, 1);
      assert(!logs.join('').includes('synthetic-donor'));
      // A queued notice must not follow a newly changed contributor identity/contact.
      const staleCase = { ...noticeCase, id: randomUUID() };
      await send(treasurer, 'cases', staleCase);
      assert.equal(
        (
          await send(treasurer, 'cases/' + staleCase.id, {
            version: 1,
            action: 'notify',
            evidenceDigest: evidence,
          })
        ).statusCode,
        200,
      );
      await send(owner, 'donors', {
        donor: {
          ...d,
          employer: 'Synthetic employer',
          occupation: 'Synthetic occupation',
          email: 'new-synthetic-donor@example.test',
        },
        expectedVersion: 3,
      });
      assert(
        await processOneMailJob({
          store,
          config,
          transport: async () => {
            notices++;
            throw Error('must not contact stale address');
          },
          logger: () => {},
        }),
      );
      assert.equal(notices, 1);
      // A crash/timeout after the durable command boundary remains uncertain and
      // cannot become an automatic retry under a fresh command UUID.
      const failedCase = {
        id: randomUUID(),
        giftId: card.id,
        kind: 'refund',
        evidenceDigest: evidence,
      };
      await send(treasurer, 'cases', failedCase);
      const uncertain = { ...command, id: randomUUID(), caseId: failedCase.id, amountCents: 100 };
      let attempts = 0;
      await assert.rejects(
        store.executeFinanceRefund(
          uncertain,
          treasurer.id,
          config.stripeTestKey,
          now,
          async (path) => {
            attempts++;
            if (!path.endsWith('/refunds'))
              return new Response(
                JSON.stringify({
                  id: sessionId,
                  livemode: false,
                  client_reference_id: clientRef,
                  amount_total: 2000,
                  currency: 'usd',
                  payment_status: 'paid',
                  payment_intent: paymentIntent,
                }),
              );
            throw Error('synthetic lost POST response');
          },
        ),
        (e) => e.code === 'finance_command_uncertain',
      );
      assert.equal(attempts, 2);
      await assert.rejects(
        store.executeFinanceRefund(uncertain, treasurer.id, config.stripeTestKey, now, async () => {
          attempts++;
        }),
        (e) => e.code === 'finance_command_uncertain',
      );
      assert.equal(attempts, 2);
      const failedRefundId = 're_synthetic' + randomBytes(8).toString('hex'),
        confirmedFailure = await webhook('refund.failed', {
          id: failedRefundId,
          payment_intent: paymentIntent,
          amount: 100,
          currency: 'usd',
          status: 'failed',
          metadata: { g28_treasury_command: uncertain.id },
        });
      assert.equal(confirmedFailure.result.status, 200);
      const failedReconciliation = await send(
        treasurer,
        'commands/' + uncertain.id + '/reconcile',
        { providerEventId: confirmedFailure.id },
      );
      assert.equal(failedReconciliation.statusCode, 200, failedReconciliation.body);
      assert.equal(
        (await pool.query('SELECT status FROM g28.treasury_commands WHERE id=$1', [uncertain.id]))
          .rows[0].status,
        'failed',
      );
      assert.equal(
        (
          await pool.query('SELECT 1 FROM g28.financial_provider_events WHERE event_id=$1', [
            failedRefundId,
          ])
        ).rowCount,
        0,
      );
      for (const lostResponse of [false, true]) {
        const race = { ...command, id: randomUUID(), caseId: failedCase.id, amountCents: 100 },
          raceRefundId = 're_synthetic' + randomBytes(8).toString('hex');
        const result = await store.executeFinanceRefund(
          race,
          treasurer.id,
          config.stripeTestKey,
          now,
          async (path, options) => {
            if (!path.endsWith('/refunds'))
              return new Response(
                JSON.stringify({
                  id: sessionId,
                  livemode: false,
                  client_reference_id: clientRef,
                  amount_total: 2000,
                  currency: 'usd',
                  payment_status: 'paid',
                  payment_intent: paymentIntent,
                }),
              );
            assert.equal(
              new URLSearchParams(options.body).get('metadata[g28_treasury_command]'),
              race.id,
            );
            const receipt = await webhook('refund.updated', {
                id: raceRefundId,
                payment_intent: paymentIntent,
                amount: 100,
                currency: 'usd',
                status: 'succeeded',
                metadata: { g28_treasury_command: race.id },
              }),
              entry = fixtureEntry(
                null,
                {
                  kind: 'refund',
                  source: 'stripe-test',
                  giftId: card.id,
                  externalReference: raceRefundId,
                  amountCents: 100,
                  receivedAt: new Date(now).toISOString(),
                  evidenceDigest: receipt.digest,
                },
                now,
              );
            await store.postFinanceEntry(entry, treasurer.id, config.treasuryKey, now);
            await store.reconcileFinanceCommand(
              race.id,
              { journalEntryId: entry.id },
              treasurer.id,
            );
            if (lostResponse) throw Error('synthetic response lost after signed reconciliation');
            return new Response(
              JSON.stringify({
                id: raceRefundId,
                amount: 100,
                currency: 'usd',
                payment_intent: paymentIntent,
                status: 'succeeded',
              }),
            );
          },
        );
        assert.equal(result.ledgerReconciled, true);
        assert.equal(
          (await pool.query('SELECT status FROM g28.treasury_commands WHERE id=$1', [race.id]))
            .rows[0].status,
          'reconciled',
        );
      }
      // Cursor precision must preserve PostgreSQL microseconds at a page boundary.
      const batch = Array.from({ length: 105 }, () => {
        const id = randomUUID();
        return {
          id,
          envelope: sealFinanceEvidence(
            id,
            {
              id,
              filename: 'synthetic-page.txt',
              mediaType: 'text/plain',
              content: Buffer.from(evidenceContent).toString('base64'),
            },
            config.treasuryKey,
          ),
        };
      });
      for (const item of batch)
        await pool.query(
          'INSERT INTO g28.treasury_evidence(id,digest,byte_count,encrypted_envelope,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6)',
          [
            item.id,
            evidence,
            Buffer.byteLength(evidenceContent),
            item.envelope,
            owner.id,
            new Date(now).toISOString().replace('.000Z', '.123456Z'),
          ],
        );
      const page1 = await send(owner, 'page', { collection: 'evidence', after: null });
      assert.equal(page1.statusCode, 200, page1.body);
      assert.equal(page1.json().items.length, 100);
      assert.match(page1.json().next.at, /\.\d{6}Z$/);
      const page2 = await send(owner, 'page', { collection: 'evidence', after: page1.json().next });
      assert.equal(page2.statusCode, 200, page2.body);
      assert.equal(page2.json().items.length, 6);
      assert.equal(
        new Set([...page1.json().items, ...page2.json().items].map((x) => x.id)).size,
        106,
      );
      assert.equal(page2.json().next, null);
      assert.equal(
        (await send(owner, 'page', { collection: 'accounts', after: null })).statusCode,
        400,
      );
      assert.equal(
        (await send(editor, 'page', { collection: 'evidence', after: null })).statusCode,
        403,
      );
      await store.withStaffSecurity(treasurer.id, (s) => {
        s.sessions = {};
      });
      assert.equal((await send(treasurer, 'overview')).statusCode, 403);
      await pool.query('UPDATE g28.admin_grants SET revoked_at=now() WHERE email_key=$1', [
        treasurer.key,
      ]);
      assert.equal(
        (await send(treasurer, 'donors/' + d.id + '/read', { version: 1 })).statusCode,
        403,
      );
    } finally {
      await app.close();
      await store.close();
      await admin.query('DROP DATABASE ' + name);
      await admin.end();
    }
  },
);
