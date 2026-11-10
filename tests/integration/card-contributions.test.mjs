import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes, createHmac, createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { PostgresStore, databasePool } from '../../apps/api/src/postgres-store.mjs';
import { createApp } from '../../apps/api/src/app.mjs';
import { CardContributionStore } from '../../apps/api/src/card-contribution-store.mjs';
import { tokenHash, randomToken } from '../../packages/core/auth.mjs';
import { StripeCampaignStore } from '../../apps/web/stripe-campaign-store.mjs';
import { MANUAL_CAPTURE_PROFILE } from '../../packages/core/stripe-manual-capture.mjs';
import {
  fixturePolicy,
  fixtureDonor,
  fixtureEntry,
  evidence,
  evidenceContent,
} from '../helpers/treasury-fixtures.mjs';
const base = process.env.TEST_DATABASE_URL;
test(
  'real SQL card consent is private, current staff/source evidence is required and concurrent mandates cannot spend the same all-channel room',
  { skip: !base },
  async () => {
    assert(['localhost', '127.0.0.1'].includes(new URL(base).hostname));
    const name = 'g28_cards_' + randomBytes(5).toString('hex'),
      admin = databasePool(base),
      url = new URL(base);
    url.pathname = '/' + name;
    await admin.query('CREATE DATABASE ' + name);
    const pool = databasePool(url.href),
      store = new PostgresStore(pool),
      now = Date.now(),
      key = Buffer.alloc(32, 19).toString('base64'),
      owner = randomUUID(),
      ownerKey = tokenHash(randomUUID()),
      sessionToken = randomToken(),
      sessionHash = tokenHash(sessionToken),
      csrf = randomToken(),
      config = {
        staffIdentity: true,
        adminLoginReady: true,
        adminOwnerEmailKey: ownerKey,
        treasuryKey: key,
        portalOrigin: 'http://localhost:4322',
        publicOrigin: 'http://localhost:4321',
      },
      cards = new CardContributionStore({ store, config, clock: () => now }),
      app = createApp({ store, config, clock: () => now });
    const headers = {
      origin: config.portalOrigin,
      cookie: 'g28-local=' + sessionToken,
      'x-csrf-token': csrf,
      'content-type': 'application/json',
    };
    const request = (path, payload, changes = {}) =>
      app.inject({
        method: 'POST',
        url: '/api/staff/finance/card/' + path,
        headers: { ...headers, ...changes },
        payload,
      });
    try {
      for (const f of (await readdir('db/migrations')).filter((f) => f.endsWith('.sql')).sort())
        await pool.query(await readFile('db/migrations/' + f, 'utf8'));
      await pool.query(
        "INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'passkey-only',now(),'synthetic')",
        [owner, ownerKey],
      );
      await pool.query(
        'INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',
        [sessionHash, owner, csrf, new Date(now + 86400000)],
      );
      await store.withStaffSecurity(owner, (s) => {
        s.credentials = [{ id: 'synthetic-finance-passkey' }];
        s.sessions = {
          [sessionHash]: { credentialId: 'synthetic-finance-passkey', expires: now + 900000 },
        };
      });
      const staff = await store.session(sessionHash, now);
      await store.saveFinanceEvidence(
        {
          id: randomUUID(),
          filename: 'synthetic.txt',
          mediaType: 'text/plain',
          content: Buffer.from(evidenceContent).toString('base64'),
        },
        owner,
        key,
      );
      const parent = fixturePolicy(now);
      parent.electionLimits = { primary: 10000, general: 10000 };
      await store.saveFinancePolicy(parent, owner, now);
      const donor = {
        ...fixtureDonor(),
        occupation: 'Synthetic occupation',
        employer: 'Synthetic employer',
      };
      await store.saveFinanceDonor(donor, 0, owner, key);
      const rules = {
        id: randomUUID(),
        version: 1,
        profile: MANUAL_CAPTURE_PROFILE,
        parentPolicyId: parent.id,
        parentPolicyVersion: 1,
        validUntil: parent.validUntil,
        electionEnds: {
          primary: new Date(now + 29 * 86400000).toISOString(),
          general: new Date(now + 29 * 86400000).toISOString(),
        },
        maxInstallments: 12,
        maxSchedulesPerDonor: 12,
        reservationSeconds: 120,
        termsVersion: '2026-11-10-synthetic-only',
        allowedCardCountries: ['US'],
        evidenceDigest: evidence,
      };
      await cards.savePolicy(staff, rules);
      const page = await request('page', { collection: 'policies', after: null });
      assert.equal(page.statusCode, 200);
      assert.equal(page.headers['cache-control'], 'no-store');
      assert.equal(page.json().items.length, 1);
      assert.equal(
        (
          await request(
            'page',
            { collection: 'policies', after: null },
            { origin: 'https://foreign.example.test' },
          )
        ).statusCode,
        403,
      );
      assert.equal(
        (
          await request(
            'page',
            { collection: 'policies', after: null },
            { 'x-csrf-token': 'wrong' },
          )
        ).statusCode,
        403,
      );
      assert.equal(
        (await request('page', { collection: 'policies', after: null }, { cookie: '' })).statusCode,
        401,
      );
      assert.equal(
        (await request('page', { collection: 'policies', after: null, ignored: 'untrusted' }))
          .statusCode,
        400,
      );
      assert.equal(
        (
          await request('commands/' + randomUUID() + '/perform-test', {
            confirm: 'dispatch exact TEST command once',
          })
        ).statusCode,
        503,
        'actual disabled test actions cannot call Stripe',
      );
      const ordinary = randomUUID(),
        ordinaryToken = randomToken(),
        ordinaryHash = tokenHash(ordinaryToken);
      await pool.query(
        "INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'synthetic',now(),'synthetic')",
        [ordinary, tokenHash(ordinary)],
      );
      await pool.query(
        'INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',
        [ordinaryHash, ordinary, csrf, new Date(now + 86400000)],
      );
      assert.equal(
        (
          await request(
            'page',
            { collection: 'policies', after: null },
            { cookie: 'g28-local=' + ordinaryToken },
          )
        ).statusCode,
        403,
        'ordinary volunteers cannot read prospective contributor finances',
      );

      await assert.rejects(
        cards.savePolicy(null, { ...rules, id: randomUUID(), version: 2 }),
        (e) => e.code === 'authentication_required',
      );
      await store.postFinanceEntry(
        fixtureEntry(donor.id, { amountCents: 6000 }, now),
        owner,
        key,
        now,
      );
      const stripe = new StripeCampaignStore(pool),
        webhookKey = 'whsec_syntheticCardsOnly12345';
      async function signed(
        type,
        object,
        eventId = 'evt_synthetic' + randomBytes(8).toString('hex'),
      ) {
        const created = Math.floor(now / 1000),
          raw = Buffer.from(
            JSON.stringify({ id: eventId, type, livemode: false, created, data: { object } }),
          ),
          header =
            't=' +
            created +
            ',v1=' +
            createHmac('sha256', webhookKey)
              .update(created + '.')
              .update(raw)
              .digest('hex');
        return {
          raw,
          header,
          digest: createHash('sha256').update(raw).digest('hex'),
          eventId,
          result: await stripe.receiveSignedWebhook({
            raw,
            header,
            secret: webhookKey,
            sandbox: true,
          }),
        };
      }
      const mandates = [];
      for (let i = 0; i < 6; i++) {
        const id = randomUUID(),
          suffix = randomBytes(8).toString('hex'),
          request = {
            id,
            clientReference: 'attempt_' + randomBytes(16).toString('hex'),
            amountCents: 2500,
            frequency: 'once',
            election: 'general',
            endAt: new Date(now + 10 * 86400000).toISOString(),
            maxInstallments: 1,
            termsVersion: rules.termsVersion,
            consentDigest: 'c'.repeat(64),
            attestations: {
              eligibleResidency: true,
              ownFunds: true,
              age18: true,
              notFederalContractor: true,
              personalCreditCard: true,
            },
          },
          sessionId = 'cs_test_' + suffix;
        await cards.beginEnrollment(request, 'test');
        await assert.rejects(
          cards.beginEnrollment({ ...request, amountCents: 2600 }, 'test'),
          (e) => e.code === 'card_enrollment_conflict',
        );
        await cards.recordSetup(id, sessionId);
        const driver = {
          verified: async () => ({
            sessionId,
            setupIntentId: 'seti_' + suffix,
            customerId: 'cus_' + suffix,
            paymentMethodId: 'pm_' + suffix,
            card: { funding: 'credit', issuerCountry: 'US' },
            billing: {
              name: 'SYNTHETIC_PRIVATE_CARD_IDENTITY_8251',
              email: 'synthetic@example.test',
              street: '1 Synthetic Street',
              city: 'Test',
              region: 'ZZ',
              postal: '00000',
              country: 'US',
              occupation: 'Synthetic occupation',
              employer: 'Synthetic employer',
            },
          }),
        };
        await assert.rejects(
          cards.verifyEnrollment(staff, id, driver),
          (e) => e.code === 'card_signed_setup_required',
        );
        const setupObject = {
          id: sessionId,
          object: 'checkout.session',
          mode: 'setup',
          client_reference_id: request.clientReference,
          metadata: {
            g28_profile: MANUAL_CAPTURE_PROFILE,
            g28_enrollment: id,
            g28_consent: request.consentDigest,
            terms_version: request.termsVersion,
          },
          customer_details: { name: 'PRIVATE_CALLBACK_NOT_STORED' },
        };
        const setupReceipt = await signed('checkout.session.completed', setupObject);
        assert.equal(setupReceipt.result.outcome, 'signed_setup_requires_review');
        assert.equal(
          (
            await stripe.receiveSignedWebhook({
              raw: setupReceipt.raw,
              header: setupReceipt.header,
              secret: webhookKey,
              sandbox: true,
            })
          ).outcome,
          'duplicate',
        );
        assert.equal(
          (
            await signed('checkout.session.completed', {
              ...setupObject,
              metadata: { ...setupObject.metadata, g28_consent: 'd'.repeat(64) },
            })
          ).result.status,
          422,
        );
        await cards.verifyEnrollment(staff, id, driver);
        const approval = {
            id: randomUUID(),
            enrollmentId: id,
            donorId: donor.id,
            donorVersion: 1,
            identityEvidenceDigest: evidence,
            confirm: 'approve exact documented card mandate',
          },
          m = await cards.approveMandate(staff, approval);
        assert.equal((await cards.approveMandate(staff, approval)).duplicate, true);
        mandates.push(m);
      }
      const results = await Promise.allSettled(
        mandates.map((m) =>
          cards.reservePeriod(staff, {
            id: randomUUID(),
            mandateId: m.mandate.id,
            mandateVersion: m.version,
            index: 0,
            confirm: 'reserve exact due installment',
          }),
        ),
      );
      assert.equal(
        results.filter((x) => x.status === 'fulfilled').length,
        1,
        'global finance lock must serialize exact all-source room, including pending authorizations',
      );
      assert(
        results
          .filter((x) => x.status === 'rejected')
          .every((x) => x.reason.code === 'card_contribution_limit'),
      );
      const held = (await pool.query('SELECT * FROM g28.card_periods')).rows;
      assert.equal(held.length, 1);
      assert.equal(Number(held[0].amount_cents), 2500);
      assert.equal(held[0].reservation_active, true);
      assert.equal(held[0].status, 'reserved');
      // The command is durable before provider I/O and can be dispatched once.
      const heldPeriod = held[0],
        authorization = {
          id: randomUUID(),
          periodId: heldPeriod.id,
          periodVersion: heldPeriod.version,
          action: 'authorize',
          confirm: 'prepare exact authorize',
        };
      await cards.prepareCommand(staff, authorization);
      assert.equal((await cards.prepareCommand(staff, authorization)).duplicate, true);
      let authorizeCalls = 0,
        captureCalls = 0,
        remoteState = 'requires_confirmation',
        lastApproval,
        providerReference = 'pi_syntheticCards12345',
        loseCaptureResponse = false;
      const driver = {
        instrument: async () => ({ funding: 'credit' }),
        authorize: async (p) => {
          authorizeCalls++;
          lastApproval = p;
          return observed(p);
        },
        inspect: async (p) => observed(p),
        capture: async (p) => {
          captureCalls++;
          remoteState = 'succeeded';
          if (loseCaptureResponse) throw Error('synthetic capture response lost');
          return observed(p);
        },
        cancel: async (p) => {
          remoteState = 'canceled';
          return observed(p);
        },
      };
      function observed(p) {
        return {
          id: providerReference,
          status: remoteState,
          amountCents: p.amountCents,
          amountCapturable: remoteState === 'requires_capture' ? p.amountCents : 0,
          amountReceived: remoteState === 'succeeded' ? p.amountCents : 0,
          customerId: p.customerId,
          paymentMethodId: p.paymentMethodId,
          environment: p.environment,
        };
      }
      assert.equal(
        (await cards.performCommand(staff, authorization.id, driver)).status,
        'requires_action',
      );
      assert.equal(lastApproval.confirmationMode, 'on_session');
      assert.equal(authorizeCalls, 1);
      await assert.rejects(
        cards.performCommand(staff, authorization.id, driver),
        (e) => e.code === 'card_command_unresolved',
      );
      assert.equal(authorizeCalls, 1);
      remoteState = 'requires_capture';
      await cards.reconcileCommand(staff, authorization.id, 'pi_syntheticCards12345', driver);
      // A later cash receipt consumes room before capture, even with an earlier
      // valid card reservation. The failed dispatch cannot charge or retry.
      await store.postFinanceEntry(
        fixtureEntry(donor.id, { amountCents: 2000 }, now),
        owner,
        key,
        now,
      );
      let period = (await pool.query('SELECT * FROM g28.card_periods WHERE id=$1', [heldPeriod.id]))
        .rows[0];
      const blockedCapture = {
        id: randomUUID(),
        periodId: period.id,
        periodVersion: period.version,
        action: 'capture',
        confirm: 'prepare exact capture',
      };
      await assert.rejects(
        cards.prepareCommand(staff, blockedCapture),
        (e) => e.code === 'card_contribution_limit',
      );
      assert.equal(captureCalls, 0);
      // Reconcile a cancellation against the same provider intent; cancellation
      // invalidates an already prepared capture and does not start another PI.
      const activeMandate = mandates.find((m) => m.mandate.id === heldPeriod.mandate_id);
      await cards.cancelMandate(staff, activeMandate.mandate.id, 1);
      await assert.rejects(
        cards.prepareCommand(staff, { ...blockedCapture, id: randomUUID() }),
        (e) => e.code === 'card_mandate_changed',
      );
      const voidCommand = {
        id: randomUUID(),
        periodId: period.id,
        periodVersion: period.version,
        action: 'cancel',
        confirm: 'prepare exact cancel',
      };
      await cards.prepareCommand(staff, voidCommand);
      assert.equal((await cards.performCommand(staff, voidCommand.id, driver)).status, 'voided');
      assert.equal(
        (
          await pool.query('SELECT reservation_active FROM g28.card_periods WHERE id=$1', [
            period.id,
          ])
        ).rows[0].reservation_active,
        false,
      );
      assert.equal(captureCalls, 0);
      // Lost authorization responses burn that period's sole attempt. Supplying
      // the exact bound intent for observation recovers it without another POST.
      const parent2 = {
        ...parent,
        id: randomUUID(),
        version: 2,
        electionLimits: { primary: 11000, general: 11000 },
      };
      await store.saveFinancePolicy(parent2, owner, now);
      await cards.savePolicy(staff, {
        ...rules,
        id: randomUUID(),
        version: 2,
        parentPolicyId: parent2.id,
        parentPolicyVersion: 2,
      });
      const other = mandates.find((m) => m.mandate.id !== heldPeriod.mandate_id);
      const next = (
        await cards.reservePeriod(staff, {
          id: randomUUID(),
          mandateId: other.mandate.id,
          mandateVersion: 1,
          index: 0,
          confirm: 'reserve exact due installment',
        })
      ).period;
      const uncertainCommand = {
        id: randomUUID(),
        periodId: next.id,
        periodVersion: next.version,
        action: 'authorize',
        confirm: 'prepare exact authorize',
      };
      await cards.prepareCommand(staff, uncertainCommand);
      let unknownCalls = 0;
      const unknown = {
        ...driver,
        authorize: async () => {
          unknownCalls++;
          throw Error('synthetic response lost');
        },
      };
      await assert.rejects(cards.performCommand(staff, uncertainCommand.id, unknown));
      await assert.rejects(
        cards.performCommand(staff, uncertainCommand.id, unknown),
        (e) => e.code === 'card_command_unresolved',
      );
      assert.equal(unknownCalls, 1);
      const saved = (await pool.query('SELECT * FROM g28.card_periods WHERE id=$1', [next.id]))
        .rows[0];
      assert.equal(saved.status, 'uncertain');
      assert.equal(saved.reservation_active, true);
      assert.equal(
        (
          await pool.query('SELECT status FROM g28.card_commands WHERE id=$1', [
            uncertainCommand.id,
          ])
        ).rows[0].status,
        'uncertain',
      );
      providerReference = 'pi_syntheticCardsSecond12345';
      remoteState = 'requires_capture';
      await cards.reconcileCommand(staff, uncertainCommand.id, providerReference, driver);
      assert.equal(unknownCalls, 1);
      period = (await pool.query('SELECT * FROM g28.card_periods WHERE id=$1', [next.id])).rows[0];
      const capture = {
        id: randomUUID(),
        periodId: period.id,
        periodVersion: period.version,
        action: 'capture',
        confirm: 'prepare exact capture',
      };
      await cards.prepareCommand(staff, capture);
      loseCaptureResponse = true;
      await assert.rejects(cards.performCommand(staff, capture.id, driver));
      assert.equal(captureCalls, 1);
      await assert.rejects(
        cards.performCommand(staff, capture.id, driver),
        (e) => e.code === 'card_command_unresolved',
      );
      assert.equal(captureCalls, 1);
      assert.equal(
        (await cards.reconcileCommand(staff, capture.id, providerReference, driver)).status,
        'captured_unposted',
      );
      assert.equal(
        (
          await pool.query('SELECT reservation_active FROM g28.card_periods WHERE id=$1', [
            period.id,
          ])
        ).rows[0].reservation_active,
        true,
        'an HTTP success is not a signed journal entry',
      );
      const approval2 = (
        await pool.query('SELECT document FROM g28.card_periods WHERE id=$1', [period.id])
      ).rows[0].document.providerApproval;
      const paidObject = {
        id: providerReference,
        object: 'payment_intent',
        capture_method: 'manual',
        currency: 'usd',
        amount: approval2.amountCents,
        amount_received: approval2.amountCents,
        amount_capturable: 0,
        customer: approval2.customerId,
        payment_method: approval2.paymentMethodId,
        status: 'succeeded',
        metadata: {
          g28_profile: MANUAL_CAPTURE_PROFILE,
          g28_attempt: approval2.attemptId,
          g28_period: approval2.periodId,
          g28_policy: approval2.policyDigest,
          g28_mandate: approval2.mandateDigest,
          g28_confirmation: approval2.confirmationMode,
        },
        client_secret: 'PRIVATE_CALLBACK_SECRET_NOT_STORED',
      };
      assert.equal(
        (await signed('payment_intent.succeeded', { ...paidObject, amount: 2600 })).result.status,
        422,
      );
      const signedCapture = await signed('payment_intent.succeeded', paidObject);
      assert.equal(signedCapture.result.outcome, 'signed_card_state_recorded');
      assert.equal(
        (await signed('payment_intent.succeeded', paidObject)).result.status,
        200,
        'a second signed event is acknowledged without a second journalable capture',
      );
      assert.equal(
        (
          await pool.query(
            'SELECT count(*)::int AS n FROM g28.financial_provider_events WHERE payment_id=$1',
            [providerReference],
          )
        ).rows[0].n,
        1,
      );
      await store.saveFinanceEvidence(
        {
          id: randomUUID(),
          filename: 'synthetic-signed-capture.txt',
          mediaType: 'text/plain',
          content: signedCapture.raw.toString('base64'),
        },
        owner,
        key,
      );
      const gift = fixtureEntry(
        donor.id,
        {
          source: 'stripe-test',
          externalReference: signedCapture.eventId,
          amountCents: 2500,
          evidenceDigest: signedCapture.digest,
          receivedAt: new Date(Math.floor(now / 1000) * 1000).toISOString(),
        },
        now,
      );
      await store.postFinanceEntry(gift, owner, key, now);
      const posted = (await pool.query('SELECT * FROM g28.card_periods WHERE id=$1', [period.id]))
        .rows[0];
      assert.equal(posted.status, 'posted');
      assert.equal(posted.reservation_active, false);
      assert.equal(posted.gift_id, gift.giftId);
      assert.equal((await store.postFinanceEntry(gift, owner, key, now)).duplicate, true);
      assert.equal(captureCalls, 1);
      assert.equal(unknownCalls, 1);
      const sql = JSON.stringify(
        (await pool.query('SELECT request_document,encrypted_details FROM g28.card_enrollments'))
          .rows,
      );
      assert(!sql.includes('SYNTHETIC_PRIVATE_CARD_IDENTITY_8251'));
      assert(!sql.includes('synthetic@example.test'));
      assert(
        !JSON.stringify(
          (await pool.query('SELECT * FROM g28.stripe_webhook_receipts')).rows,
        ).includes('PRIVATE_CALLBACK'),
      );
      assert(
        !JSON.stringify((await pool.query('SELECT document FROM g28.card_periods')).rows).includes(
          'PRIVATE_CALLBACK',
        ),
      );
      assert(
        (await pool.query('SELECT count(*)::int AS n FROM g28.card_workflow_audit')).rows[0].n > 10,
      );
      await pool.query('DELETE FROM g28.sessions WHERE token_hash=$1', [sessionHash]);
      await assert.rejects(
        cards.reservePeriod(staff, {
          id: randomUUID(),
          mandateId: mandates[1].mandate.id,
          mandateVersion: 1,
          index: 0,
          confirm: 'reserve exact due installment',
        }),
        (e) => e.code === 'authentication_required',
        'an old MFA stamp cannot revive a revoked ordinary session',
      );
    } finally {
      await app.close();
      await pool.end();
      await admin.query('DROP DATABASE ' + name);
      await admin.end();
    }
  },
);
