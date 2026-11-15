import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes, createHmac } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { PostgresStore, databasePool } from '../../apps/api/src/postgres-store.mjs';
import { createApp } from '../../apps/api/src/app.mjs';
import { CardContributionStore } from '../../apps/api/src/card-contribution-store.mjs';
import {
  RecurringCardService,
  newRecoveryCode,
} from '../../apps/api/src/card-recurring-service.mjs';
import { tokenHash, randomToken } from '../../packages/core/auth.mjs';
import { StripeCampaignStore } from '../../apps/web/stripe-campaign-store.mjs';
import { MANUAL_CAPTURE_PROFILE } from '../../packages/core/stripe-manual-capture.mjs';
import {
  fixturePolicy,
  fixtureDonor,
  evidence,
  evidenceContent,
} from '../helpers/treasury-fixtures.mjs';

const base = process.env.TEST_DATABASE_URL;
const DAY = 86400000;
const attest = {
  eligibleResidency: true,
  ownFunds: true,
  age18: true,
  notFederalContractor: true,
  personalCreditCard: true,
};

test(
  'monthly donor self-service, card replacement, bank confirmation binding and due-installment processing fail closed',
  { skip: !base },
  async () => {
    assert(['localhost', '127.0.0.1'].includes(new URL(base).hostname));
    const name = 'g28_recurring_' + randomBytes(5).toString('hex'),
      admin = databasePool(base),
      url = new URL(base);
    url.pathname = '/' + name;
    await admin.query('CREATE DATABASE ' + name);
    const pool = databasePool(url.href),
      store = new PostgresStore(pool),
      start = Date.now();
    let now = start;
    const clock = () => now,
      key = Buffer.alloc(32, 23).toString('base64'),
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
      cards = new CardContributionStore({ store, config, clock }),
      recurring = new RecurringCardService({ cards, clock }),
      app = createApp({ store, config, clock });
    const staffRequest = (path, payload, changes = {}) =>
      app.inject({
        method: 'POST',
        url: '/api/staff/finance/card/' + path,
        headers: {
          origin: config.portalOrigin,
          cookie: 'g28-local=' + sessionToken,
          'x-csrf-token': csrf,
          'content-type': 'application/json',
          ...changes,
        },
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
        [sessionHash, owner, csrf, new Date(start + 400 * DAY)],
      );
      // The fresh-passkey stamp is refreshed whenever the test moves its clock.
      const refreshPasskey = () =>
        store.withStaffSecurity(owner, (s) => {
          s.credentials = [{ id: 'synthetic-finance-passkey' }];
          s.sessions = {
            [sessionHash]: { credentialId: 'synthetic-finance-passkey', expires: now + 900000 },
          };
        });
      await refreshPasskey();
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
      parent.validUntil = new Date(start + 300 * DAY).toISOString();
      parent.electionLimits = { primary: 100000, general: 100000 };
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
          primary: new Date(start + 200 * DAY).toISOString(),
          general: new Date(start + 200 * DAY).toISOString(),
        },
        maxInstallments: 12,
        maxSchedulesPerDonor: 12,
        reservationSeconds: 120,
        termsVersion: '2026-11-15-synthetic-only',
        allowedCardCountries: ['US'],
        evidenceDigest: evidence,
      };
      await cards.savePolicy(staff, rules);
      const shown = await recurring.publicRules();
      assert.equal(shown.termsVersion, rules.termsVersion);
      assert.equal(shown.maxInstallments, 12);
      assert.equal(shown.cutoffs.general, rules.electionEnds.general);
      assert.equal(JSON.stringify(shown).includes('allowedCardCountries'), false);

      const stripe = new StripeCampaignStore(pool),
        webhookKey = 'whsec_syntheticRecurringOnly123';
      async function signed(type, object) {
        const created = Math.floor(Date.now() / 1000),
          raw = Buffer.from(
            JSON.stringify({
              id: 'evt_synthetic' + randomBytes(8).toString('hex'),
              type,
              livemode: false,
              created,
              data: { object },
            }),
          ),
          header =
            't=' +
            created +
            ',v1=' +
            createHmac('sha256', webhookKey)
              .update(created + '.')
              .update(raw)
              .digest('hex');
        return stripe.receiveSignedWebhook({ raw, header, secret: webhookKey, sandbox: true });
      }
      const monthly = (extra = {}) => ({
        id: randomUUID(),
        clientReference: 'attempt_' + randomBytes(16).toString('hex'),
        amountCents: 2500,
        frequency: 'monthly',
        election: 'general',
        endAt: new Date(start + 150 * DAY).toISOString(),
        maxInstallments: 3,
        termsVersion: rules.termsVersion,
        consentDigest: 'c'.repeat(64),
        attestations: attest,
        ...extra,
      });
      async function completeSetup(request, suffix = randomBytes(8).toString('hex')) {
        const sessionId = 'cs_test_' + suffix;
        await cards.recordSetup(request.id, sessionId);
        const receipt = await signed('checkout.session.completed', {
          id: sessionId,
          object: 'checkout.session',
          mode: 'setup',
          client_reference_id: request.clientReference,
          metadata: {
            g28_profile: MANUAL_CAPTURE_PROFILE,
            g28_enrollment: request.id,
            g28_consent: request.consentDigest,
            terms_version: request.termsVersion,
          },
        });
        assert.equal(receipt.outcome, 'signed_setup_requires_review');
        await cards.verifyEnrollment(staff, request.id, {
          verified: async () => ({
            sessionId,
            setupIntentId: 'seti_' + suffix,
            customerId: 'cus_' + suffix,
            paymentMethodId: 'pm_' + suffix,
            card: { funding: 'credit', issuerCountry: 'US' },
            billing: {
              name: 'SYNTHETIC_RECURRING_IDENTITY',
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
        });
        return { sessionId, suffix };
      }

      // ---- Prospective setup, replay and recovery -----------------------------------
      const first = monthly(),
        code = newRecoveryCode();
      const begun = await recurring.beginSetup(first, { recoveryCode: code });
      assert.equal(begun.fresh, true);
      const replay = await recurring.beginSetup(first, { recoveryCode: newRecoveryCode() });
      assert.equal(replay.fresh, false, 'a replayed click keeps the original consent and code');
      assert.equal(
        (
          await pool.query('SELECT count(*)::int AS n FROM g28.card_enrollments')
        ).rows[0].n,
        1,
      );
      await assert.rejects(
        recurring.beginSetup({ ...first, amountCents: 9900 }, { recoveryCode: code }),
        (e) => e.code === 'card_enrollment_conflict',
      );
      await assert.rejects(
        recurring.beginSetup(monthly({ maxInstallments: 13 }), { recoveryCode: newRecoveryCode() }),
        (e) => e.code === 'card_consent_policy',
        'a donor cannot exceed the published installment limit',
      );
      const stored = (
        await pool.query('SELECT recovery_sha256 FROM g28.card_enrollments WHERE id=$1', [first.id])
      ).rows[0];
      assert.match(stored.recovery_sha256, /^[a-f0-9]{64}$/);
      assert.notEqual(stored.recovery_sha256, code, 'the recovery code is never stored');
      assert.deepEqual(await recurring.recover(code.toLowerCase()), {
        enrollmentId: first.id,
        clientReference: first.clientReference,
      });
      assert.equal(await recurring.recover(newRecoveryCode()), null);
      assert.equal(await recurring.recover('not-a-code'), null);

      const view0 = await recurring.donorView(first.id, first.clientReference);
      assert.equal(view0.enrollment.status, 'preparing');
      assert.equal(view0.schedule, null);
      const foreign = 'attempt_' + 'f'.repeat(32);
      for (const call of [
        () => recurring.donorView(first.id, foreign),
        () => recurring.donorCancel(first.id, foreign),
        () => recurring.confirmationTarget(first.id, foreign, randomUUID()),
      ])
        await assert.rejects(call(), (e) => e.code === 'donor_authority' && e.status === 403);

      // A setup the donor withdraws before review cannot become a schedule.
      const withdrawn = monthly();
      await recurring.beginSetup(withdrawn, { recoveryCode: newRecoveryCode() });
      assert.deepEqual(await recurring.donorCancel(withdrawn.id, withdrawn.clientReference), {
        setup: 'cancelled',
      });
      assert.equal(
        (await recurring.donorCancel(withdrawn.id, withdrawn.clientReference)).duplicate,
        true,
      );
      await assert.rejects(
        cards.recordSetup(withdrawn.id, 'cs_test_' + randomBytes(8).toString('hex')),
        (e) => e.code === 'card_setup_conflict',
      );

      // ---- Mandate and due-installment processing -----------------------------------
      const setup = await completeSetup(first);
      const approved = await cards.approveMandate(staff, {
        id: randomUUID(),
        enrollmentId: first.id,
        donorId: donor.id,
        donorVersion: 1,
        identityEvidenceDigest: evidence,
        confirm: 'approve exact documented card mandate',
      });
      const mandateId = approved.mandate.id;
      let due = await recurring.processDue();
      assert.equal(due.due, 1, 'the first installment is due immediately');
      assert.equal((await recurring.processDue()).missed, 0, 'processing is idempotent');
      const queue = await staffRequest('due', {});
      assert.equal(queue.statusCode, 200);
      assert.equal(queue.json().items.length, 1);
      assert.equal(
        (await staffRequest('due', {}, { 'x-csrf-token': 'wrong' })).statusCode,
        403,
        'the due queue needs staff CSRF',
      );
      assert.equal((await staffRequest('due', {}, { cookie: '' })).statusCode, 401);
      let view = await recurring.donorView(first.id, first.clientReference);
      assert.equal(view.schedule.status, 'active');
      assert.equal(view.schedule.amountCents, 2500);
      assert.equal(view.installments[0].state, 'due for treasury review');
      assert.equal(JSON.stringify(view).includes('SYNTHETIC_RECURRING_IDENTITY'), false);
      assert.equal(JSON.stringify(view).includes('pm_' + setup.suffix), false);

      // Staff reserves; an unsent reservation expires and frees its room, and that
      // month is not caught up.
      const period0 = randomUUID();
      await cards.reservePeriod(staff, {
        id: period0,
        mandateId,
        mandateVersion: 1,
        index: 0,
        confirm: 'reserve exact due installment',
      });
      due = await recurring.processDue();
      assert.equal(due.due, 0);
      now += 10 * 60000;
      due = await recurring.processDue();
      assert.equal(due.released, 1);
      const p0 = (
        await pool.query('SELECT status,reservation_active FROM g28.card_periods WHERE id=$1', [
          period0,
        ])
      ).rows[0];
      assert.deepEqual(p0, { status: 'blocked', reservation_active: false });
      // Month two passes untouched: it becomes missed and is never reopened.
      now = start + 31 * DAY + 3600000;
      await refreshPasskey();
      due = await recurring.processDue();
      assert.equal(due.due, 1);
      now = start + 62 * DAY + 3600000;
      await refreshPasskey();
      due = await recurring.processDue();
      assert.equal(due.missed, 1);
      assert.equal(
        (
          await pool.query(
            'SELECT status FROM g28.card_due_installments WHERE mandate_id=$1 AND installment=1',
            [mandateId],
          )
        ).rows[0].status,
        'missed',
      );

      // ---- Replacement card -----------------------------------------------------------
      const replacement = monthly({ endAt: first.endAt });
      await recurring.beginSetup(replacement, {
        recoveryCode: newRecoveryCode(),
        replacesMandateId: mandateId,
      });
      await assert.rejects(
        recurring.beginSetup(replacement, {
          recoveryCode: newRecoveryCode(),
          replacesMandateId: null,
        }),
        (e) => e.code === 'card_enrollment_conflict',
      );
      const replacementSetup = await completeSetup(replacement);
      await assert.rejects(
        cards.approveMandate(staff, {
          id: randomUUID(),
          enrollmentId: replacement.id,
          donorId: donor.id,
          donorVersion: 1,
          identityEvidenceDigest: evidence,
          confirm: 'approve exact documented card mandate',
        }),
        (e) => e.code === 'card_replacement_setup',
        'a replacement card cannot start a second schedule',
      );
      const widened = monthly({ amountCents: 9000, endAt: first.endAt });
      await recurring.beginSetup(widened, {
        recoveryCode: newRecoveryCode(),
        replacesMandateId: mandateId,
      });
      await completeSetup(widened);
      const mandateVersion = (
        await pool.query('SELECT version FROM g28.card_mandates WHERE id=$1', [mandateId])
      ).rows[0].version;
      const change = (enrollmentId, extra = {}) =>
        staffRequest('mandates/' + mandateId + '/replace-method', {
          mandateVersion,
          enrollmentId,
          identityEvidenceDigest: evidence,
          confirm: 'replace exact saved card for future installments',
          ...extra,
        });
      assert.equal((await change(widened.id)).json().error, 'card_method_terms');
      assert.equal((await change(replacement.id, { confirm: 'yes' })).statusCode, 400);
      assert.equal(
        (await change(replacement.id, { identityEvidenceDigest: 'e'.repeat(64) })).statusCode,
        409,
      );
      const changed = await change(replacement.id);
      assert.equal(changed.statusCode, 200, changed.body);
      assert.equal(changed.json().version, mandateVersion + 1);
      const doc = (
        await pool.query('SELECT document FROM g28.card_mandates WHERE id=$1', [mandateId])
      ).rows[0].document;
      assert.equal(doc.paymentMethodId, 'pm_' + replacementSetup.suffix);
      assert.equal(doc.amountCents, 2500);
      assert.equal((await change(replacement.id)).statusCode, 409, 'a stale version is refused');
      // The replacement holder sees the same schedule.
      view = await recurring.donorView(replacement.id, replacement.clientReference);
      assert.equal(view.schedule.status, 'active');

      // ---- Bank confirmation of a staff-prepared first installment ----------------------
      // Run on a second schedule whose first installment is still due.
      now = start + 63 * DAY;
      await refreshPasskey();
      const second = monthly({ endAt: new Date(start + 150 * DAY).toISOString() });
      await recurring.beginSetup(second, { recoveryCode: newRecoveryCode() });
      await completeSetup(second);
      const m2 = await cards.approveMandate(staff, {
        id: randomUUID(),
        enrollmentId: second.id,
        donorId: donor.id,
        donorVersion: 1,
        identityEvidenceDigest: evidence,
        confirm: 'approve exact documented card mandate',
      });
      const period = randomUUID();
      const reserved = await cards.reservePeriod(staff, {
        id: period,
        mandateId: m2.mandate.id,
        mandateVersion: 1,
        index: 0,
        confirm: 'reserve exact due installment',
      });
      const command = randomUUID();
      await cards.prepareCommand(staff, {
        id: command,
        periodId: period,
        periodVersion: reserved.period.version,
        action: 'authorize',
        confirm: 'prepare exact authorize',
      });
      const pi = 'pi_' + randomBytes(10).toString('hex');
      const seen = (status, extra = {}) => ({
        id: pi,
        status,
        amountCents: 2500,
        amountCapturable: status === 'requires_capture' ? 2500 : 0,
        amountReceived: 0,
        customerId: m2.mandate.customerId,
        paymentMethodId: m2.mandate.paymentMethodId,
        environment: 'test',
        ...extra,
      });
      await cards.performCommand(staff, command, {
        instrument: async () => ({}),
        authorize: async () => seen('requires_confirmation'),
      });
      const target = await recurring.confirmationTarget(second.id, second.clientReference, period);
      assert.equal(target.paymentIntentId, pi);
      assert.equal(target.approval.confirmationMode, 'on_session');
      view = await recurring.donorView(second.id, second.clientReference);
      assert.deepEqual(view.confirmation, { periodId: period });
      await assert.rejects(
        recurring.confirmationTarget(first.id, first.clientReference, period),
        (e) => e.code === 'card_confirmation_unavailable',
        'another donor’s schedule cannot confirm this installment',
      );
      await assert.rejects(
        recurring.recordConfirmationObservation(period, seen('succeeded', { amountReceived: 2500 })),
        (e) => e.code === 'card_processor_uncertain',
        'a donor return can never record collected funds',
      );
      const observed = await recurring.recordConfirmationObservation(
        period,
        seen('requires_capture'),
      );
      assert.equal(observed.status, 'authorized');
      await assert.rejects(
        recurring.confirmationTarget(second.id, second.clientReference, period),
        (e) => e.code === 'card_confirmation_unavailable',
        'an authorized installment cannot be confirmed again',
      );

      // ---- Donor cancellation ----------------------------------------------------------
      const cancelled = await recurring.donorCancel(second.id, second.clientReference);
      assert.deepEqual(cancelled, { schedule: 'cancelled' });
      assert.equal((await recurring.donorCancel(second.id, second.clientReference)).duplicate, true);
      const p2 = (
        await pool.query('SELECT status,reservation_active FROM g28.card_periods WHERE id=$1', [
          period,
        ])
      ).rows[0];
      assert.deepEqual(
        p2,
        { status: 'authorized', reservation_active: true },
        'an attempt already at the processor is kept for exact treasury release, not dropped',
      );
      await assert.rejects(
        cards.prepareCommand(staff, {
          id: randomUUID(),
          periodId: period,
          periodVersion: (
            await pool.query('SELECT version FROM g28.card_periods WHERE id=$1', [period])
          ).rows[0].version,
          action: 'capture',
          confirm: 'prepare exact capture',
        }),
        (e) => e.code === 'card_mandate_changed',
        'nothing can be captured after the donor cancels',
      );
      // Cancelling the first schedule also withdraws nothing it should not.
      assert.deepEqual(await recurring.donorCancel(first.id, first.clientReference), {
        schedule: 'cancelled',
      });
      assert.equal(
        (
          await pool.query(
            "SELECT count(*)::int AS n FROM g28.card_due_installments WHERE mandate_id=$1 AND status='due'",
            [mandateId],
          )
        ).rows[0].n,
        0,
      );
      due = await recurring.processDue();
      assert.equal(due.due, 0, 'cancelled schedules produce no due installments');

      // ---- Completion -------------------------------------------------------------------
      const third = monthly({ maxInstallments: 1, frequency: 'monthly' });
      await recurring.beginSetup(third, { recoveryCode: newRecoveryCode() });
      await completeSetup(third);
      const m3 = await cards.approveMandate(staff, {
        id: randomUUID(),
        enrollmentId: third.id,
        donorId: donor.id,
        donorVersion: 1,
        identityEvidenceDigest: evidence,
        confirm: 'approve exact documented card mandate',
      });
      now += 40 * DAY;
      due = await recurring.processDue();
      assert.equal(due.completed >= 1, true);
      assert.equal(
        (await pool.query('SELECT status FROM g28.card_mandates WHERE id=$1', [m3.mandate.id]))
          .rows[0].status,
        'complete',
      );
      // ---- Signed refund of a captured monthly installment --------------------------------
      const capturedPi = 'pi_' + randomBytes(10).toString('hex');
      await pool.query(
        "UPDATE g28.card_periods SET status='captured_unposted',provider_payment_id=$2,reservation_active=true WHERE id=$1",
        [period0, capturedPi],
      );
      await pool.query(
        "INSERT INTO g28.financial_provider_events(provider,event_id,payment_id,event_digest,event_kind,amount_cents,occurred_at) VALUES('stripe-test',$1,$2,$3,'captured',2500,now())",
        ['evt_capture' + randomBytes(6).toString('hex'), capturedPi, 'a'.repeat(64)],
      );
      const refund = (amount, pi = capturedPi) =>
        signed('refund.updated', {
          id: 're_' + randomBytes(8).toString('hex'),
          object: 'refund',
          amount,
          currency: 'usd',
          status: 'succeeded',
          payment_intent: pi,
        });
      assert.equal(
        (await refund(1000)).outcome,
        'verified_refund_requires_treasury_reconciliation',
      );
      const effects = (
        await pool.query(
          "SELECT event_kind,amount_cents FROM g28.financial_provider_events WHERE payment_id=$1 ORDER BY event_kind",
          [capturedPi],
        )
      ).rows.map((r) => r.event_kind + ':' + r.amount_cents);
      assert.deepEqual(effects, ['captured:2500', 'partially_refunded:1000']);
      assert.equal(
        (await refund(500, 'pi_' + randomBytes(10).toString('hex'))).status,
        422,
        'a refund for an unknown installment is not recorded',
      );
      await assert.rejects(refund(5000), /exceeds captured balance/);

      const audit = (
        await pool.query('SELECT action FROM g28.card_workflow_audit ORDER BY created_at')
      ).rows.map((r) => r.action);
      for (const action of [
        'card_recovery_bound',
        'card_donor_recovered',
        'card_setup_cancelled_by_donor',
        'card_reservation_expired',
        'card_installment_missed',
        'card_method_replaced',
        'card_mandate_cancelled_by_donor',
        'card_mandate_completed',
      ])
        assert.ok(audit.includes(action), action);
    } finally {
      await pool.end();
      await admin.query('DROP DATABASE IF EXISTS ' + name + ' WITH (FORCE)');
      await admin.end();
    }
  },
);
