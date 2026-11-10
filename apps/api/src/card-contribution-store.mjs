import { randomUUID, createHash } from 'node:crypto';
import { assert, exactKeys } from '../../../packages/core/validation.mjs';
import { canonical } from '../../../packages/core/protected-crypto.mjs';
import { treasuryPolicy, financeId } from '../../../packages/core/treasury-workflow.mjs';
import {
  cardContributionPolicy,
  cardMandate,
  decideCardInstallment,
} from '../../../packages/core/card-mandates.mjs';
import { cardEnrollmentRequest } from '../../../packages/core/stripe-card-setup.mjs';
import { openFinanceIdentity } from '../../../packages/core/treasury-private.mjs';
import { sealTreasury, openTreasury } from '../../../packages/core/treasury-vault.mjs';
const sha = (x) =>
  createHash('sha256')
    .update(typeof x === 'string' ? x : canonical(x))
    .digest('hex');
const audit = (c, actor, id, action, value) =>
  c.query(
    'INSERT INTO g28.card_workflow_audit(id,actor_id,object_id,action,digest) VALUES($1,$2,$3,$4,$5)',
    [randomUUID(), actor, id, action, sha(value)],
  );
const proof = async (c, digest) =>
  assert(
    /^[a-f0-9]{64}$/.test(digest) &&
      (await c.query('SELECT 1 FROM g28.treasury_evidence WHERE digest=$1 LIMIT 1', [digest]))
        .rowCount,
    'card_documentary_evidence',
    'Record the actual private documentary evidence before approval.',
    409,
  );
const seal = (id, value, key) =>
  sealTreasury('bank', { context: 'g28:card-enrollment:v1', id, value }, key);
const open = (id, envelope, key) => {
  const x = openTreasury('bank', envelope, key);
  assert(
    x.context === 'g28:card-enrollment:v1' && x.id === id,
    'card_billing_binding',
    'The encrypted financial source belongs to another record.',
    409,
  );
  return x.value;
};
export class CardContributionStore {
  constructor({ store, config, clock = Date.now }) {
    this.store = store;
    this.pool = store.pool;
    this.config = config;
    this.clock = clock;
  }
  async transaction(fn, staff = null) {
    const c = await this.pool.connect();
    try {
      await c.query('BEGIN');
      await c.query("SELECT pg_advisory_xact_lock(hashtext('g28-finance-journal'))");
      let actor = 'processor';
      if (staff) {
        assert(
          this.config.staffIdentity && this.config.adminLoginReady,
          'card_staff_unavailable',
          'Verified treasury staff access is not configured.',
          503,
        );
        await c.query('LOCK TABLE g28.admin_grants IN SHARE MODE');
        const scoped = Object.create(this.store);
        scoped.pool = c;
        const session = await scoped.session(staff.hash, this.clock());
        assert(
          session?.account.id === staff.account?.id,
          'authentication_required',
          'Sign in again before approving a financial action.',
          401,
        );
        const role = await scoped.adminRole(session.account, this.config.adminOwnerEmailKey);
        assert(
          ['owner', 'treasurer'].includes(role) &&
            (await scoped.staffMfaValid(session.account.id, session.hash, this.clock())),
          'card_staff_forbidden',
          'Current treasury authority and a fresh verified staff passkey are required.',
          403,
        );
        actor = session.account.id;
      }
      const result = await fn(c, actor);
      await c.query('COMMIT');
      return result;
    } catch (error) {
      await c.query('ROLLBACK');
      throw error;
    } finally {
      c.release();
    }
  }
  async page(staff, input) {
    assert(staff, 'authentication_required', 'Verified treasury staff access is required.', 401);
    const b = exactKeys(input, ['collection', 'after']);
    assert(
      ['enrollments', 'mandates', 'periods', 'commands', 'policies'].includes(b.collection),
      'card_collection',
      'Choose a card-control collection.',
    );
    if (b.after !== null) financeId(b.after);
    const names = {
        enrollments: 'card_enrollments',
        mandates: 'card_mandates',
        periods: 'card_periods',
        commands: 'card_commands',
        policies: 'card_contribution_policies',
      },
      columns = {
        enrollments:
          'id,client_reference,request_document,environment,status,setup_session_id,updated_at',
        mandates: 'id,document,status,version,updated_at',
        periods:
          'id,mandate_id,installment,document,environment,status,amount_cents,reservation_active,provider_payment_id,version,updated_at',
        commands: 'id,period_id,action,status,provider_reference,created_at',
        policies: 'id,version,document,created_at',
      };
    return this.transaction(async (c) => {
      const rows = (
          await c.query(
            'SELECT ' +
              columns[b.collection] +
              ' FROM g28.' +
              names[b.collection] +
              ' WHERE ($1::uuid IS NULL OR id>$1::uuid) ORDER BY id LIMIT 51',
            [b.after],
          )
        ).rows,
        more = rows.length > 50,
        items = rows.slice(0, 50);
      return { items, after: more ? items.at(-1).id : null, more };
    }, staff);
  }
  async reviewEnrollment(staff, id) {
    assert(staff, 'authentication_required', 'Verified treasury staff access is required.', 401);
    financeId(id);
    return this.transaction(async (c, actor) => {
      const e = (await c.query('SELECT * FROM g28.card_enrollments WHERE id=$1', [id])).rows[0];
      assert(
        e?.encrypted_details,
        'card_setup_unverified',
        'Verify the actual processor setup before source review.',
        409,
      );
      const verified = open(e.id, e.encrypted_details, this.config.treasuryKey);
      await audit(c, actor, e.id, 'card_billing_identity_read', {
        setupIntentId: verified.setupIntentId,
      });
      return {
        id: e.id,
        consent: e.request_document,
        billing: verified.billing,
        card: verified.card,
        status: e.status,
      };
    }, staff);
  }
  async rules(c) {
    const parent = (
        await c.query('SELECT document FROM g28.treasury_policies ORDER BY version DESC LIMIT 1')
      ).rows[0]?.document,
      rules = (
        await c.query(
          'SELECT document FROM g28.card_contribution_policies ORDER BY version DESC LIMIT 1',
        )
      ).rows[0]?.document;
    assert(
      parent && rules,
      'card_policy_unavailable',
      'Current treasury and card-control policies are required.',
      409,
    );
    return {
      parent: treasuryPolicy(parent, this.clock()),
      rules: cardContributionPolicy(rules, parent, this.clock()),
    };
  }
  async savePolicy(staff, input) {
    assert(staff, 'authentication_required', 'Verified treasury staff access is required.', 401);
    return this.transaction(async (c, actor) => {
      const parent = (
        await c.query('SELECT document FROM g28.treasury_policies ORDER BY version DESC LIMIT 1')
      ).rows[0]?.document;
      assert(parent, 'card_policy_unavailable', 'Record current treasury rules first.', 409);
      const p = cardContributionPolicy(input, parent, this.clock());
      await proof(c, p.evidenceDigest);
      const latest =
        (
          await c.query(
            'SELECT version FROM g28.card_contribution_policies ORDER BY version DESC LIMIT 1',
          )
        ).rows[0]?.version || 0;
      assert(
        p.version === latest + 1,
        'card_policy_conflict',
        'Publish the next exact policy version.',
        409,
      );
      await c.query(
        'INSERT INTO g28.card_contribution_policies(id,version,document,created_by) VALUES($1,$2,$3,$4)',
        [p.id, p.version, p, actor],
      );
      await audit(c, actor, p.id, 'card_policy_published', p);
      return p;
    }, staff);
  }
  async beginEnrollment(input, environment) {
    const b = cardEnrollmentRequest(input);
    assert(
      environment === 'test',
      'card_test_only',
      'Only reviewed TEST enrollments are installed.',
      503,
    );
    return this.transaction(async (c) => {
      const { rules } = await this.rules(c);
      assert(
        b.termsVersion === rules.termsVersion &&
          Date.parse(b.endAt) > this.clock() &&
          Date.parse(b.endAt) <=
            Math.min(Date.parse(rules.validUntil), Date.parse(rules.electionEnds[b.election])) &&
          b.maxInstallments <= rules.maxInstallments,
        'card_consent_policy',
        'Use the currently displayed amount, schedule, cutoff and terms.',
        409,
      );
      const digest = sha(b),
        old = (
          await c.query('SELECT * FROM g28.card_enrollments WHERE client_reference=$1', [
            b.clientReference,
          ])
        ).rows[0];
      if (old) {
        assert(
          old.id === b.id && old.request_sha256 === digest && old.environment === environment,
          'card_enrollment_conflict',
          'This browser request already has different immutable consent.',
          409,
        );
        return old;
      }
      await c.query(
        "INSERT INTO g28.card_enrollments(id,client_reference,request_document,request_sha256,environment,status) VALUES($1,$2,$3,$4,$5,'preparing')",
        [b.id, b.clientReference, b, digest, environment],
      );
      await audit(c, 'donor-browser', b.id, 'card_setup_prepared', b);
      return (await c.query('SELECT * FROM g28.card_enrollments WHERE id=$1', [b.id])).rows[0];
    });
  }
  async recordSetup(id, sessionId) {
    financeId(id);
    assert(
      /^cs_test_[A-Za-z0-9]{8,100}$/.test(sessionId),
      'card_setup_reference',
      'Use the exact processor TEST setup.',
    );
    return this.transaction(async (c) => {
      const row = (await c.query('SELECT * FROM g28.card_enrollments WHERE id=$1', [id])).rows[0];
      assert(
        row &&
          row.environment === 'test' &&
          ['preparing', 'pending'].includes(row.status) &&
          (!row.setup_session_id || row.setup_session_id === sessionId),
        'card_setup_conflict',
        'The original setup was changed or cancelled.',
        409,
      );
      await c.query(
        "UPDATE g28.card_enrollments SET setup_session_id=$2,status='pending',updated_at=now() WHERE id=$1",
        [id, sessionId],
      );
      await audit(c, 'processor', id, 'card_setup_recorded', { sessionId });
      return { id, sessionId };
    });
  }
  async verifyEnrollment(staff, id, driver) {
    assert(staff, 'authentication_required', 'Verified treasury staff access is required.', 401);
    financeId(id);
    const start = await this.transaction(async (c) => {
        const row = (await c.query('SELECT * FROM g28.card_enrollments WHERE id=$1', [id])).rows[0];
        assert(
          row && ['pending', 'verified', 'requires_review'].includes(row.status),
          'card_setup_unavailable',
          'This exact pending setup is not available.',
          409,
        );
        const { rules } = await this.rules(c);
        return { row, countries: rules.allowedCardCountries };
      }, staff),
      verified = await driver.verified(
        start.row.request_document,
        start.row.setup_session_id,
        start.countries,
      );
    return this.transaction(async (c, actor) => {
      const row = (await c.query('SELECT * FROM g28.card_enrollments WHERE id=$1', [id])).rows[0],
        { rules } = await this.rules(c);
      assert(
        row &&
          row.request_sha256 === start.row.request_sha256 &&
          row.setup_session_id === verified.sessionId &&
          row.status !== 'cancelled' &&
          rules.allowedCardCountries.includes(verified.card.issuerCountry),
        'card_setup_conflict',
        'The setup or current card policy changed during verification.',
        409,
      );
      assert(
        (
          await c.query(
            "SELECT 1 FROM g28.stripe_webhook_receipts WHERE session_id=$1 AND event_type='checkout.session.completed' AND livemode=false LIMIT 1",
            [verified.sessionId],
          )
        ).rowCount,
        'card_signed_setup_required',
        'Wait for an authenticated processor setup receipt before approval.',
        409,
      );
      await c.query(
        "UPDATE g28.card_enrollments SET customer_id=$2,payment_method_id=$3,setup_intent_id=$4,encrypted_details=$5,status='verified',updated_at=now() WHERE id=$1",
        [
          id,
          verified.customerId,
          verified.paymentMethodId,
          verified.setupIntentId,
          seal(id, verified, this.config.treasuryKey),
        ],
      );
      await audit(c, actor, id, 'card_setup_verified', {
        sessionId: verified.sessionId,
        setupIntentId: verified.setupIntentId,
      });
      return { id, status: 'verified' };
    }, staff);
  }
  async approveMandate(staff, input) {
    assert(staff, 'authentication_required', 'Verified treasury staff access is required.', 401);
    const b = exactKeys(input, [
      'id',
      'enrollmentId',
      'donorId',
      'donorVersion',
      'identityEvidenceDigest',
      'confirm',
    ]);
    financeId(b.id);
    financeId(b.enrollmentId);
    financeId(b.donorId);
    assert(
      b.confirm === 'approve exact documented card mandate',
      'card_mandate_confirmation',
      'Confirm this exact documented contributor and consent.',
    );
    return this.transaction(async (c, actor) => {
      const e = (await c.query('SELECT * FROM g28.card_enrollments WHERE id=$1', [b.enrollmentId]))
          .rows[0],
        { rules, parent } = await this.rules(c);
      assert(
        e?.status === 'verified',
        'card_setup_review_required',
        'Verify the actual card setup first.',
        409,
      );
      await proof(c, b.identityEvidenceDigest);
      const donor = (
        await c.query('SELECT version FROM g28.treasury_donors WHERE id=$1', [b.donorId])
      ).rows[0];
      assert(
        donor?.version === b.donorVersion,
        'card_donor_review_required',
        'Use the exact current source-verified contributor revision.',
        409,
      );
      const identityRow = (
        await c.query(
          'SELECT encrypted_envelope FROM g28.treasury_donor_revisions WHERE donor_id=$1 AND version=$2',
          [b.donorId, b.donorVersion],
        )
      ).rows[0];
      assert(
        identityRow,
        'card_donor_review_required',
        'The actual immutable contributor source is required.',
        409,
      );
      const identity = openFinanceIdentity(
        b.donorId,
        b.donorVersion,
        identityRow.encrypted_envelope,
        this.config.treasuryKey,
      );
      assert(
        identity.occupation && identity.employer,
        'card_donor_review_required',
        'Complete required contributor reporting information before online collection.',
        409,
      );
      const verified = open(e.id, e.encrypted_details, this.config.treasuryKey),
        r = e.request_document;
      assert(
        r.termsVersion === rules.termsVersion &&
          rules.allowedCardCountries.includes(verified.card.issuerCountry),
        'card_terms_changed',
        'Current source rules or terms require a new donor review.',
        409,
      );
      const old = (await c.query('SELECT * FROM g28.card_mandates WHERE enrollment_id=$1', [e.id]))
        .rows[0];
      if (old) {
        assert(
          old.id === b.id && old.donor_id === b.donorId && old.donor_version === b.donorVersion,
          'card_mandate_conflict',
          'This original setup already has another immutable mandate.',
          409,
        );
        return { mandate: old.document, status: old.status, version: old.version, duplicate: true };
      }
      const firstAt = new Date(this.clock()).toISOString(),
        m = cardMandate({
          id: b.id,
          enrollmentId: e.id,
          donorId: b.donorId,
          donorVersion: b.donorVersion,
          environment: e.environment,
          customerId: e.customer_id,
          paymentMethodId: e.payment_method_id,
          amountCents: r.amountCents,
          frequency: r.frequency,
          election: r.election,
          firstAt,
          endAt: r.endAt,
          maxInstallments: r.maxInstallments,
          termsVersion: r.termsVersion,
          consentDigest: r.consentDigest,
        });
      assert(
        Date.parse(m.endAt) >= this.clock() &&
          Date.parse(m.endAt) <=
            Math.min(Date.parse(rules.validUntil), Date.parse(rules.electionEnds[m.election])) &&
          m.amountCents <= parent.electionLimits[m.election],
        'card_mandate_expired',
        'The consent or approved election window no longer permits this schedule.',
        409,
      );
      const active = Number(
        (
          await c.query(
            "SELECT count(*)::int AS n FROM g28.card_mandates WHERE donor_id=$1 AND environment=$2 AND status='active'",
            [m.donorId, m.environment],
          )
        ).rows[0].n,
      );
      assert(
        active < rules.maxSchedulesPerDonor,
        'card_schedule_limit',
        'Review the existing active schedules before another commitment.',
        409,
      );
      await c.query(
        "INSERT INTO g28.card_mandates(id,enrollment_id,donor_id,donor_version,environment,document,status,version,approved_by) VALUES($1,$2,$3,$4,$5,$6,'active',1,$7)",
        [m.id, e.id, m.donorId, m.donorVersion, m.environment, m, actor],
      );
      await c.query(
        'INSERT INTO g28.card_mandate_revisions(mandate_id,version,document,created_by) VALUES($1,1,$2,$3)',
        [m.id, m, actor],
      );
      await audit(c, actor, m.id, 'card_mandate_approved', {
        mandate: m,
        identityEvidenceDigest: b.identityEvidenceDigest,
      });
      return { mandate: m, status: 'active', version: 1 };
    }, staff);
  }
  async reservePeriod(staff, input) {
    assert(staff, 'authentication_required', 'Verified treasury staff access is required.', 401);
    const b = exactKeys(input, ['id', 'mandateId', 'mandateVersion', 'index', 'confirm']);
    financeId(b.id);
    financeId(b.mandateId);
    assert(
      b.confirm === 'reserve exact due installment',
      'card_period_confirmation',
      'Confirm the exact due installment and current aggregate.',
    );
    return this.transaction(async (c, actor) => {
      const row = (await c.query('SELECT * FROM g28.card_mandates WHERE id=$1', [b.mandateId]))
        .rows[0];
      assert(
        row?.status === 'active' && row.version === b.mandateVersion,
        'card_mandate_changed',
        'Reload the current active mandate before preparing a charge.',
        409,
      );
      const m = row.document,
        { rules, parent } = await this.rules(c),
        old = (
          await c.query('SELECT * FROM g28.card_periods WHERE mandate_id=$1 AND installment=$2', [
            m.id,
            b.index,
          ])
        ).rows[0];
      if (old) {
        assert(
          old.id === b.id,
          'card_period_conflict',
          'This installment already has a different immutable reference.',
          409,
        );
        return { period: old, duplicate: true };
      }
      assert(
        !(
          await c.query(
            'SELECT 1 FROM g28.card_periods WHERE mandate_id=$1 AND reservation_active LIMIT 1',
            [m.id],
          )
        ).rowCount,
        'card_prior_period_unresolved',
        'Resolve the existing authorization or unposted captured installment before another period.',
        409,
      );
      const totals = (
          await c.query(
            "SELECT COALESCE((SELECT sum((state->'allocations'->>$3)::bigint) FROM g28.treasury_gifts WHERE donor_id=$1 AND environment=$2),0)::text AS posted,COALESCE((SELECT sum(amount_cents) FROM g28.card_periods WHERE donor_id=$1 AND environment=$2 AND election=$3 AND reservation_active),0)::text AS reserved",
            [m.donorId, m.environment, m.election],
          )
        ).rows[0],
        active = Number(
          (
            await c.query(
              "SELECT count(*)::int AS n FROM g28.card_mandates WHERE donor_id=$1 AND environment=$2 AND status='active'",
              [m.donorId, m.environment],
            )
          ).rows[0].n,
        ),
        cases = Number(
          (
            await c.query(
              "SELECT count(*)::int AS n FROM g28.treasury_cases c JOIN g28.treasury_gifts g ON g.id=c.gift_id WHERE g.donor_id=$1 AND g.environment=$2 AND c.document->>'status'<>'closed'",
              [m.donorId, m.environment],
            )
          ).rows[0].n,
        ),
        d = (await c.query('SELECT version FROM g28.treasury_donors WHERE id=$1', [m.donorId]))
          .rows[0],
        decision = decideCardInstallment({
          rules,
          treasury: parent,
          mandate: m,
          index: b.index,
          periodId: b.id,
          postedCents: totals.posted,
          reservedCents: totals.reserved,
          activeSchedules: active,
          openCaseCount: cases,
          donorVersion: d?.version,
          now: this.clock(),
        }),
        doc = {
          ...decision,
          mandateVersion: row.version,
          mandateDigest: sha(m),
          policyDigest: sha({ parent, rules }),
        };
      await c.query(
        "INSERT INTO g28.card_periods(id,mandate_id,mandate_version,installment,donor_id,donor_version,environment,election,amount_cents,document,status,reservation_active,expires_at,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'reserved',true,$11,1)",
        [
          b.id,
          m.id,
          row.version,
          b.index,
          m.donorId,
          m.donorVersion,
          m.environment,
          m.election,
          m.amountCents,
          doc,
          doc.expiresAt,
        ],
      );
      await audit(c, actor, b.id, 'card_period_reserved', doc);
      return {
        period: (await c.query('SELECT * FROM g28.card_periods WHERE id=$1', [b.id])).rows[0],
        duplicate: false,
      };
    }, staff);
  }

  // Each outgoing operation has a committed command first. A crash or lost
  // response leaves that command unresolved; only observation may recover it.
  async currentDecision(c, period) {
    const row = (await c.query('SELECT * FROM g28.card_mandates WHERE id=$1', [period.mandate_id]))
      .rows[0];
    assert(
      row?.status === 'active' && row.version === period.mandate_version,
      'card_mandate_changed',
      'This schedule was cancelled, held or revised. No new funds may be collected.',
      409,
    );
    const m = row.document,
      { rules, parent } = await this.rules(c),
      totals = (
        await c.query(
          "SELECT COALESCE((SELECT sum((state->'allocations'->>$3)::bigint) FROM g28.treasury_gifts WHERE donor_id=$1 AND environment=$2),0)::text AS posted,COALESCE((SELECT sum(amount_cents) FROM g28.card_periods WHERE donor_id=$1 AND environment=$2 AND election=$3 AND reservation_active AND id<>$4),0)::text AS reserved",
          [m.donorId, m.environment, m.election, period.id],
        )
      ).rows[0],
      active = Number(
        (
          await c.query(
            "SELECT count(*)::int AS n FROM g28.card_mandates WHERE donor_id=$1 AND environment=$2 AND status='active'",
            [m.donorId, m.environment],
          )
        ).rows[0].n,
      ),
      cases = Number(
        (
          await c.query(
            "SELECT count(*)::int AS n FROM g28.treasury_cases c JOIN g28.treasury_gifts g ON g.id=c.gift_id WHERE g.donor_id=$1 AND g.environment=$2 AND c.document->>'status'<>'closed'",
            [m.donorId, m.environment],
          )
        ).rows[0].n,
      ),
      donor = (await c.query('SELECT version FROM g28.treasury_donors WHERE id=$1', [m.donorId]))
        .rows[0];
    const decision = decideCardInstallment({
      rules,
      treasury: parent,
      mandate: m,
      index: period.installment,
      periodId: period.id,
      postedCents: totals.posted,
      reservedCents: totals.reserved,
      activeSchedules: active,
      openCaseCount: cases,
      donorVersion: donor?.version,
      now: this.clock(),
    });
    assert(
      period.reservation_active &&
        period.donor_id === m.donorId &&
        period.donor_version === m.donorVersion &&
        Number(period.amount_cents) === m.amountCents &&
        period.environment === m.environment &&
        period.election === m.election,
      'card_period_binding',
      'The reserved installment no longer matches its immutable mandate.',
      409,
    );
    return { decision, rules, parent, mandate: m };
  }
  async prepareCommand(staff, input) {
    assert(staff, 'authentication_required', 'Verified treasury staff access is required.', 401);
    const b = exactKeys(input, ['id', 'periodId', 'periodVersion', 'action', 'confirm']);
    financeId(b.id);
    financeId(b.periodId);
    assert(
      ['authorize', 'capture', 'cancel'].includes(b.action) &&
        Number.isSafeInteger(b.periodVersion) &&
        b.periodVersion > 0 &&
        b.confirm === 'prepare exact ' + b.action,
      'card_command_confirmation',
      'Confirm the exact current financial operation.',
    );
    return this.transaction(async (c, actor) => {
      const old = (await c.query('SELECT * FROM g28.card_commands WHERE id=$1', [b.id])).rows[0];
      if (old) {
        assert(
          old.request_sha256 === sha(b),
          'card_command_conflict',
          'This immutable command already has different content.',
          409,
        );
        return { command: old, duplicate: true };
      }
      const p = (await c.query('SELECT * FROM g28.card_periods WHERE id=$1', [b.periodId])).rows[0];
      assert(
        p && p.version === b.periodVersion && p.reservation_active,
        'card_period_changed',
        'Reload the current unresolved installment.',
        409,
      );
      assert(
        !(
          await c.query(
            "SELECT 1 FROM g28.card_commands WHERE period_id=$1 AND status IN ('processing','uncertain')",
            [p.id],
          )
        ).rowCount,
        'card_command_unresolved',
        'Reconcile the existing command before another operation.',
        409,
      );
      let doc = p.document;
      if (b.action === 'cancel')
        assert(
          p.provider_payment_id && !['captured_unposted', 'posted'].includes(p.status),
          'card_cancel_unavailable',
          'Only an actual uncaptured authorization can be voided. Captured gifts require the separate refund workflow.',
          409,
        );
      else {
        const current = await this.currentDecision(c, p);
        if (b.action === 'authorize') {
          assert(
            p.status === 'reserved' &&
              new Date(p.expires_at).getTime() > this.clock() &&
              !(
                await c.query(
                  "SELECT 1 FROM g28.card_commands WHERE period_id=$1 AND action='authorize'",
                  [p.id],
                )
              ).rowCount,
            'card_authorization_replay',
            'This installment already has an attempt or expired reservation. Reconcile or close it; never create another authorization.',
            409,
          );
          const m = current.mandate;
          doc = {
            ...doc,
            providerApproval: {
              attemptId: b.id,
              periodId: p.id,
              customerId: m.customerId,
              paymentMethodId: m.paymentMethodId,
              amountCents: m.amountCents,
              environment: m.environment,
              policyDigest: sha({ parent: current.parent, rules: current.rules }),
              mandateDigest: sha(m),
              confirmationMode: p.installment === 0 ? 'on_session' : 'off_session',
              expiresAt: current.decision.expiresAt,
            },
          };
        } else
          assert(
            p.status === 'authorized' && p.provider_payment_id,
            'card_capture_unavailable',
            'Reconcile the exact uncaptured authorization before capture.',
            409,
          );
      }
      assert(
        doc.providerApproval,
        'card_authorization_required',
        'The original exact provider approval is required.',
        409,
      );
      await c.query(
        "INSERT INTO g28.card_commands(id,period_id,action,request_document,request_sha256,status,created_by) VALUES($1,$2,$3,$4,$5,'processing',$6)",
        [b.id, p.id, b.action, b, sha(b), actor],
      );
      await c.query(
        'UPDATE g28.card_periods SET document=$2,status=$3,version=version+1,updated_at=now() WHERE id=$1',
        [
          p.id,
          doc,
          { authorize: 'authorizing', capture: 'capturing', cancel: 'cancelling' }[b.action],
        ],
      );
      await audit(c, actor, p.id, 'card_command_prepared', {
        commandId: b.id,
        action: b.action,
        requestDigest: sha(b),
      });
      return {
        command: (await c.query('SELECT * FROM g28.card_commands WHERE id=$1', [b.id])).rows[0],
        duplicate: false,
      };
    }, staff);
  }
  async observeCommand(c, command, period, seen, actor) {
    assert(
      seen.id && (!period.provider_payment_id || period.provider_payment_id === seen.id),
      'card_processor_binding',
      'Observation belongs to another processor intent.',
      409,
    );
    assert(
      Number.isSafeInteger(seen.amountReceived) &&
        seen.amountReceived >= 0 &&
        (seen.status !== 'succeeded' || seen.amountReceived === Number(period.amount_cents)) &&
        (seen.status !== 'canceled' || (seen.amountReceived === 0 && seen.amountCapturable === 0)),
      'card_processor_uncertain',
      'The observed financial outcome is not an exact final capture or void.',
      409,
    );
    assert(
      period.status !== 'voided' || seen.status === 'canceled',
      'card_terminal_state',
      'A confirmed void cannot be revived by a late observation.',
      409,
    );
    const status =
      seen.status === 'succeeded'
        ? 'captured_unposted'
        : seen.status === 'canceled'
          ? 'voided'
          : seen.status === 'requires_capture'
            ? 'authorized'
            : ['requires_action', 'requires_confirmation', 'requires_payment_method'].includes(
                  seen.status,
                )
              ? 'requires_action'
              : 'uncertain';
    // A late observation cannot erase an already journaled or captured gift.
    assert(
      !['posted', 'captured_unposted'].includes(period.status) ||
        ['posted', 'captured_unposted'].includes(status),
      'card_terminal_state',
      'A terminal financial state cannot be rolled back by a late response.',
      409,
    );
    const finalStatus = period.status === 'posted' ? 'posted' : status;
    await c.query(
      'UPDATE g28.card_commands SET status=$2,provider_reference=$3,result_document=$4,updated_at=now() WHERE id=$1',
      [command.id, status === 'uncertain' ? 'uncertain' : 'observed', seen.id, seen],
    );
    await c.query(
      'UPDATE g28.card_periods SET provider_payment_id=$2,status=$3,reservation_active=$4,version=version+1,updated_at=now() WHERE id=$1',
      [period.id, seen.id, finalStatus, !['voided', 'posted'].includes(finalStatus)],
    );
    await audit(c, actor, period.id, 'card_command_observed', { commandId: command.id, seen });
    return { commandId: command.id, periodId: period.id, status: finalStatus, result: seen };
  }
  async performCommand(staff, id, driver) {
    assert(staff, 'authentication_required', 'Verified treasury staff access is required.', 401);
    financeId(id);
    // Claim once in its own committed transaction. Processing is deliberately
    // not a lease: a timeout never grants permission to retry financial I/O.
    const claimed = await this.transaction(async (c, actor) => {
      const cmd = (await c.query('SELECT * FROM g28.card_commands WHERE id=$1', [id])).rows[0];
      assert(
        cmd && cmd.status === 'processing',
        'card_command_unresolved',
        'This command was dispatched or requires reconciliation.',
        409,
      );
      assert(
        !cmd.result_document,
        'card_command_unresolved',
        'This command was already dispatched. Reconcile it instead.',
        409,
      );
      await c.query('UPDATE g28.card_commands SET result_document=$2 WHERE id=$1', [
        id,
        { dispatchClaimed: true },
      ]);
      await audit(c, actor, cmd.period_id, 'card_dispatch_claimed', { commandId: id });
      return cmd;
    }, staff);
    try {
      return await this.transaction(async (c, actor) => {
        const cmd = (await c.query('SELECT * FROM g28.card_commands WHERE id=$1', [id])).rows[0],
          p = (await c.query('SELECT * FROM g28.card_periods WHERE id=$1', [claimed.period_id]))
            .rows[0];
        assert(
          cmd?.status === 'processing' && p.reservation_active,
          'card_command_unresolved',
          'The original dispatch is no longer current.',
          409,
        );
        let approval = p.document.providerApproval;
        if (cmd.action === 'authorize')
          assert(
            new Date(p.expires_at).getTime() > this.clock(),
            'card_dispatch_expired',
            'This original authorization reservation expired before dispatch.',
            409,
          );
        if (cmd.action !== 'cancel') {
          const current = await this.currentDecision(c, p);
          approval = { ...approval, expiresAt: current.decision.expiresAt };
          await audit(c, actor, p.id, 'card_dispatch_rechecked', {
            commandId: id,
            decision: current.decision,
            policyDigest: sha({ parent: current.parent, rules: current.rules }),
          });
          await driver.instrument(approval, current.rules.allowedCardCountries);
          if (cmd.action === 'capture') {
            const seen = await driver.inspect(approval, p.provider_payment_id);
            assert(
              seen.status === 'requires_capture' &&
                seen.amountCapturable === approval.amountCents &&
                seen.amountReceived === 0,
              'card_capture_unavailable',
              'The actual original intent is not authorized for the exact full capture.',
              409,
            );
          }
        }
        // The journal and mandate locks remain held through this bounded provider
        // call. Later cash postings/cancellation cannot overtake this decision.
        const seen =
          cmd.action === 'authorize'
            ? await driver.authorize(approval)
            : cmd.action === 'capture'
              ? await driver.capture(approval, p.provider_payment_id)
              : await driver.cancel(approval, p.provider_payment_id);
        return this.observeCommand(c, cmd, p, seen, actor);
      }, staff);
    } catch (error) {
      // This also covers failure before dispatch. Conservative unknown state is
      // preferable to guessing that a timed-out/crashed process sent nothing.
      await this.transaction(async (c) => {
        await c.query(
          "UPDATE g28.card_commands SET status='uncertain',updated_at=now() WHERE id=$1 AND status='processing'",
          [id],
        );
        await c.query(
          "UPDATE g28.card_periods SET status='uncertain',version=version+1,updated_at=now() WHERE id=$1 AND status NOT IN ('posted','captured_unposted','voided')",
          [claimed.period_id],
        );
        await audit(c, 'processor', claimed.period_id, 'card_dispatch_requires_reconciliation', {
          commandId: id,
        });
      });
      throw error;
    }
  }
  async reconcileCommand(staff, id, providerId, driver) {
    assert(staff, 'authentication_required', 'Verified treasury staff access is required.', 401);
    financeId(id);
    assert(
      /^pi_[A-Za-z0-9]{8,100}$/.test(providerId),
      'card_processor_reference',
      'Use the exact provider intent; no replacement attempt.',
    );
    return this.transaction(async (c, actor) => {
      const cmd = (await c.query('SELECT * FROM g28.card_commands WHERE id=$1', [id])).rows[0];
      assert(cmd, 'card_command_not_found', 'The original command is required.', 404);
      const p = (await c.query('SELECT * FROM g28.card_periods WHERE id=$1', [cmd.period_id]))
        .rows[0];
      assert(
        !p.provider_payment_id || p.provider_payment_id === providerId,
        'card_processor_binding',
        'Use this exact original intent.',
        409,
      );
      const seen = await driver.inspect(p.document.providerApproval, providerId);
      const result = await this.observeCommand(c, cmd, p, seen, actor);
      await audit(c, actor, p.id, 'card_command_reconciled', { commandId: id, providerId });
      return result;
    }, staff);
  }
  async cancelMandate(staff, id, version) {
    assert(staff, 'authentication_required', 'Verified treasury staff access is required.', 401);
    financeId(id);
    return this.transaction(async (c, actor) => {
      const m = (await c.query('SELECT * FROM g28.card_mandates WHERE id=$1', [id])).rows[0];
      assert(
        m && m.version === version,
        'card_mandate_changed',
        'Reload the exact current schedule before cancelling.',
        409,
      );
      if (m.status === 'cancelled')
        return { id, status: 'cancelled', version: m.version, duplicate: true };
      const next = version + 1,
        document = {
          ...m.document,
          cancellation: {
            at: new Date(this.clock()).toISOString(),
            actor,
            meaning:
              'No new authorizations or captures after cancellation is committed. Existing captured contributions remain; uncertain bank holds require reconciliation.',
          },
        };
      await c.query(
        "UPDATE g28.card_mandates SET status='cancelled',version=$2,updated_at=now() WHERE id=$1",
        [id, next],
      );
      await c.query(
        'INSERT INTO g28.card_mandate_revisions(mandate_id,version,document,created_by) VALUES($1,$2,$3,$4)',
        [id, next, document, actor],
      );
      await audit(c, actor, id, 'card_mandate_cancelled', { version: next });
      return { id, status: 'cancelled', version: next };
    }, staff);
  }
}
