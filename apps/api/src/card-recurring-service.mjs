// Donor self-service, replacement card setup, bank-confirmation binding and the
// operational due-installment queue for TEST monthly card schedules.
//
// Boundaries kept from the reviewed manual-capture design:
// - A donor can see, cancel and request a card change for their own schedule, and
//   authenticate the first installment with their bank. A donor can never create,
//   reserve, authorize beyond the staff-prepared attempt, or capture funds.
// - Due-installment processing identifies due, missed and finished installments,
//   releases never-dispatched expired reservations and completes finished schedules.
//   Every authorization and capture still needs current owner/treasurer authority and a
//   fresh staff passkey, rechecking all-channel limits immediately before dispatch.
// - Missed monthly periods are never caught up.
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { assert, exactKeys } from '../../../packages/core/validation.mjs';
import { financeId } from '../../../packages/core/treasury-workflow.mjs';
import { cardInstallmentAt } from '../../../packages/core/card-mandates.mjs';
import { canonical } from '../../../packages/core/protected-crypto.mjs';
import { randomUUID } from 'node:crypto';

const sha = (x) =>
  createHash('sha256')
    .update(typeof x === 'string' ? x : canonical(x))
    .digest('hex');
const audit = (c, actor, id, action, value) =>
  c.query(
    'INSERT INTO g28.card_workflow_audit(id,actor_id,object_id,action,digest) VALUES($1,$2,$3,$4,$5)',
    [randomUUID(), actor, id, action, sha(value)],
  );
const CLIENT_REF = /^attempt_[a-f0-9]{32}$/;
export const RECOVERY_CODE = /^G28R-[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){5}$/;
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

// 24 symbols from a 32-symbol alphabet: 120 bits. Shown once, stored only as a digest.
export function newRecoveryCode() {
  const bytes = randomBytes(24);
  const symbols = [...bytes].map((b) => ALPHABET[b & 31]).join('');
  return 'G28R-' + symbols.match(/.{4}/g).join('-');
}
export const recoveryDigest = (code) => sha('g28:card-recovery:v1:' + code);

function nextMonth(stamp, index) {
  const first = new Date(stamp),
    month = first.getUTCMonth() + index,
    year = first.getUTCFullYear() + Math.floor(month / 12),
    day = Math.min(first.getUTCDate(), new Date(Date.UTC(year, (month % 12) + 1, 0)).getUTCDate());
  return Date.UTC(
    year,
    month % 12,
    day,
    first.getUTCHours(),
    first.getUTCMinutes(),
    first.getUTCSeconds(),
    first.getUTCMilliseconds(),
  );
}
// The latest moment an installment may still be collected: never past the consent
// cutoff and, for monthly schedules, never into the next month (no catch-up).
export function installmentWindow(m, index) {
  const at = Date.parse(cardInstallmentAt(m, index));
  const end = Math.min(
    Date.parse(m.endAt),
    m.frequency === 'monthly' ? nextMonth(m.firstAt, index + 1) : Infinity,
  );
  return { at, end };
}

export class RecurringCardService {
  constructor({ cards, clock = Date.now }) {
    this.cards = cards;
    this.clock = clock;
  }
  tx(fn, staff = null) {
    return this.cards.transaction(fn, staff);
  }

  // ---- Public rules shown before any setup ----------------------------------------
  async publicRules() {
    return this.tx(async (c) => {
      const { rules } = await this.cards.rules(c);
      return {
        termsVersion: rules.termsVersion,
        maxInstallments: rules.maxInstallments,
        cutoffs: {
          primary: new Date(
            Math.min(Date.parse(rules.electionEnds.primary), Date.parse(rules.validUntil)),
          ).toISOString(),
          general: new Date(
            Math.min(Date.parse(rules.electionEnds.general), Date.parse(rules.validUntil)),
          ).toISOString(),
        },
      };
    });
  }

  // ---- Prospective setup -----------------------------------------------------------
  // Records the donor's immutable consent and binds a recovery digest. Replayed
  // submissions of the same browser reference return the original record unchanged.
  async beginSetup(request, { recoveryCode, replacesMandateId = null }) {
    assert(RECOVERY_CODE.test(recoveryCode), 'card_recovery_code', 'Invalid recovery code.');
    if (replacesMandateId !== null) financeId(replacesMandateId);
    const row = await this.cards.beginEnrollment(request, 'test');
    return this.tx(async (c) => {
      const current = (
        await c.query('SELECT * FROM g28.card_enrollments WHERE id=$1 FOR UPDATE', [row.id])
      ).rows[0];
      if (!current.recovery_sha256) {
        await c.query(
          'UPDATE g28.card_enrollments SET recovery_sha256=$2,replaces_mandate_id=$3,updated_at=now() WHERE id=$1',
          [row.id, recoveryDigest(recoveryCode), replacesMandateId],
        );
        await audit(c, 'donor-browser', row.id, 'card_recovery_bound', {
          replacesMandateId,
        });
        return { enrollment: { ...current, replaces_mandate_id: replacesMandateId }, fresh: true };
      }
      assert(
        current.replaces_mandate_id === replacesMandateId,
        'card_enrollment_conflict',
        'This browser request already has different immutable consent.',
        409,
      );
      // A replay never rebinds recovery: the original code stays authoritative.
      return { enrollment: current, fresh: false };
    });
  }

  // ---- Donor authority -------------------------------------------------------------
  async #owned(c, enrollmentId, clientReference, lock = false) {
    financeId(enrollmentId);
    assert(CLIENT_REF.test(clientReference), 'donor_authority', 'Open your schedule again.', 403);
    const e = (
      await c.query(
        'SELECT * FROM g28.card_enrollments WHERE id=$1' + (lock ? ' FOR UPDATE' : ''),
        [enrollmentId],
      )
    ).rows[0];
    assert(
      e &&
        e.environment === 'test' &&
        e.client_reference.length === clientReference.length &&
        timingSafeEqual(Buffer.from(e.client_reference), Buffer.from(clientReference)),
      'donor_authority',
      'This browser cannot manage that schedule.',
      403,
    );
    const mandate = (
      await c.query(
        'SELECT * FROM g28.card_mandates WHERE id=$1 OR enrollment_id=$2' +
          (lock ? ' FOR UPDATE' : ''),
        [e.replaces_mandate_id, e.id],
      )
    ).rows[0];
    return { e, mandate: mandate || null };
  }
  async recover(code) {
    if (typeof code !== 'string' || !RECOVERY_CODE.test(code.trim().toUpperCase())) return null;
    return this.tx(async (c) => {
      const e = (
        await c.query(
          'SELECT id,client_reference FROM g28.card_enrollments WHERE recovery_sha256=$1',
          [recoveryDigest(code.trim().toUpperCase())],
        )
      ).rows[0];
      if (e) await audit(c, 'donor-browser', e.id, 'card_donor_recovered', {});
      return e ? { enrollmentId: e.id, clientReference: e.client_reference } : null;
    });
  }

  // What the donor can see: their consent, schedule and installment states. No billing
  // identity, card number, processor secret or other donor's information.
  async donorView(enrollmentId, clientReference) {
    return this.tx(async (c) => {
      const { e, mandate } = await this.#owned(c, enrollmentId, clientReference);
      const r = e.request_document;
      const view = {
        enrollment: {
          id: e.id,
          status: e.status,
          donorCancelled: Boolean(e.donor_cancelled_at),
          replacesSchedule: Boolean(e.replaces_mandate_id),
          amountCents: r.amountCents,
          frequency: r.frequency,
          election: r.election,
          maxInstallments: r.maxInstallments,
          endAt: r.endAt,
          termsVersion: r.termsVersion,
        },
        schedule: null,
        installments: [],
        confirmation: null,
      };
      if (!mandate) return view;
      const m = mandate.document,
        periods = (
          await c.query(
            'SELECT id,installment,status,reservation_active,document,provider_payment_id FROM g28.card_periods WHERE mandate_id=$1 ORDER BY installment',
            [mandate.id],
          )
        ).rows,
        due = (
          await c.query(
            'SELECT installment,status,due_at FROM g28.card_due_installments WHERE mandate_id=$1 ORDER BY installment',
            [mandate.id],
          )
        ).rows;
      const used = new Set([...periods.map((p) => p.installment), ...due.map((d) => d.installment)]);
      let next = null;
      if (mandate.status === 'active')
        for (let i = 0; i < m.maxInstallments; i++) {
          if (used.has(i)) continue;
          const w = installmentWindow(m, i);
          if (w.end >= this.clock()) {
            next = new Date(Math.max(w.at, this.clock())).toISOString();
            break;
          }
        }
      view.schedule = {
        status: mandate.status,
        version: mandate.version,
        amountCents: m.amountCents,
        frequency: m.frequency,
        election: m.election,
        firstAt: m.firstAt,
        endAt: m.endAt,
        maxInstallments: m.maxInstallments,
        nextScheduledAt: next,
      };
      const label = {
        reserved: 'being prepared',
        authorizing: 'being authorized',
        requires_action: 'waiting for your bank confirmation',
        authorized: 'authorized, not yet collected',
        capturing: 'being collected',
        captured_unposted: 'collected',
        posted: 'collected',
        cancelling: 'being released',
        voided: 'released without collection',
        uncertain: 'under treasury review',
        blocked: 'not collected',
      };
      view.installments = [
        ...periods.map((p) => ({ installment: p.installment, state: label[p.status] })),
        ...due
          .filter((d) => !periods.some((p) => p.installment === d.installment))
          .map((d) => ({
            installment: d.installment,
            state: d.status === 'missed' ? 'skipped (not collected)' : 'due for treasury review',
          })),
      ].sort((a, b) => a.installment - b.installment);
      const waiting = periods.find(
        (p) =>
          p.status === 'requires_action' &&
          p.reservation_active &&
          p.provider_payment_id &&
          p.document?.providerApproval?.confirmationMode === 'on_session',
      );
      if (waiting && mandate.status === 'active') {
        const w = installmentWindow(m, waiting.installment);
        if (w.end > this.clock()) view.confirmation = { periodId: waiting.id };
      }
      return view;
    });
  }

  // ---- Donor cancellation ----------------------------------------------------------
  // Idempotent. Stops every future authorization or capture once committed. Captured
  // contributions remain; an attempt already sent to the processor stays reserved for
  // exact treasury reconciliation (it is never silently dropped).
  async donorCancel(enrollmentId, clientReference) {
    return this.tx(async (c) => {
      const { e, mandate } = await this.#owned(c, enrollmentId, clientReference, true);
      const at = new Date(this.clock()).toISOString();
      if (!mandate) {
        if (e.status === 'cancelled') return { setup: 'cancelled', duplicate: true };
        await c.query(
          "UPDATE g28.card_enrollments SET status='cancelled',donor_cancelled_at=now(),updated_at=now() WHERE id=$1",
          [e.id],
        );
        await audit(c, 'donor-browser', e.id, 'card_setup_cancelled_by_donor', { at });
        return { setup: 'cancelled' };
      }
      // Any pending replacement-card request for this schedule is withdrawn too.
      await c.query(
        "UPDATE g28.card_enrollments SET status='cancelled',donor_cancelled_at=now(),updated_at=now() WHERE replaces_mandate_id=$1 AND status<>'cancelled'",
        [mandate.id],
      );
      if (['cancelled', 'complete'].includes(mandate.status))
        return { schedule: mandate.status, duplicate: true };
      const version = mandate.version + 1,
        revision = {
          ...mandate.document,
          cancellation: {
            at,
            actor: 'donor',
            meaning:
              'Cancelled by the donor. No new authorizations or captures after this is committed. Collected contributions remain; any attempt already sent to the processor is reconciled by treasury and released or refunded, never re-attempted.',
          },
        };
      await c.query(
        "UPDATE g28.card_mandates SET status='cancelled',version=$2,updated_at=now() WHERE id=$1",
        [mandate.id, version],
      );
      await c.query(
        'INSERT INTO g28.card_mandate_revisions(mandate_id,version,document,created_by) VALUES($1,$2,$3,$4)',
        [mandate.id, version, revision, 'donor-browser'],
      );
      // Release reservations that never reached the processor.
      await c.query(
        "UPDATE g28.card_periods p SET status='blocked',reservation_active=false,version=version+1,updated_at=now() WHERE p.mandate_id=$1 AND p.status='reserved' AND NOT EXISTS(SELECT 1 FROM g28.card_commands k WHERE k.period_id=p.id)",
        [mandate.id],
      );
      await c.query(
        "UPDATE g28.card_due_installments SET status='closed',updated_at=now() WHERE mandate_id=$1 AND status='due'",
        [mandate.id],
      );
      await audit(c, 'donor-browser', mandate.id, 'card_mandate_cancelled_by_donor', {
        version,
        at,
      });
      return { schedule: 'cancelled' };
    });
  }

  // ---- Bank confirmation of a staff-prepared first installment -------------------------
  async confirmationTarget(enrollmentId, clientReference, periodId) {
    financeId(periodId);
    return this.tx(async (c) => {
      const { mandate } = await this.#owned(c, enrollmentId, clientReference);
      const p = (
        await c.query('SELECT * FROM g28.card_periods WHERE id=$1', [periodId])
      ).rows[0];
      assert(
        mandate &&
          mandate.status === 'active' &&
          p &&
          p.mandate_id === mandate.id &&
          p.mandate_version === mandate.version &&
          p.status === 'requires_action' &&
          p.reservation_active &&
          /^pi_[A-Za-z0-9]{8,100}$/.test(p.provider_payment_id || '') &&
          p.document?.providerApproval?.confirmationMode === 'on_session' &&
          installmentWindow(mandate.document, p.installment).end > this.clock(),
        'card_confirmation_unavailable',
        'There is no installment waiting for your bank confirmation.',
        409,
      );
      return {
        approval: p.document.providerApproval,
        paymentIntentId: p.provider_payment_id,
        periodId: p.id,
      };
    });
  }
  // Records the processor state observed after the donor returns from their bank. The
  // observation is bound to the original authorize command; it cannot capture funds.
  async recordConfirmationObservation(periodId, seen) {
    financeId(periodId);
    return this.tx(async (c) => {
      const p = (
        await c.query('SELECT * FROM g28.card_periods WHERE id=$1 FOR UPDATE', [periodId])
      ).rows[0];
      const cmd = (
        await c.query(
          "SELECT * FROM g28.card_commands WHERE period_id=$1 AND action='authorize' ORDER BY created_at LIMIT 1",
          [periodId],
        )
      ).rows[0];
      assert(p && cmd, 'card_confirmation_unavailable', 'Unknown installment.', 409);
      assert(
        ['requires_action', 'requires_capture', 'canceled', 'processing'].includes(seen.status) &&
          seen.amountReceived === 0,
        'card_processor_uncertain',
        'The observed state needs treasury reconciliation.',
        409,
      );
      return this.cards.observeCommand(c, cmd, p, seen, 'donor-browser');
    });
  }

  // ---- Replacement card (payment-method change) -------------------------------------
  // The donor's replacement setup is reviewed like a new card: signed setup callback,
  // fresh private processor verification and documented staff approval. Only then does
  // the mandate's saved method change, as a new immutable mandate version.
  async approveMethodChange(staff, input) {
    assert(staff, 'authentication_required', 'Verified treasury staff access is required.', 401);
    const b = exactKeys(input, [
      'mandateId',
      'mandateVersion',
      'enrollmentId',
      'identityEvidenceDigest',
      'confirm',
    ]);
    financeId(b.mandateId);
    financeId(b.enrollmentId);
    assert(
      b.confirm === 'replace exact saved card for future installments' &&
        Number.isSafeInteger(b.mandateVersion) &&
        /^[a-f0-9]{64}$/.test(b.identityEvidenceDigest),
      'card_method_confirmation',
      'Confirm the exact replacement card and documentary review.',
    );
    return this.tx(async (c, actor) => {
      assert(
        (
          await c.query('SELECT 1 FROM g28.treasury_evidence WHERE digest=$1 LIMIT 1', [
            b.identityEvidenceDigest,
          ])
        ).rowCount,
        'card_documentary_evidence',
        'Record the actual private documentary evidence before approval.',
        409,
      );
      const mandate = (
          await c.query('SELECT * FROM g28.card_mandates WHERE id=$1 FOR UPDATE', [b.mandateId])
        ).rows[0],
        e = (
          await c.query('SELECT * FROM g28.card_enrollments WHERE id=$1 FOR UPDATE', [
            b.enrollmentId,
          ])
        ).rows[0];
      assert(
        mandate?.status === 'active' && mandate.version === b.mandateVersion,
        'card_mandate_changed',
        'Reload the current active schedule.',
        409,
      );
      assert(
        e &&
          e.replaces_mandate_id === mandate.id &&
          e.status === 'verified' &&
          !e.donor_cancelled_at &&
          e.environment === mandate.environment &&
          /^cus_/.test(e.customer_id || '') &&
          /^pm_/.test(e.payment_method_id || ''),
        'card_setup_review_required',
        'Verify the actual replacement card setup first.',
        409,
      );
      const r = e.request_document,
        m = mandate.document;
      assert(
        r.amountCents === m.amountCents &&
          r.frequency === m.frequency &&
          r.election === m.election &&
          Date.parse(r.endAt) <= Date.parse(m.endAt) &&
          r.maxInstallments <= m.maxInstallments,
        'card_method_terms',
        'A replacement card cannot widen the amount, frequency, election, cutoff or count.',
        409,
      );
      assert(
        !(
          await c.query(
            'SELECT 1 FROM g28.card_periods WHERE mandate_id=$1 AND reservation_active LIMIT 1',
            [mandate.id],
          )
        ).rowCount,
        'card_prior_period_unresolved',
        'Resolve the open installment before changing the saved card.',
        409,
      );
      const version = mandate.version + 1,
        next = { ...m, customerId: e.customer_id, paymentMethodId: e.payment_method_id };
      await c.query(
        'UPDATE g28.card_mandates SET document=$2,version=$3,updated_at=now() WHERE id=$1',
        [mandate.id, next, version],
      );
      await c.query(
        'INSERT INTO g28.card_mandate_revisions(mandate_id,version,document,created_by) VALUES($1,$2,$3,$4)',
        [mandate.id, version, next, actor],
      );
      await c.query(
        "UPDATE g28.card_due_installments SET mandate_version=$2,updated_at=now() WHERE mandate_id=$1 AND status='due'",
        [mandate.id, version],
      );
      await audit(c, actor, mandate.id, 'card_method_replaced', {
        enrollmentId: e.id,
        version,
        identityEvidenceDigest: b.identityEvidenceDigest,
      });
      return { mandateId: mandate.id, version, status: 'active' };
    }, staff);
  }

  // ---- Operational due-period processing ----------------------------------------------
  // Safe to run repeatedly and concurrently (finance lock). Never contacts the processor.
  async processDue() {
    return this.tx(async (c) => {
      const now = this.clock(),
        summary = { due: 0, missed: 0, released: 0, completed: 0 };
      const released = await c.query(
        "UPDATE g28.card_periods p SET status='blocked',reservation_active=false,version=version+1,updated_at=now() WHERE p.status='reserved' AND p.reservation_active AND p.expires_at<$1 AND NOT EXISTS(SELECT 1 FROM g28.card_commands k WHERE k.period_id=p.id) RETURNING id,mandate_id,installment",
        [new Date(now)],
      );
      for (const p of released.rows) {
        await c.query(
          "UPDATE g28.card_due_installments SET status='missed',updated_at=now() WHERE mandate_id=$1 AND installment=$2",
          [p.mandate_id, p.installment],
        );
        await audit(c, 'due-worker', p.id, 'card_reservation_expired', {});
      }
      summary.released = released.rowCount;
      const mandates = (
        await c.query("SELECT * FROM g28.card_mandates WHERE status='active' AND environment='test'")
      ).rows;
      for (const mandate of mandates) {
        const m = mandate.document;
        const periods = new Map(
          (
            await c.query(
              'SELECT installment,status,reservation_active FROM g28.card_periods WHERE mandate_id=$1',
              [mandate.id],
            )
          ).rows.map((p) => [p.installment, p]),
        );
        const existing = new Map(
          (
            await c.query(
              'SELECT installment,status FROM g28.card_due_installments WHERE mandate_id=$1',
              [mandate.id],
            )
          ).rows.map((d) => [d.installment, d.status]),
        );
        let settled = 0;
        for (let i = 0; i < m.maxInstallments; i++) {
          const w = installmentWindow(m, i),
            period = periods.get(i),
            before = existing.get(i);
          if (!period && w.at > now) break;
          let status = period ? 'reserved' : now <= w.end ? 'due' : 'missed';
          // A missed or closed installment is never reopened (no catch-up).
          if (!period && ['missed', 'closed'].includes(before)) status = before;
          if (status !== before) {
            await c.query(
              'INSERT INTO g28.card_due_installments(mandate_id,installment,mandate_version,due_at,window_ends_at,status) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(mandate_id,installment) DO UPDATE SET status=EXCLUDED.status,mandate_version=EXCLUDED.mandate_version,updated_at=now()',
              [mandate.id, i, mandate.version, new Date(w.at), new Date(w.end), status],
            );
            if (status === 'missed') {
              summary.missed++;
              await audit(c, 'due-worker', mandate.id, 'card_installment_missed', { installment: i });
            }
          }
          if (status === 'due') summary.due++;
          if (
            status === 'missed' ||
            status === 'closed' ||
            (period &&
              !period.reservation_active &&
              ['posted', 'voided', 'blocked'].includes(period.status))
          )
            settled++;
        }
        const finished =
          (settled === m.maxInstallments || now > Date.parse(m.endAt)) &&
          ![...periods.values()].some((p) => p.reservation_active);
        if (finished) {
          const version = mandate.version + 1;
          await c.query(
            "UPDATE g28.card_mandates SET status='complete',version=$2,updated_at=now() WHERE id=$1",
            [mandate.id, version],
          );
          await c.query(
            'INSERT INTO g28.card_mandate_revisions(mandate_id,version,document,created_by) VALUES($1,$2,$3,$4)',
            [
              mandate.id,
              version,
              { ...m, completion: { at: new Date(now).toISOString(), reason: 'schedule finished' } },
              'due-worker',
            ],
          );
          await c.query(
            "UPDATE g28.card_due_installments SET status='closed',updated_at=now() WHERE mandate_id=$1 AND status='due'",
            [mandate.id],
          );
          await audit(c, 'due-worker', mandate.id, 'card_mandate_completed', { version });
          summary.completed++;
        }
      }
      return summary;
    });
  }
  async dueQueue(staff) {
    assert(staff, 'authentication_required', 'Verified treasury staff access is required.', 401);
    return this.tx(async (c) => {
      const items = (
        await c.query(
          "SELECT mandate_id,installment,mandate_version,due_at,window_ends_at FROM g28.card_due_installments WHERE status='due' ORDER BY due_at,mandate_id,installment LIMIT 200",
        )
      ).rows;
      return { items };
    }, staff);
  }
}

// Runs the due-installment processing on an interval until aborted. Errors are logged
// without financial detail and never trigger processor calls.
export async function runDueLoop({ service, signal, intervalMs = 15 * 60 * 1000, logger = console.log }) {
  while (!signal.aborted) {
    try {
      const s = await service.processDue();
      logger(JSON.stringify({ event: 'card_due_processed', ...s }));
    } catch {
      logger(JSON.stringify({ event: 'card_due_processing_failed' }));
    }
    await new Promise((resolve) => {
      const t = setTimeout(resolve, intervalMs);
      signal.addEventListener('abort', () => {
        clearTimeout(t);
        resolve();
      }, { once: true });
    });
  }
}
