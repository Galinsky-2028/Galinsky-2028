import { financePage, financeCollections } from './treasury-pages.mjs';
import { emailKey, sealDelivery } from '../../../packages/core/auth.mjs';
import { randomUUID, createHash } from 'node:crypto';
import { assert, exactKeys } from '../../../packages/core/validation.mjs';
import { canonical } from '../../../packages/core/protected-crypto.mjs';
import {
  treasuryPolicy,
  treasuryDonor,
  treasuryEntry,
  projectTreasury,
  settlementDocument,
  financeCase,
  advanceFinanceCase,
  financeId,
} from '../../../packages/core/treasury-workflow.mjs';
import {
  sealFinanceIdentity,
  openFinanceIdentity,
  sealFinanceEvidence,
  openFinanceEvidence,
} from '../../../packages/core/treasury-private.mjs';
import { csvCell } from '../../../packages/core/treasury-export.mjs';
import { requestStripeTestRefund } from '../../../packages/core/stripe-treasury-actions.mjs';
const sha = (value) =>
  createHash('sha256')
    .update(typeof value === 'string' ? value : canonical(value))
    .digest('hex');
async function audit(c, actor, id, action, value) {
  await c.query(
    'INSERT INTO g28.treasury_workflow_audit(id,actor_id,object_id,action,digest) VALUES($1,$2,$3,$4,$5)',
    [randomUUID(), actor, id, action, sha(value)],
  );
}
async function evidence(c, digest) {
  assert(
    (
      await c.query(
        'SELECT 1 FROM g28.treasury_evidence WHERE digest=$1 UNION ALL SELECT 1 FROM g28.financial_provider_events WHERE event_digest=$1 UNION ALL SELECT 1 FROM g28.stripe_remedy_events WHERE event_sha256=$1 LIMIT 1',
        [digest],
      )
    ).rowCount,
    'finance_evidence_required',
    'Upload the actual private documentary evidence or choose an authenticated provider source digest.',
    409,
  );
}
async function policy(c, now) {
  const p = (
    await c.query('SELECT document FROM g28.treasury_policies ORDER BY version DESC LIMIT 1')
  ).rows[0]?.document;
  assert(
    p,
    'finance_policy_required',
    'Configure the treasurer-approved source, deadline, election and export rules first.',
    409,
  );
  return treasuryPolicy(p, now);
}
async function donor(c, id, version, key) {
  const row = (
    await c.query(
      'SELECT encrypted_envelope FROM g28.treasury_donor_revisions WHERE donor_id=$1 AND version=$2',
      [id, version],
    )
  ).rows[0];
  assert(
    row,
    'finance_donor_not_found',
    'That exact verified contributor revision is not available.',
    404,
  );
  return openFinanceIdentity(id, version, row.encrypted_envelope, key);
}
export const postgresTreasuryWorkflow = {
  async saveFinanceEvidence(input, actor, key) {
    return this.financeTransaction(async (c) => {
      const b = exactKeys(input, ['id', 'filename', 'mediaType', 'content']);
      financeId(b.id);
      assert(
        typeof b.filename === 'string' &&
          b.filename.length >= 1 &&
          b.filename.length <= 120 &&
          !/[\x00-\x1f/\\]/.test(b.filename) &&
          ['application/pdf', 'text/plain', 'text/csv'].includes(b.mediaType) &&
          typeof b.content === 'string' &&
          b.content.length <= 200000 &&
          /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(b.content),
        'finance_evidence_upload',
        'Use a PDF/text/CSV documentary source of at most 150 KB.',
      );
      const bytes = Buffer.from(b.content, 'base64');
      assert(
        bytes.length > 0 &&
          bytes.length <= 150000 &&
          (b.mediaType !== 'application/pdf' || bytes.subarray(0, 5).toString() === '%PDF-'),
        'finance_evidence_upload',
        'The documentary file type or size is invalid.',
      );
      const digest = createHash('sha256').update(bytes).digest('hex'),
        envelope = sealFinanceEvidence(b.id, b, key);
      await c.query(
        'INSERT INTO g28.treasury_evidence(id,digest,byte_count,encrypted_envelope,created_by) VALUES($1,$2,$3,$4,$5)',
        [b.id, digest, bytes.length, envelope, actor],
      );
      await audit(c, actor, b.id, 'documentary_evidence_stored', { digest, bytes: bytes.length });
      return { id: b.id, digest, byteCount: bytes.length };
    });
  },
  async readFinanceEvidence(id, actor, key) {
    return this.financeTransaction(async (c) => {
      const row = (
        await c.query('SELECT encrypted_envelope,digest FROM g28.treasury_evidence WHERE id=$1', [
          financeId(id),
        ])
      ).rows[0];
      assert(row, 'finance_evidence_not_found', 'Documentary source not found.', 404);
      const value = openFinanceEvidence(id, row.encrypted_envelope, key);
      await audit(c, actor, id, 'documentary_evidence_downloaded', { digest: row.digest });
      return { bytes: Buffer.from(value.content, 'base64'), digest: row.digest };
    });
  },
  async financeTransaction(fn) {
    const c = await this.pool.connect();
    try {
      await c.query('BEGIN');
      await c.query("SELECT pg_advisory_xact_lock(hashtext('g28-finance-journal'))");
      const result = await fn(c);
      await c.query('COMMIT');
      return result;
    } catch (e) {
      await c.query('ROLLBACK');
      throw e;
    } finally {
      c.release();
    }
  },
  async saveFinancePolicy(input, actor, now) {
    return this.financeTransaction(async (c) => {
      const p = treasuryPolicy(input, now);
      await evidence(c, p.evidenceDigest);
      await evidence(c, p.exportSystem.evidenceDigest);
      const previous = (
        await c.query(
          'SELECT version,document FROM g28.treasury_policies ORDER BY version DESC LIMIT 1',
        )
      ).rows[0];
      for (const source of p.sources) {
        const old = previous?.document.sources.find((x) => x.id === source.id);
        assert(
          !old || (old.channel === source.channel && old.environment === source.environment),
          'finance_source_identity',
          'A source identifier cannot change channel or test/live identity. Use a distinct approved source.',
          409,
        );
      }
      assert(
        !previous || p.version === previous.version + 1,
        'finance_policy_version',
        'Use the next immutable policy version.',
        409,
      );
      await c.query(
        'INSERT INTO g28.treasury_policies(id,version,document,created_by) VALUES($1,$2,$3,$4)',
        [p.id, p.version, p, actor],
      );
      await audit(c, actor, p.id, 'policy_approved', p);
      return { policy: p };
    });
  },
  async saveFinanceDonor(input, expected, actor, key) {
    return this.financeTransaction(async (c) => {
      const d = treasuryDonor(input);
      await evidence(c, d.evidenceDigest);
      const old = (await c.query('SELECT version FROM g28.treasury_donors WHERE id=$1', [d.id]))
        .rows[0];
      assert(
        (old?.version ?? 0) === expected,
        'stale_finance_identity',
        'Reload the exact contributor revision. Never merge people by name or email.',
        409,
      );
      const version = expected + 1,
        envelope = sealFinanceIdentity(d.id, version, d, key);
      await c.query(
        'INSERT INTO g28.treasury_donors(id,encrypted_envelope,evidence_digest,version) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET encrypted_envelope=EXCLUDED.encrypted_envelope,evidence_digest=EXCLUDED.evidence_digest,version=EXCLUDED.version,updated_at=now()',
        [d.id, envelope, d.evidenceDigest, version],
      );
      await c.query(
        'INSERT INTO g28.treasury_donor_revisions(donor_id,version,encrypted_envelope,evidence_digest,created_by) VALUES($1,$2,$3,$4,$5)',
        [d.id, version, envelope, d.evidenceDigest, actor],
      );
      await audit(c, actor, d.id, 'donor_revision', envelope);
      return { id: d.id, version, informationComplete: Boolean(d.occupation && d.employer) };
    });
  },
  async financeDonor(id, version, actor, key) {
    return this.financeTransaction(async (c) => {
      const value = await donor(c, id, version, key);
      await audit(c, actor, id, 'donor_identity_read', { id, version });
      return { donor: value, version };
    });
  },
  async postFinanceEntry(input, actor, key, now) {
    return this.financeTransaction(async (c) => {
      const p = await policy(c, now),
        event = treasuryEntry(input, p, now),
        previous = (
          await c.query('SELECT state FROM g28.treasury_gifts WHERE id=$1', [event.giftId])
        ).rows[0]?.state;
      const existing = (
        await c.query(
          'SELECT digest FROM g28.treasury_journal WHERE source=$1 AND external_reference=$2 AND environment=$3',
          [event.source, event.externalReference, event.environment],
        )
      ).rows[0];
      if (event.kind === 'gift' || event.kind === 'reattribution') {
        const d = (
          await c.query('SELECT version FROM g28.treasury_donors WHERE id=$1', [event.donorId])
        ).rows[0];
        assert(
          d,
          'finance_donor_not_found',
          'Record the source-verified contributor identity first.',
          409,
        );
        event.donorVersion = d.version;
      }
      // A replay remains bound to the donor revision and policy recorded originally.
      if (existing) {
        const old = (
          await c.query(
            'SELECT document FROM g28.treasury_journal WHERE source=$1 AND external_reference=$2 AND environment=$3',
            [event.source, event.externalReference, event.environment],
          )
        ).rows[0].document;
        event.policyId = old.policyId;
        for (const field of [
          'donorVersion',
          'effectiveDonorId',
          'priorDonorReference',
          'providerPaymentId',
        ])
          if (old[field] !== undefined) event[field] = old[field];
        assert(
          existing.digest === sha(event),
          'finance_reference_conflict',
          'The source reference already has different immutable content.',
          409,
        );
        return { duplicate: true, gift: previous };
      }
      if (event.channel === 'card' && ['gift', 'refund', 'dispute'].includes(event.kind)) {
        const receipt = (
          await c.query(
            'SELECT payment_id,event_digest,event_kind,amount_cents,occurred_at FROM g28.financial_provider_events WHERE provider=$1 AND event_id=$2',
            [event.source, event.externalReference],
          )
        ).rows[0];
        assert(
          receipt &&
            receipt.event_digest === event.evidenceDigest &&
            Number(receipt.amount_cents) === event.amountCents &&
            new Date(receipt.occurred_at).toISOString() === event.receivedAt &&
            (event.kind === 'gift'
              ? receipt.event_kind === 'captured'
              : event.kind === 'dispute'
                ? receipt.event_kind === 'disputed'
                : ['refunded', 'partially_refunded'].includes(receipt.event_kind)),
          'finance_signed_source',
          'Card effects must match the exact authenticated provider event, amount, date and digest.',
          409,
        );
        if (previous)
          assert(
            previous.providerPaymentId === receipt.payment_id,
            'finance_source_mismatch',
            'This event belongs to another provider payment.',
            409,
          );
        event.providerPaymentId = receipt.payment_id;
      }
      if (event.channel === 'card' && event.kind === 'dispute_closed') {
        const receipt = (
          await c.query(
            'SELECT session_id,kind,amount_cents,event_sha256,occurred_at,livemode FROM g28.stripe_remedy_events WHERE event_id=$1',
            [event.externalReference],
          )
        ).rows[0];
        assert(
          receipt &&
            receipt.kind === (event.outcome === 'won' ? 'dispute_won' : 'chargeback') &&
            receipt.livemode === (event.environment === 'live') &&
            Number(receipt.amount_cents) === event.amountCents &&
            receipt.event_sha256 === event.evidenceDigest &&
            receipt.session_id === previous?.providerPaymentId &&
            new Date(receipt.occurred_at).toISOString() === event.receivedAt,
          'finance_signed_source',
          'Dispute closure must match the authenticated final processor outcome.',
          409,
        );
        event.providerPaymentId = receipt.session_id;
      }
      await evidence(c, event.evidenceDigest);
      if (event.intentDigest) await evidence(c, event.intentDigest);
      const state = projectTreasury(previous, event);
      if (event.kind === 'gift') state.providerPaymentId = event.providerPaymentId || null;
      if (event.kind === 'gift' || event.kind === 'reattribution')
        state.donorVersion = event.donorVersion;
      event.effectiveDonorId = state.donorId;
      event.donorVersion = state.donorVersion;
      if (event.kind === 'reattribution')
        event.priorDonorReference = previous.donorId + ':' + previous.donorVersion;
      const identity = await donor(c, state.donorId, state.donorVersion, key);
      await c.query(
        'INSERT INTO g28.treasury_journal(id,gift_id,source,external_reference,environment,event_kind,document,digest,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [
          event.id,
          event.giftId,
          event.source,
          event.externalReference,
          event.environment,
          event.kind,
          event,
          sha(event),
          actor,
        ],
      );
      await c.query(
        'INSERT INTO g28.treasury_gifts(id,donor_id,source,environment,state) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET donor_id=EXCLUDED.donor_id,state=EXCLUDED.state,updated_at=now()',
        [state.id, state.donorId, state.source, state.environment, state],
      );
      // A captured manual-card period keeps its all-channel reservation until
      // this exact signed source has been journaled under the same lock. Do
      // not release merely because a provider HTTP response said succeeded.
      if (event.channel === 'card' && event.kind === 'gift') {
        const period = (await c.query('SELECT * FROM g28.card_periods WHERE provider_payment_id=$1', [event.providerPaymentId])).rows[0];
        if (period) {
          assert(period.donor_id === state.donorId && period.donor_version === state.donorVersion && period.environment === state.environment && Number(period.amount_cents) === event.amountCents && Number(state.allocations[period.election]) === event.amountCents && !period.gift_id, 'card_journal_binding', 'The signed capture must match the original contributor revision, exact amount and election reservation.', 409);
          await c.query("UPDATE g28.card_periods SET status='posted',reservation_active=false,capture_event_id=$2,gift_id=$3,version=version+1,updated_at=now() WHERE id=$1", [period.id,event.externalReference,state.id]);
        }
      }
      const aggregates = (
        await c.query(
          "SELECT COALESCE(sum((state->'allocations'->>'primary')::bigint),0)::text AS primary,COALESCE(sum((state->'allocations'->>'general')::bigint),0)::text AS general FROM g28.treasury_gifts WHERE donor_id=$1 AND environment=$2",
          [state.donorId, state.environment],
        )
      ).rows[0];
      const issues = [];
      if (!identity.occupation || !identity.employer) issues.push('missing_information');
      if (['primary', 'general'].some((e) => BigInt(aggregates[e]) > BigInt(p.electionLimits[e])))
        issues.push('excess');
      if (state.disputedCents) issues.push('dispute');
      for (const kind of issues) {
        const open = await c.query(
          "SELECT 1 FROM g28.treasury_cases WHERE gift_id=$1 AND document->>'kind'=$2 AND document->>'status'<>'closed' LIMIT 1",
          [state.id, kind],
        );
        if (!open.rowCount) {
          const item = financeCase(
            { id: randomUUID(), giftId: state.id, kind, evidenceDigest: event.evidenceDigest },
            p,
            now,
            state,
          );
          await c.query(
            'INSERT INTO g28.treasury_cases(id,gift_id,document,version) VALUES($1,$2,$3,1)',
            [item.id, item.giftId, item],
          );
          await audit(c, actor, item.id, 'exception_created', item);
        }
      }
      await audit(c, actor, event.id, 'journal_posted', event);
      return {
        duplicate: false,
        gift: state,
        aggregates,
        issues,
        notice:
          'Recorded source evidence and accounting projection; no payment, refund, legal determination or bank settlement was initiated.',
      };
    });
  },
  async saveFinanceSettlement(input, actor, now) {
    return this.financeTransaction(async (c) => {
      await policy(c, now);
      await evidence(c, input?.evidenceDigest);
      const ids = input?.entryIds;
      assert(
        Array.isArray(ids) && ids.length <= 1000,
        'finance_settlement',
        'Choose bounded exact journal entries.',
      );
      const events = (
          await c.query('SELECT document FROM g28.treasury_journal WHERE id=ANY($1::uuid[])', [
            ids.map(financeId),
          ])
        ).rows.map((r) => r.document),
        document = settlementDocument(input, events);
      const disputed = await c.query(
        "SELECT 1 FROM g28.treasury_gifts WHERE id=ANY($1::uuid[]) AND (state->>'disputedCents')::bigint>0 LIMIT 1",
        [events.map((e) => e.giftId)],
      );
      assert(
        !disputed.rowCount,
        'finance_open_dispute',
        'Resolve source disputes before marking a payout reconciled.',
        409,
      );
      const used = await c.query(
        'SELECT 1 FROM g28.treasury_settlement_entries WHERE entry_id=ANY($1::uuid[]) LIMIT 1',
        [ids],
      );
      assert(
        !used.rowCount,
        'finance_settlement_duplicate',
        'A source effect is already assigned to a settlement.',
        409,
      );
      await c.query(
        'INSERT INTO g28.treasury_settlements(id,source,environment,external_reference,document) VALUES($1,$2,$3,$4,$5)',
        [document.id, document.source, document.environment, document.externalReference, document],
      );
      for (const id of ids)
        await c.query(
          'INSERT INTO g28.treasury_settlement_entries(entry_id,settlement_id) VALUES($1,$2)',
          [id, document.id],
        );
      await audit(c, actor, document.id, 'settlement_recorded', document);
      return { settlement: document, bankConfirmed: false };
    });
  },
  async saveFinanceDeposit(input, actor, now) {
    return this.financeTransaction(async (c) => {
      await policy(c, now);
      const b = exactKeys(input, [
        'id',
        'settlementId',
        'bankReference',
        'amountCents',
        'receivedAt',
        'evidenceDigest',
      ]);
      financeId(b.id);
      financeId(b.settlementId);
      assert(
        typeof b.bankReference === 'string' &&
          /^[a-zA-Z0-9_-]{1,128}$/.test(b.bankReference) &&
          Number.isSafeInteger(b.amountCents) &&
          b.amountCents !== 0 &&
          Math.abs(b.amountCents) <= 100000000 &&
          /^[a-f0-9]{64}$/.test(b.evidenceDigest) &&
          Number.isFinite(Date.parse(b.receivedAt)) &&
          new Date(b.receivedAt).toISOString() === b.receivedAt &&
          Date.parse(b.receivedAt) <= now + 60000,
        'finance_deposit',
        'Record the exact documented bank transaction, date and evidence digest.',
      );
      await evidence(c, b.evidenceDigest);
      const settlement = (
        await c.query('SELECT document FROM g28.treasury_settlements WHERE id=$1', [b.settlementId])
      ).rows[0]?.document;
      assert(
        settlement,
        'finance_settlement_not_found',
        'Record the provider/manual-source settlement first.',
        404,
      );
      await c.query(
        'INSERT INTO g28.treasury_deposits(id,settlement_id,bank_reference,document) VALUES($1,$2,$3,$4)',
        [b.id, b.settlementId, b.bankReference, b],
      );
      const deposits = (
        await c.query(
          "SELECT COALESCE(sum((document->>'amountCents')::bigint),0)::text AS cents FROM g28.treasury_deposits WHERE settlement_id=$1",
          [b.settlementId],
        )
      ).rows[0].cents;
      const balanced =
        settlement.balanced && BigInt(deposits) === BigInt(settlement.computed.netCents);
      await audit(c, actor, b.id, 'bank_deposit_recorded', b);
      return {
        deposit: b,
        depositedCents: deposits,
        expectedNetCents: settlement.computed.netCents,
        balanced,
        notice: balanced
          ? 'Documentary provider/bank amounts reconcile. This is not automatic legal acceptance.'
          : 'Mismatch remains open for treasurer reconciliation; the bank observation was preserved.',
      };
    });
  },
  async saveFinanceCase(input, actor, now) {
    return this.financeTransaction(async (c) => {
      const p = await policy(c, now),
        gift = (
          await c.query('SELECT state FROM g28.treasury_gifts WHERE id=$1', [
            financeId(input?.giftId),
          ])
        ).rows[0]?.state;
      assert(gift, 'finance_gift_not_found', 'Choose an existing gift.', 404);
      const item = financeCase(input, p, now, gift);
      await evidence(c, item.evidenceDigest);
      await c.query(
        'INSERT INTO g28.treasury_cases(id,gift_id,document,version) VALUES($1,$2,$3,1)',
        [item.id, item.giftId, item],
      );
      await audit(c, actor, item.id, 'exception_created', item);
      return { case: item };
    });
  },
  async advanceFinanceCase(id, input, actor, now, mailConfig) {
    return this.financeTransaction(async (c) => {
      const old = (
        await c.query('SELECT document FROM g28.treasury_cases WHERE id=$1', [financeId(id)])
      ).rows[0]?.document;
      assert(old, 'finance_case_not_found', 'Finance case not found.', 404);
      await evidence(c, input?.evidenceDigest);
      if (input?.action === 'close')
        assert(
          !(
            await c.query(
              "SELECT 1 FROM g28.treasury_commands WHERE case_id=$1 AND status IN ('processing','accepted','uncertain') LIMIT 1",
              [id],
            )
          ).rowCount,
          'finance_command_pending',
          'Reconcile the pending provider operation before closing this case.',
          409,
        );
      const item = advanceFinanceCase(old, input, now);
      if (input.action === 'notify') {
        assert(
          mailConfig?.mailReady && mailConfig.deliveryKey && mailConfig.pepper,
          'finance_notice_unavailable',
          'Transactional donor delivery is not configured. No notice was queued.',
          503,
        );
        const recipient = (
            await c.query(
              'SELECT g.donor_id,d.version FROM g28.treasury_gifts g JOIN g28.treasury_donors d ON d.id=g.donor_id WHERE g.id=$1',
              [old.giftId],
            )
          ).rows[0],
          identity = await donor(c, recipient.donor_id, recipient.version, mailConfig.treasuryKey);
        assert(
          identity.email,
          'finance_contact_required',
          'Record the source-verified contributor contact before requesting a notice.',
          409,
        );
        const subject = emailKey(identity.email, mailConfig.pepper);
        const recent = (
          await c.query(
            "SELECT count(*)::int AS n FROM g28.outbox WHERE kind='finance_attention' AND subject_key=$1 AND created_at>$2",
            [subject, new Date(now - 86400000)],
          )
        ).rows[0].n;
        assert(
          recent < 2,
          'finance_notice_bound',
          'Wait before another transactional notice to this contributor.',
          429,
        );
        const job = randomUUID();
        await c.query(
          "INSERT INTO g28.outbox(id,kind,subject_key,payload_envelope) VALUES($1,'finance_attention',$2,$3)",
          [
            job,
            subject,
            sealDelivery(
              {
                email: identity.email,
                expires: Math.min(now + 86400000, Date.parse(item.deadline)),
              },
              mailConfig.deliveryKey,
            ),
          ],
        );
        await c.query(
          'INSERT INTO g28.treasury_case_notices(case_id,case_version,donor_id,donor_version,job_id) VALUES($1,$2,$3,$4,$5)',
          [id, item.version, recipient.donor_id, recipient.version, job],
        );
      }
      await c.query(
        'UPDATE g28.treasury_cases SET document=$2,version=$3,updated_at=now() WHERE id=$1',
        [id, item, item.version],
      );
      await audit(c, actor, id, 'exception_' + input.action, item);
      return {
        case: item,
        notice:
          input.action === 'notify'
            ? 'Generic transactional notice queued with a durable delivery receipt; queue acceptance is not delivery or legal sufficiency.'
            : 'Documented case status/follow-up only; no contact, refund or legal certification was generated.',
      };
    });
  },
  async financePage(kind, after) {
    return this.financeTransaction((c) => financePage(c, kind, after));
  },
  async financeOverview() {
    return this.financeTransaction(async (c) => {
      const policyRow = (
        await c.query('SELECT document FROM g28.treasury_policies ORDER BY version DESC LIMIT 1')
      ).rows[0];
      const pages = await Promise.all(financeCollections.map((kind) => financePage(c, kind)));
      const collections = Object.fromEntries(
        financeCollections.map((kind, i) => [kind, pages[i].items]),
      );
      return {
        policy: policyRow?.document || null,
        ...collections,
        pages: Object.fromEntries(financeCollections.map((kind, i) => [kind, pages[i].next])),
        limit: 100,
        notice:
          'Each initial collection has at most 100 rows; load additional pages explicitly. All source effects not yet imported remain unmatched. Test/live data stay separate; captured gifts are not settled bank deposits.',
      };
    });
  },
  async executeFinanceRefund(input, actor, secretKey, now, transport = fetch) {
    const b = exactKeys(input, [
      'id',
      'caseId',
      'caseVersion',
      'amountCents',
      'evidenceDigest',
      'confirm',
    ]);
    financeId(b.id);
    financeId(b.caseId);
    assert(
      b.confirm === 'request this Stripe TEST refund' &&
        Number.isSafeInteger(b.amountCents) &&
        b.amountCents > 0 &&
        /^[a-f0-9]{64}$/.test(b.evidenceDigest),
      'finance_action_confirmation',
      'Confirm the exact approved Stripe TEST refund and documentary evidence.',
    );
    assert(
      typeof secretKey === 'string' && /^sk_test_[A-Za-z0-9_]{12,}$/.test(secretKey),
      'sandbox_action_only',
      'Live financial actions are not installed.',
      403,
    );
    const prepared = await this.financeTransaction(async (c) => {
      await policy(c, now);
      await evidence(c, b.evidenceDigest);
      const existing = (
        await c.query(
          'SELECT document,status,provider_reference FROM g28.treasury_commands WHERE id=$1',
          [b.id],
        )
      ).rows[0];
      if (existing) {
        assert(
          canonical(existing.document.request) === canonical(b),
          'finance_command_conflict',
          'The command reference was reused with different instructions.',
          409,
        );
        assert(
          ['accepted', 'reconciled', 'failed'].includes(existing.status),
          'finance_command_uncertain',
          'This command was already attempted. Reconcile the provider outcome before another action.',
          409,
        );
        return {
          duplicate: true,
          status: existing.status,
          providerReference: existing.provider_reference,
        };
      }
      const item = (
        await c.query('SELECT document FROM g28.treasury_cases WHERE id=$1', [b.caseId])
      ).rows[0]?.document;
      assert(
        item &&
          item.version === b.caseVersion &&
          item.kind === 'refund' &&
          item.status !== 'closed',
        'finance_case_approval',
        'Use a current open refund case and approved amount.',
        409,
      );
      const gift = (
        await c.query('SELECT state FROM g28.treasury_gifts WHERE id=$1', [item.giftId])
      ).rows[0]?.state;
      assert(
        gift &&
          gift.source === 'stripe-test' &&
          gift.environment === 'test' &&
          !gift.disputedCents &&
          b.amountCents <= gift.grossCents - gift.refundedCents - gift.chargebackCents,
        'sandbox_refund_amount',
        'Only available undisputed test funds may be requested.',
        409,
      );
      const pending = await c.query(
        "SELECT 1 FROM g28.treasury_commands WHERE document->>'giftId'=$1 AND status IN ('processing','accepted','uncertain') LIMIT 1",
        [gift.id],
      );
      assert(
        !pending.rowCount,
        'finance_command_uncertain',
        'Reconcile the existing provider command for this gift before another request.',
        409,
      );
      const source = (
        await c.query(
          'SELECT client_reference,amount_cents,livemode FROM g28.stripe_checkout_intents WHERE session_id=$1',
          [gift.providerPaymentId],
        )
      ).rows[0];
      assert(
        source && !source.livemode && Number(source.amount_cents) === gift.grossCents,
        'sandbox_payment_mismatch',
        'The original recorded test checkout is required.',
        409,
      );
      const doc = {
        request: b,
        giftId: gift.id,
        sessionId: gift.providerPaymentId,
        clientReference: source.client_reference,
        originalAmountCents: gift.grossCents,
      };
      await c.query(
        "INSERT INTO g28.treasury_commands(id,case_id,document,status) VALUES($1,$2,$3,'processing')",
        [b.id, b.caseId, doc],
      );
      await audit(c, actor, b.id, 'sandbox_refund_attempt_committed', doc);
      return doc;
    });
    if (prepared.duplicate) return prepared;
    let result;
    try {
      result = await requestStripeTestRefund({
        secretKey,
        sessionId: prepared.sessionId,
        clientReference: prepared.clientReference,
        originalAmountCents: prepared.originalAmountCents,
        amountCents: b.amountCents,
        commandId: b.id,
        transport,
      });
    } catch {
      const current = await this.financeTransaction(async (c) => {
        await c.query(
          "UPDATE g28.treasury_commands SET status='uncertain',updated_at=now() WHERE id=$1 AND status='processing'",
          [b.id],
        );
        const row = (
          await c.query('SELECT status,provider_reference FROM g28.treasury_commands WHERE id=$1', [
            b.id,
          ])
        ).rows[0];
        await audit(
          c,
          actor,
          b.id,
          ['reconciled', 'failed'].includes(row.status)
            ? 'sandbox_refund_terminal_receipt'
            : 'sandbox_refund_uncertain',
          { id: b.id, status: row.status },
        );
        return row;
      });
      if (['reconciled', 'failed'].includes(current.status))
        return {
          commandId: b.id,
          commandStatus: current.status,
          providerReference: current.provider_reference,
          ledgerReconciled: current.status === 'reconciled',
          notice:
            'The signed provider outcome was reconciled while the initial response was unavailable. No retry was initiated.',
        };
      assert(
        false,
        'finance_command_uncertain',
        'The test provider outcome is uncertain. Do not retry; reconcile signed provider records first.',
        409,
      );
    }
    const final = await this.financeTransaction(async (c) => {
      await c.query(
        "UPDATE g28.treasury_commands SET status='accepted',provider_reference=$2,updated_at=now() WHERE id=$1 AND status='processing'",
        [b.id, result.providerReference],
      );
      const row = (
        await c.query('SELECT status,provider_reference FROM g28.treasury_commands WHERE id=$1', [
          b.id,
        ])
      ).rows[0];
      assert(
        row.provider_reference === result.providerReference,
        'finance_command_conflict',
        'Conflicting provider identities require manual review.',
        409,
      );
      await audit(c, actor, b.id, 'sandbox_refund_provider_response', result);
      return row;
    });
    return {
      ...result,
      commandId: b.id,
      commandStatus: final.status,
      ledgerReconciled: final.status === 'reconciled',
    };
  },
  async reconcileFinanceCommand(id, input, actor) {
    return this.financeTransaction(async (c) => {
      const b = exactKeys(input, ['journalEntryId', 'providerEventId']);
      const command = (
        await c.query(
          'SELECT document,status,provider_reference FROM g28.treasury_commands WHERE id=$1',
          [financeId(id)],
        )
      ).rows[0];
      assert(
        command &&
          ['processing', 'accepted', 'uncertain', 'reconciled', 'failed'].includes(command.status),
        'finance_command_not_found',
        'Choose an attempted provider command.',
        404,
      );
      if (b.providerEventId) {
        assert(
          b.journalEntryId === undefined || b.journalEntryId === null,
          'finance_command_proof',
          'Choose one exact terminal provider proof.',
        );
        assert(
          typeof b.providerEventId === 'string' &&
            /^evt_[A-Za-z0-9]{5,100}$/.test(b.providerEventId),
          'finance_command_proof',
          'Use the signed provider event reference.',
        );
        const failed = (
          await c.query(
            "SELECT provider_reference,session_id,amount_cents FROM g28.stripe_remedy_events WHERE event_id=$1 AND command_id=$2 AND kind='refund_failed' AND livemode=false",
            [b.providerEventId, id],
          )
        ).rows[0];
        assert(
          failed &&
            failed.session_id === command.document.sessionId &&
            Number(failed.amount_cents) === command.document.request.amountCents &&
            (!command.provider_reference ||
              failed.provider_reference === command.provider_reference),
          'finance_command_proof',
          'The signed failure does not bind this exact command/payment/amount.',
          409,
        );
        assert(
          !(
            await c.query(
              "SELECT 1 FROM g28.financial_provider_events WHERE provider='stripe-test' AND event_id=$1",
              [failed.provider_reference],
            )
          ).rowCount,
          'finance_command_conflict',
          'Conflicting success and failure evidence requires manual review.',
          409,
        );
        await c.query(
          "UPDATE g28.treasury_commands SET status='failed',provider_reference=$2,updated_at=now() WHERE id=$1",
          [id, failed.provider_reference],
        );
        await audit(c, actor, id, 'sandbox_refund_verified_failure', b);
        return { reconciled: true, outcome: 'provider_confirmed_failure', financialEffect: false };
      }
      assert(
        command.status !== 'failed',
        'finance_command_conflict',
        'A confirmed failure cannot be silently replaced with a success. Review conflicting provider evidence first.',
        409,
      );
      financeId(b.journalEntryId);
      const entry = (
        await c.query('SELECT document FROM g28.treasury_journal WHERE id=$1', [b.journalEntryId])
      ).rows[0]?.document;
      assert(
        entry &&
          entry.kind === 'refund' &&
          entry.giftId === command.document.giftId &&
          entry.environment === 'test' &&
          entry.amountCents === command.document.request.amountCents &&
          (!command.provider_reference || entry.externalReference === command.provider_reference),
        'finance_command_mismatch',
        'The exact signed refund effect must already be posted to this gift.',
        409,
      );
      const proof = (
        await c.query(
          "SELECT provider_reference FROM g28.stripe_remedy_events WHERE command_id=$1 AND provider_reference=$2 AND kind='refund' AND event_sha256=$3 LIMIT 1",
          [id, entry.externalReference, entry.evidenceDigest],
        )
      ).rows[0];
      assert(
        proof,
        'finance_signed_source',
        'The signed provider refund must bind this exact command reference.',
        409,
      );
      await c.query(
        "UPDATE g28.treasury_commands SET status='reconciled',provider_reference=$2,updated_at=now() WHERE id=$1",
        [id, proof.provider_reference],
      );
      await audit(c, actor, id, 'sandbox_refund_reconciled', b);
      return { reconciled: true };
    });
  },
  async exportFinance(input, actor, key, now) {
    return this.financeTransaction(async (c) => {
      const b = exactKeys(input, [
        'from',
        'until',
        'environment',
        'format',
        'includeIdentity',
        'confirm',
      ]);
      assert(
        b.confirm === 'export approved treasury report' &&
          ['test', 'live'].includes(b.environment) &&
          ['csv', 'json'].includes(b.format) &&
          typeof b.includeIdentity === 'boolean' &&
          Number.isFinite(Date.parse(b.from)) &&
          Number.isFinite(Date.parse(b.until)) &&
          Date.parse(b.until) > Date.parse(b.from) &&
          Date.parse(b.until) - Date.parse(b.from) <= 366 * 86400000,
        'finance_export',
        'Confirm an exact environment, bounded period, identity scope and format.',
      );
      const p = await policy(c, now),
        rows = (
          await c.query(
            "SELECT j.document,g.state FROM g28.treasury_journal j JOIN g28.treasury_gifts g ON g.id=j.gift_id WHERE j.environment=$1 AND (j.document->>'receivedAt')::timestamptz>=$2 AND (j.document->>'receivedAt')::timestamptz<$3 ORDER BY j.id LIMIT 10001",
            [b.environment, b.from, b.until],
          )
        ).rows;
      assert(rows.length <= 10000, 'finance_export_too_large', 'Narrow the reporting range.', 409);
      const columns = p.exportSystem.columns.filter(
          (c) =>
            b.includeIdentity ||
            ![
              'donor_name',
              'street',
              'city',
              'region',
              'postal',
              'country',
              'occupation',
              'employer',
            ].includes(c.field),
        ),
        records = [],
        totals = {
          grossCents: 0,
          refundCents: 0,
          feeCents: 0,
          chargebackCents: 0,
          netCents: 0,
          primaryAllocatedCents: 0,
          generalAllocatedCents: 0,
        };
      for (const { document: e, state: s } of rows) {
        if (b.format === 'csv')
          for (const field of e.kind === 'reattribution'
            ? ['prior_donor_reference', 'donor_intent_digest']
            : e.kind === 'redesignation'
              ? ['target_election', 'donor_intent_digest']
              : [])
            assert(
              columns.some((c) => c.field === field),
              'finance_export_mapping',
              'The approved CSV mapping must preserve donor intent and reallocation/reattribution context.',
              409,
            );
        const d = b.includeIdentity
            ? await donor(c, e.effectiveDonorId, e.donorVersion, key)
            : null,
          n = e.amountCents,
          gross =
            e.kind === 'gift'
              ? n
              : e.kind === 'correction'
                ? e.outcome === 'increase'
                  ? n
                  : -n
                : 0,
          refund = e.kind === 'refund' ? n : 0,
          fee = e.kind === 'fee' ? n : 0,
          chargeback = e.kind === 'dispute_closed' && e.outcome === 'lost' ? n : 0,
          effect = gross - refund - fee - chargeback,
          allocated = { primary: 0, general: 0 };
        allocated[e.election] = gross - refund - chargeback;
        if (e.kind === 'redesignation') {
          allocated[e.election] = -n;
          allocated[e.targetElection] = n;
        }
        records.push({
          event_id: e.id,
          event_kind: e.kind,
          gift_id: s.id,
          source: e.source,
          external_reference: e.externalReference,
          environment: e.environment,
          donor_reference: e.effectiveDonorId + ':' + e.donorVersion,
          ...(d
            ? {
                donor_name: d.name,
                street: d.street,
                city: d.city,
                region: d.region,
                postal: d.postal,
                country: d.country,
                occupation: d.occupation || '',
                employer: d.employer || '',
              }
            : {}),
          election: e.election,
          target_election: e.targetElection || '',
          prior_donor_reference: e.priorDonorReference || '',
          donor_intent_digest: e.intentDigest || '',
          amount_cents: n,
          effect_cents: effect,
          gross_cents: gross,
          refund_cents: refund,
          fee_cents: fee,
          chargeback_cents: chargeback,
          net_cents: effect,
          primary_allocated_cents: allocated.primary,
          general_allocated_cents: allocated.general,
          made_at: s.madeAt,
          received_at: s.receivedAt,
          event_received_at: e.receivedAt,
          event_source_digest: e.evidenceDigest,
          source_digest: s.evidenceDigest,
        });
        totals.grossCents += gross;
        totals.refundCents += refund;
        totals.feeCents += fee;
        totals.chargebackCents += chargeback;
        totals.netCents += effect;
        totals.primaryAllocatedCents += allocated.primary;
        totals.generalAllocatedCents += allocated.general;
      }
      assert(
        Object.values(totals).every(Number.isSafeInteger),
        'finance_export_overflow',
        'Narrow the range to retain exact integer totals.',
        409,
      );
      const reference = randomUUID(),
        document = {
          schemaVersion: 1,
          reference,
          system: p.exportSystem.id,
          policyId: p.id,
          environment: b.environment,
          range: { from: b.from, until: b.until },
          includesIdentity: b.includeIdentity,
          records,
          totals,
          notice:
            'One row per immutable source event in the received-date period. Disputes are flagged without pretending pending funds settled; gross/refund/fee/chargeback/net and allocation totals remain distinct. Treasurer-approved private accounting/import mapping only; no automatic FEC filing or legal acceptance.',
        };
      const bytes =
        b.format === 'json'
          ? JSON.stringify(document, null, 2) + '\n'
          : [
              columns.map((x) => csvCell(x.header)).join(','),
              ...records.map((r) => columns.map((x) => csvCell(r[x.field] ?? '')).join(',')),
            ].join('\r\n') + '\r\n';
      await audit(c, actor, reference, 'approved_treasury_export', {
        sha256: sha(bytes),
        rows: records.length,
        identity: b.includeIdentity,
        range: document.range,
        policyId: p.id,
        environment: b.environment,
      });
      return { bytes, digest: sha(bytes), reference };
    });
  },
};
