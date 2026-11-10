import { createHash } from 'node:crypto';
// Called only AFTER exact raw-body Stripe signature, freshness and mode checks.
// Only minimized signed metadata is stored. No provider action is initiated.
export async function recordStripeRemedy(pool, event, raw) {
  const r = event.remedy,
    refund = event.type.startsWith('refund.'),
    referencePattern = refund ? /^re_[A-Za-z0-9]{5,100}$/ : /^dp_[A-Za-z0-9]{5,100}$/;
  if (
    !r ||
    !referencePattern.test(r.reference) ||
    !event.paymentIntentId ||
    !Number.isSafeInteger(r.amountCents) ||
    r.amountCents <= 0 ||
    r.amountCents > 100000000 ||
    r.currency !== 'usd' ||
    !Number.isSafeInteger(event.created) ||
    event.created <= 0 ||
    event.created > Math.floor(Date.now() / 1000) + 60
  )
    return { status: 422, outcome: 'invalid_remedy_source' };
  if (
    refund &&
    (!['succeeded', 'pending', 'failed', 'canceled', 'requires_action'].includes(r.status) ||
      (event.type === 'refund.failed' && r.status !== 'failed'))
  )
    return { status: 422, outcome: 'invalid_remedy_status' };
  const kind = refund
    ? r.status === 'succeeded'
      ? 'refund'
      : ['failed', 'canceled'].includes(r.status)
        ? 'refund_failed'
        : 'refund_pending'
    : event.type === 'charge.dispute.created'
      ? 'dispute'
      : r.status === 'won'
        ? 'dispute_won'
        : r.status === 'lost'
          ? 'chargeback'
          : null;
  if (!kind) return { status: 422, outcome: 'unresolved_dispute_source' };
  const digest = createHash('sha256').update(raw).digest('hex'),
    c = await pool.connect();
  try {
    await c.query('BEGIN');
    const identity = (
      await c.query(
        'SELECT i.session_id,s.amount_cents,s.payment_state FROM g28.stripe_payment_identities i JOIN g28.stripe_checkout_intents s ON s.session_id=i.session_id WHERE i.payment_intent_id=$1 AND i.livemode=$2 FOR UPDATE OF s',
        [event.paymentIntentId, event.livemode],
      )
    ).rows[0];
    if (!identity || !['paid', 'requires_review'].includes(identity.payment_state)) {
      await c.query('ROLLBACK');
      return { status: 422, outcome: 'unmatched_remedy_requires_reconciliation' };
    }
    const inserted = await c.query(
      'INSERT INTO g28.stripe_webhook_receipts(event_id,event_sha256,session_id,livemode,event_type) VALUES($1,$2,$3,$4,$5) ON CONFLICT(event_id) DO NOTHING RETURNING event_id',
      [event.id, digest, identity.session_id, event.livemode, event.type],
    );
    if (!inserted.rowCount) {
      const previous = (
        await c.query('SELECT event_sha256 FROM g28.stripe_webhook_receipts WHERE event_id=$1', [
          event.id,
        ])
      ).rows[0];
      if (previous?.event_sha256 !== digest) throw Error('Conflicting signed remedy event');
      await c.query('COMMIT');
      return { status: 200, outcome: 'duplicate' };
    }
    await c.query(
      'INSERT INTO g28.stripe_remedy_events(event_id,session_id,provider_reference,command_id,kind,amount_cents,event_sha256,occurred_at,livemode) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [
        event.id,
        identity.session_id,
        r.reference,
        r.commandId,
        kind,
        r.amountCents,
        digest,
        new Date(event.created * 1000),
        event.livemode,
      ],
    );
    if (kind === 'refund' || kind === 'dispute') {
      const provider = event.livemode ? 'stripe' : 'stripe-test',
        previous = (
          await c.query(
            'SELECT payment_id,event_kind,amount_cents FROM g28.financial_provider_events WHERE provider=$1 AND event_id=$2',
            [provider, r.reference],
          )
        ).rows[0];
      if (previous) {
        if (
          previous.payment_id !== identity.session_id ||
          Number(previous.amount_cents) !== r.amountCents ||
          (kind === 'refund'
            ? !['partially_refunded', 'refunded'].includes(previous.event_kind)
            : previous.event_kind !== 'disputed')
        )
          throw Error('Conflicting remedy effect');
      } else {
        const totals = (
            await c.query(
              "SELECT COALESCE(sum(amount_cents) FILTER(WHERE event_kind='captured'),0)::text AS captured,COALESCE(sum(amount_cents) FILTER(WHERE event_kind IN ('partially_refunded','refunded')),0)::text AS refunded FROM g28.financial_provider_events WHERE provider=$1 AND payment_id=$2",
              [provider, identity.session_id],
            )
          ).rows[0],
          remaining = BigInt(totals.captured) - BigInt(totals.refunded);
        if (BigInt(r.amountCents) > remaining || remaining <= 0n)
          throw Error('Remedy exceeds captured balance');
        const financialKind =
          kind === 'dispute'
            ? 'disputed'
            : BigInt(r.amountCents) === remaining
              ? 'refunded'
              : 'partially_refunded';
        await c.query(
          'INSERT INTO g28.financial_provider_events(provider,event_id,payment_id,event_digest,event_kind,amount_cents,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7)',
          [
            provider,
            r.reference,
            identity.session_id,
            digest,
            financialKind,
            r.amountCents,
            new Date(event.created * 1000),
          ],
        );
      }
    }
    await c.query('COMMIT');
    return { status: 200, outcome: 'verified_' + kind + '_requires_treasury_reconciliation' };
  } catch (error) {
    await c.query('ROLLBACK');
    throw error;
  } finally {
    c.release();
  }
}
