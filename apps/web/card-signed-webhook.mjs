import { createHash } from 'node:crypto';
// No signature bypass: caller supplies only the minimized, authenticated event
// returned by verifyStripeWebhook, plus its exact original raw-body digest.
export async function recordSignedCardEvent(pool, e, raw) {
  const f = e.manualCard;
  if (!f || f.invalid || e.livemode || !Number.isSafeInteger(e.created) || e.created <= 0)
    return { status: 422, outcome: 'unmatched_card_event' };
  const digest = createHash('sha256').update(raw).digest('hex'),
    c = await pool.connect();
  try {
    await c.query('BEGIN');
    await c.query("SELECT pg_advisory_xact_lock(hashtext('g28-finance-journal'))");
    const prior = (
      await c.query('SELECT event_sha256 FROM g28.stripe_webhook_receipts WHERE event_id=$1', [
        e.id,
      ])
    ).rows[0];
    if (prior) {
      if (prior.event_sha256 !== digest) {
        await c.query('ROLLBACK');
        return { status: 422, outcome: 'conflicting_card_event' };
      }
      await c.query('COMMIT');
      return { status: 200, outcome: 'duplicate' };
    }
    let reference;
    if (f.kind === 'setup') {
      const row = (
          await c.query('SELECT * FROM g28.card_enrollments WHERE id=$1', [f.enrollmentId])
        ).rows[0],
        b = row?.request_document;
      if (
        !row ||
        row.environment !== 'test' ||
        row.client_reference !== f.clientReference ||
        b.consentDigest !== f.consentDigest ||
        b.termsVersion !== f.termsVersion ||
        (row.setup_session_id && row.setup_session_id !== f.sessionId)
      ) {
        await c.query('ROLLBACK');
        return { status: 422, outcome: 'unmatched_card_setup' };
      }
      // This receipt proves the callback only; fresh private SDK verification and
      // documented staff review are still required before mandate approval.
      reference = f.sessionId;
      if (e.type === 'checkout.session.completed' && row.status === 'preparing')
        await c.query(
          "UPDATE g28.card_enrollments SET setup_session_id=$2,status='pending',updated_at=now() WHERE id=$1",
          [row.id, f.sessionId],
        );
    } else {
      const row = (await c.query('SELECT * FROM g28.card_periods WHERE id=$1', [f.periodId]))
          .rows[0],
        p = row?.document?.providerApproval,
        cmd = (
          await c.query(
            "SELECT * FROM g28.card_commands WHERE id=$1 AND period_id=$2 AND action='authorize'",
            [f.attemptId, f.periodId],
          )
        ).rows[0];
      if (
        !row ||
        !p ||
        !cmd ||
        row.environment !== 'test' ||
        (row.provider_payment_id && row.provider_payment_id !== f.id) ||
        p.attemptId !== f.attemptId ||
        p.periodId !== f.periodId ||
        p.policyDigest !== f.policyDigest ||
        p.mandateDigest !== f.mandateDigest ||
        p.confirmationMode !== f.confirmationMode ||
        p.customerId !== f.customerId ||
        p.amountCents !== f.amountCents ||
        !(
          p.paymentMethodId === f.paymentMethodId ||
          (f.paymentMethodId === null &&
            ['requires_payment_method', 'canceled'].includes(f.status) &&
            f.amountReceived === 0 &&
            f.amountCapturable === 0)
        )
      ) {
        await c.query('ROLLBACK');
        return { status: 422, outcome: 'unmatched_card_intent' };
      }
      if (
        (e.type === 'payment_intent.succeeded' &&
          (f.status !== 'succeeded' ||
            f.amountReceived !== f.amountCents ||
            f.amountCapturable !== 0)) ||
        (f.status === 'succeeded' && e.type !== 'payment_intent.succeeded') ||
        (e.type === 'payment_intent.canceled' &&
          (f.status !== 'canceled' || f.amountReceived !== 0 || f.amountCapturable !== 0))
      ) {
        await c.query('ROLLBACK');
        return { status: 422, outcome: 'conflicting_card_outcome' };
      }
      reference = f.id;
      if (e.type === 'payment_intent.succeeded') {
        // A second terminal callback cannot journal the same contribution twice.
        if (!row.capture_event_id) {
          await c.query(
            "INSERT INTO g28.financial_provider_events(provider,event_id,payment_id,event_digest,event_kind,amount_cents,occurred_at) VALUES('stripe-test',$1,$2,$3,'captured',$4,$5)",
            [e.id, f.id, digest, f.amountReceived, new Date(e.created * 1000)],
          );
          await c.query(
            "UPDATE g28.card_periods SET provider_payment_id=$2,capture_event_id=$3,status=CASE WHEN status='posted' THEN status ELSE 'captured_unposted' END,version=version+1,updated_at=now() WHERE id=$1",
            [row.id, f.id, e.id],
          );
        }
      } else if (e.type === 'payment_intent.canceled') {
        if (!['posted', 'captured_unposted'].includes(row.status))
          await c.query(
            "UPDATE g28.card_periods SET provider_payment_id=$2,status='voided',reservation_active=false,version=version+1,updated_at=now() WHERE id=$1",
            [row.id, f.id],
          );
      } else if (!row.provider_payment_id)
        await c.query(
          'UPDATE g28.card_periods SET provider_payment_id=$2,version=version+1,updated_at=now() WHERE id=$1',
          [row.id, f.id],
        );
      // Do not clear a command's unknown status on a nonterminal callback. Staff
      // GET reconciliation must verify current processor state before another I/O.
    }
    await c.query(
      'INSERT INTO g28.stripe_webhook_receipts(event_id,event_sha256,session_id,livemode,event_type) VALUES($1,$2,$3,false,$4)',
      [e.id, digest, reference, e.type],
    );
    await c.query('COMMIT');
    return {
      status: 200,
      outcome: f.kind === 'setup' ? 'signed_setup_requires_review' : 'signed_card_state_recorded',
    };
  } catch (error) {
    await c.query('ROLLBACK');
    throw error;
  } finally {
    c.release();
  }
}
