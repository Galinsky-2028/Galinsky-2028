import { assert } from './validation.mjs';
// The installed executor is TEST ONLY. No flag, staff grant or supplied live key
// can turn this module into a live charge/refund implementation.
export async function requestStripeTestRefund({
  secretKey,
  sessionId,
  clientReference,
  originalAmountCents,
  amountCents,
  commandId,
  transport = fetch,
}) {
  assert(
    typeof secretKey === 'string' &&
      /^sk_test_[A-Za-z0-9_]{12,}$/.test(secretKey) &&
      /^cs_test_[A-Za-z0-9]{10,}$/.test(sessionId),
    'sandbox_action_only',
    'Only a verified Stripe test payment can be used.',
    403,
  );
  const send = async (path, body) => {
    const response = await transport('https://api.stripe.com/v1/' + path, {
      method: body ? 'POST' : 'GET',
      headers: {
        Authorization: 'Bearer ' + secretKey,
        ...(body
          ? {
              'Content-Type': 'application/x-www-form-urlencoded',
              'Idempotency-Key': 'g28-treasury-refund-' + commandId,
            }
          : {}),
      },
      ...(body ? { body: new URLSearchParams(body).toString() } : {}),
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    assert(
      response.ok,
      'sandbox_provider_refusal',
      'The test provider did not confirm this operation.',
      503,
    );
    const text = await response.text();
    assert(text.length < 100000, 'invalid_provider_response', 'Unexpected provider response.', 503);
    return JSON.parse(text);
  };
  const session = await send('checkout/sessions/' + encodeURIComponent(sessionId));
  assert(
    session.id === sessionId &&
      session.livemode === false &&
      session.client_reference_id === clientReference &&
      session.amount_total === originalAmountCents &&
      session.currency === 'usd' &&
      session.payment_status === 'paid' &&
      /^pi_[A-Za-z0-9]{5,100}$/.test(session.payment_intent),
    'sandbox_payment_mismatch',
    'Stripe did not verify the exact original test payment.',
    409,
  );
  assert(
    Number.isSafeInteger(amountCents) &&
      amountCents > 0 &&
      amountCents <= originalAmountCents &&
      /^[a-f0-9-]{36}$/.test(commandId),
    'sandbox_refund_amount',
    'Use an exact approved test refund amount and command reference.',
  );
  const result = await send('refunds', {
    payment_intent: session.payment_intent,
    amount: String(amountCents),
    'metadata[g28_treasury_command]': commandId,
  });
  assert(
    /^re_[A-Za-z0-9]{5,100}$/.test(result.id) &&
      result.amount === amountCents &&
      result.currency === 'usd' &&
      result.payment_intent === session.payment_intent &&
      ['pending', 'succeeded', 'requires_action'].includes(result.status),
    'sandbox_refund_unconfirmed',
    'The provider did not confirm the expected test refund. Reconcile its status before any retry.',
    409,
  );
  return {
    providerReference: result.id,
    status: result.status,
    notice:
      'Provider test response only. A signed refund receipt and matching treasury posting are still required.',
  };
}
