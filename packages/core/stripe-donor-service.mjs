// Donor authority is separate from volunteer/staff identity. An HttpOnly,
// signed original-browser capability binds exactly one recorded checkout.
import { createHmac, timingSafeEqual } from 'node:crypto';
import { assert, escapeHtml } from './validation.mjs';
const SESSION = /^cs_(test|live)_[A-Za-z0-9]{10,}$/;
export const DONOR_COOKIE = '__Host-g28-donor';
const mac = (secret, value) =>
  createHmac('sha256', secret)
    .update('g28:donor-management:v1:' + value)
    .digest('base64url');
export function donorCapability(secret, { clientRef, sessionId }, now = Date.now()) {
  assert(
    /^attempt_[a-f0-9]{32}$/.test(clientRef) && SESSION.test(sessionId),
    'invalid_donor_reference',
    'Invalid contribution reference.',
  );
  const payload = Buffer.from(
    JSON.stringify({ clientRef, sessionId, expires: now + 30 * 86400000 }),
  ).toString('base64url');
  return payload + '.' + mac(secret, payload);
}
export function donorAuthority(secret, cookie, now = Date.now()) {
  try {
    if (typeof cookie !== 'string' || cookie.length > 1000) return null;
    const [value, tag, ...extra] = cookie.split('.'),
      expected = mac(secret, value);
    if (
      extra.length ||
      typeof tag !== 'string' ||
      tag.length !== expected.length ||
      !timingSafeEqual(Buffer.from(tag), Buffer.from(expected))
    )
      return null;
    const p = JSON.parse(Buffer.from(value, 'base64url'));
    if (
      !/^attempt_[a-f0-9]{32}$/.test(p.clientRef) ||
      !SESSION.test(p.sessionId) ||
      !Number.isSafeInteger(p.expires) ||
      p.expires <= now ||
      p.expires > now + 30 * 86400000
    )
      return null;
    return p;
  } catch {
    return null;
  }
}
export const donorCookie = (value) =>
  `${DONOR_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`;
export function donorCsrf(secret, capability, now = Date.now()) {
  const issued = String(Math.floor(now / 1000));
  return issued + '.' + mac(secret, 'csrf:' + capability + ':' + issued);
}
export function validDonorCsrf(secret, capability, token, now = Date.now()) {
  if (typeof token !== 'string' || !/^\d{10}\.[A-Za-z0-9_-]{43}$/.test(token)) return false;
  const [issued, tag] = token.split('.'),
    expected = mac(secret, 'csrf:' + capability + ':' + issued);
  return (
    +issued <= now / 1000 + 10 &&
    +issued > now / 1000 - 900 &&
    tag.length === expected.length &&
    timingSafeEqual(Buffer.from(tag), Buffer.from(expected))
  );
}
function providerUrl(value, host) {
  try {
    const u = new URL(value);
    if (u.protocol === 'https:' && u.hostname === host && !u.username && !u.password && !u.port)
      return u.href;
  } catch {}
  return null;
}
export function donorLoginUrl(value) {
  const u = providerUrl(value, 'billing.stripe.com');
  return u && /^\/p\/login\/[A-Za-z0-9]+$/.test(new URL(u).pathname) ? u : null;
}
async function stripe(settings, path, { transport = fetch, body } = {}) {
  const response = await transport('https://api.stripe.com/v1/' + path, {
    method: body ? 'POST' : 'GET',
    headers: {
      Authorization: 'Bearer ' + settings.secretKey,
      ...(body ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}),
    },
    ...(body ? { body: new URLSearchParams(body).toString() } : {}),
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  assert(
    response.ok,
    'donor_provider_unavailable',
    'Stripe could not complete this request. Check again later; no new contribution was created.',
    503,
  );
  const text = await response.text();
  assert(text.length < 200000, 'invalid_provider_response', 'Invalid processor response.', 503);
  try {
    return JSON.parse(text);
  } catch {
    assert(false, 'invalid_provider_response', 'Invalid processor response.', 503);
  }
}
export async function stripeDonorRecord({ settings, authority, store, transport = fetch }) {
  const row = await store.donorIntent(authority.clientRef, authority.sessionId);
  assert(
    row && row.livemode === settings.live,
    'donor_forbidden',
    'This browser does not have access to that contribution.',
    403,
  );
  const checkout = await stripe(
    settings,
    'checkout/sessions/' +
      encodeURIComponent(authority.sessionId) +
      '?expand%5B%5D=payment_intent.latest_charge',
    { transport },
  );
  assert(
    checkout.id === authority.sessionId &&
      checkout.client_reference_id === authority.clientRef &&
      checkout.livemode === settings.live &&
      checkout.currency === 'usd' &&
      checkout.amount_total === Number(row.amount_cents),
    'donor_identity_mismatch',
    'The provider record does not match the recorded contribution.',
    409,
  );
  const paid = checkout.payment_status === 'paid' && row.payment_state === 'paid';
  const receipt = paid
    ? providerUrl(checkout.payment_intent?.latest_charge?.receipt_url, 'pay.stripe.com') ||
      providerUrl(checkout.payment_intent?.latest_charge?.receipt_url, 'receipts.stripe.com')
    : null;
  const customer =
    typeof checkout.customer === 'string' && /^cus_[A-Za-z0-9]+$/.test(checkout.customer)
      ? checkout.customer
      : null;
  const refundedCents = Number(row.refunded_cents || 0);
  assert(
    Number.isSafeInteger(refundedCents) &&
      refundedCents >= 0 &&
      refundedCents <= Number(row.amount_cents),
    'donor_reconciliation_required',
    'Refund source totals need campaign reconciliation.',
    409,
  );
  return {
    paid,
    status: row.payment_state,
    amountCents: Number(row.amount_cents),
    refundedCents,
    election: row.election,
    receipt,
    customer,
    termsVersion: row.terms_version,
    recurring: false,
  };
}
export async function stripeDonorPortal({
  settings,
  authority,
  store,
  transport = fetch,
  configuration,
}) {
  const record = await stripeDonorRecord({ settings, authority, store, transport });
  assert(
    record.paid && record.customer,
    'donor_portal_unavailable',
    'A confirmed Stripe customer is required. Use Stripe’s own verified email login or receipt link.',
    409,
  );
  assert(
    typeof configuration === 'string' && /^bpc_[A-Za-z0-9]+$/.test(configuration),
    'donor_portal_unavailable',
    'The campaign must configure Stripe’s donor portal before this action opens.',
    503,
  );
  const result = await stripe(settings, 'billing_portal/sessions', {
      transport,
      body: {
        customer: record.customer,
        configuration,
        return_url: settings.origin + '/donate/manage',
      },
    }),
    url = providerUrl(result.url, 'billing.stripe.com');
  assert(
    result.customer === record.customer &&
      result.configuration === configuration &&
      result.livemode === settings.live,
    'donor_portal_identity',
    'Stripe did not confirm this exact customer, configuration and environment.',
    503,
  );
  assert(url, 'invalid_donor_portal', 'Stripe returned an invalid donor portal destination.', 503);
  return url;
}
export function donorManagementHtml({ record, csrf, loginUrl, available, sandbox }) {
  const safe = escapeHtml,
    link = donorLoginUrl(loginUrl);
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow"><title>Manage your contribution | Galinsky 2028</title><link rel="stylesheet" href="/assets/design.css"><link rel="stylesheet" href="/assets/site.css"></head><body><main id="main" class="wrap" style="max-width:800px;padding:42px 20px"><a href="/donate/">Contribution information</a><h1>Manage your contribution</h1>' +
    (sandbox
      ? '<p class="service-notice"><strong>Stripe test mode. No real money moved.</strong></p>'
      : '') +
    '<p>No volunteer account is needed. The campaign does not handle your card number. Stripe controls final payment, receipt and subscription states.</p>' +
    (record
      ? '<h2>This browser’s most recent contribution</h2><p>Original amount: $' +
        (record.amountCents / 100).toFixed(2) +
        ' USD · ' +
        safe(record.election) +
        ' election</p><p>Status: ' +
        safe(
          record.paid
            ? 'Original processor payment and signed campaign ledger confirmed; bank settlement is separate.'
            : record.status === 'pending'
              ? 'Processing; do not submit another payment.'
              : record.status === 'requires_review'
                ? 'Campaign reconciliation is required.'
                : record.status,
        ) +
        '</p>' +
        (record.refundedCents
          ? '<p>Signed processor refunds recorded: $' +
            (record.refundedCents / 100).toFixed(2) +
            ' USD. Check the processor receipt for its authoritative current details.</p>'
          : '') +
        '<p>One-time contribution. No recurring schedule was authorized.</p>' +
        (record.receipt
          ? '<p><a class="btn blue" href="' +
            safe(record.receipt) +
            '" rel="noopener noreferrer">Open Stripe receipt</a></p>'
          : '<p>A processor receipt is available after confirmed payment. This page does not claim a pending or unmatched payment succeeded.</p>') +
        (available && record.paid && record.customer
          ? '<form action="/donate/manage/portal" method="post"><input type="hidden" name="form_token" value="' +
            safe(csrf) +
            '"><button class="btn blue">Open Stripe donor portal</button></form>'
          : '')
      : '<p>This browser has no current contribution session. Use the processor’s own verified-email login or the receipt sent by Stripe; campaign support cannot disclose another donor’s records.</p>') +
    (record
      ? '<form action="/donate/manage/forget" method="post"><input type="hidden" name="form_token" value="' +
        safe(csrf) +
        '"><button class="btn outline">Forget contribution access on this browser</button></form>'
      : '') +
    (link
      ? '<p><a href="' +
        safe(link) +
        '" rel="noopener noreferrer">Sign in directly through Stripe</a></p>'
      : '<p>Use the secure receipt or management link sent directly by Stripe if you are on another device.</p>') +
    '<p>For any existing subscription, review its frequency, next charge and cancellation effect on Stripe before confirming a change. Cancellation stops future scheduled charges according to the provider’s displayed terms; it does not itself refund past gifts. New recurring campaign contributions remain disabled until their rules and enforcement are approved.</p><p>Contributions are not tax deductible. Paid for by Phillip Galinsky for America.</p></main></body></html>'
  );
}
