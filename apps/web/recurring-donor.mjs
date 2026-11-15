// Donor pages for TEST monthly card schedules (G28-044).
//
// Everything here is TEST only and opens only when ALL of these hold: the private
// preview mode, Stripe TEST checkout settings, G28_TREASURY_SANDBOX_ACTIONS_ENABLED,
// G28_RECURRING_TEST_ENABLED and a database. Card details are entered only on Stripe's
// hosted setup page. A donor never needs a volunteer account. No page loads a script.
// Pages never redirect a form POST to another site; the donor follows an explicit link.
import { createHmac, createHash, timingSafeEqual, randomBytes } from 'node:crypto';
import { escapeHtml } from '../../packages/core/validation.mjs';
import { readCookie } from '../../packages/core/auth.mjs';
import {
  createCheckoutToken,
  checkCheckoutToken,
  validDonationOrigin,
} from '../../packages/core/stripe-web-checkout.mjs';
import { ONLINE_DONATION_ELECTION } from '../../packages/core/contribution-terms.mjs';
import { newRecoveryCode } from '../api/src/card-recurring-service.mjs';

export const MONTHLY_COOKIE = '__Host-g28-monthly';
const CSP =
  "default-src 'self'; style-src 'self'; img-src 'self'; script-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const ATTESTATIONS = [
  ['eligibleResidency', 'I am a U.S. citizen or lawfully admitted permanent resident (i.e., green card holder).'],
  ['ownFunds', 'I contribute from my own funds. I am not contributing funds provided by another person or entity.'],
  ['age18', 'I am at least 18 years old.'],
  ['notFederalContractor', 'I am not a federal contractor.'],
  [
    'personalCreditCard',
    'I am using my personal credit card, not a corporate or business card or a card issued to another person.',
  ],
];
const safe = escapeHtml;
const money = (cents) => '$' + (cents / 100).toFixed(2);
const day = (iso) => new Date(iso).toISOString().slice(0, 10);

export function monthlyEnabled(env, stripeConfig) {
  return (
    env.G28_PUBLIC_MODE === 'preview' &&
    stripeConfig?.sandbox === true &&
    /^sk_test_[A-Za-z0-9_]{12,}$/.test(stripeConfig.secretKey || '') &&
    env.G28_TREASURY_SANDBOX_ACTIONS_ENABLED === 'true' &&
    env.G28_RECURRING_TEST_ENABLED === 'true'
  );
}
const derive = (key, label) => createHmac('sha256', key).update(label).digest();
const mac = (key, value) =>
  createHmac('sha256', key).update('g28:monthly-donor:v1:' + value).digest('base64url');

export function monthlyCapability(key, { enrollmentId, clientReference }, now = Date.now()) {
  const payload = Buffer.from(
    JSON.stringify({ enrollmentId, clientReference, expires: now + 180 * 86400000 }),
  ).toString('base64url');
  return payload + '.' + mac(key, payload);
}
export function monthlyAuthority(key, cookie, now = Date.now()) {
  try {
    if (typeof cookie !== 'string' || cookie.length > 1000) return null;
    const [value, tag, ...extra] = cookie.split('.'),
      expected = mac(key, value);
    if (
      extra.length ||
      typeof tag !== 'string' ||
      tag.length !== expected.length ||
      !timingSafeEqual(Buffer.from(tag), Buffer.from(expected))
    )
      return null;
    const p = JSON.parse(Buffer.from(value, 'base64url'));
    if (
      !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(p.enrollmentId) ||
      !/^attempt_[a-f0-9]{32}$/.test(p.clientReference) ||
      !Number.isSafeInteger(p.expires) ||
      p.expires <= now ||
      p.expires > now + 180 * 86400000
    )
      return null;
    return p;
  } catch {
    return null;
  }
}
const cookie = (value) =>
  `${MONTHLY_COOKIE}=${value}; Path=/donate/monthly; HttpOnly; Secure; SameSite=Lax; Max-Age=15552000`;
const forget = `${MONTHLY_COOKIE}=; Path=/donate/monthly; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
function csrfFor(key, capability, now = Date.now()) {
  const issued = String(Math.floor(now / 1000));
  return issued + '.' + mac(key, 'csrf:' + capability + ':' + issued);
}
function validCsrf(key, capability, token, now = Date.now()) {
  if (typeof token !== 'string' || !/^\d{10}\.[A-Za-z0-9_-]{43}$/.test(token)) return false;
  const [issued, tag] = token.split('.'),
    expected = mac(key, 'csrf:' + capability + ':' + issued);
  return (
    +issued <= now / 1000 + 10 &&
    +issued > now / 1000 - 1800 &&
    tag.length === expected.length &&
    timingSafeEqual(Buffer.from(tag), Buffer.from(expected))
  );
}
// Deterministic enrollment id per browser form, so a replayed submission maps onto the
// original immutable record instead of creating another commitment.
function enrollmentIdFor(key, clientReference) {
  const h = createHmac('sha256', key).update('enrollment:' + clientReference).digest('hex');
  return (
    h.slice(0, 8) +
    '-' +
    h.slice(8, 12) +
    '-4' +
    h.slice(13, 16) +
    '-' +
    ((parseInt(h[16], 16) & 3) | 8).toString(16) +
    h.slice(17, 20) +
    '-' +
    h.slice(20, 32)
  );
}
export function consentDigest(r) {
  return createHash('sha256')
    .update(
      JSON.stringify([
        'g28-monthly-consent-v1',
        r.amountCents,
        r.frequency,
        r.election,
        r.maxInstallments,
        r.endAt,
        r.termsVersion,
        ATTESTATIONS.map(([, text]) => text),
      ]),
    )
    .digest('hex');
}
function page(title, body, notice = true) {
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow"><title>' +
    safe(title) +
    ' | Galinsky 2028</title><link rel="stylesheet" href="/assets/design.css"><link rel="stylesheet" href="/assets/site.css"></head><body><main class="wrap" id="main" style="max-width:760px;padding:48px 20px"><h1>' +
    safe(title) +
    '</h1>' +
    (notice
      ? '<p class="service-notice"><strong>Stripe test mode. No real money moves, and no real card should be used.</strong></p>'
      : '') +
    body +
    '</main></body></html>'
  );
}
function readForm(req, limit = 4096) {
  return (async () => {
    if (!/^application\/x-www-form-urlencoded(?:;|$)/i.test(req.headers['content-type'] || ''))
      throw Object.assign(Error('form'), { status: 415 });
    let raw = '';
    for await (const chunk of req) {
      raw += chunk.toString('utf8');
      if (raw.length > limit) throw Object.assign(Error('form'), { status: 413 });
    }
    return new URLSearchParams(raw);
  })();
}
function sendHtml(res, status, html, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Security-Policy': CSP,
    'Content-Length': Buffer.byteLength(html),
    ...headers,
  });
  res.end(html);
}
function see(res, location, headers = {}) {
  res.writeHead(303, { Location: location, 'Content-Length': '0', ...headers });
  res.end();
}
const scheduleText = (r) =>
  `${money(r.amountCents)} each month, for at most ${r.maxInstallments} month${r.maxInstallments === 1 ? '' : 's'}, never after ${day(r.endAt)}`;

export function createMonthlyDonor({ env, stripeConfig, nonceKey, service, setupDriver, captureDriver, clock = Date.now }) {
  const enabled = monthlyEnabled(env, stripeConfig) && service && setupDriver && captureDriver;
  const formKey = derive(nonceKey, 'g28:monthly-form:v1'),
    capKey = derive(nonceKey, 'g28:monthly-capability:v1');
  const unavailable = (res) =>
    sendHtml(
      res,
      503,
      page(
        'Monthly giving is not available',
        '<p>Monthly giving is not open. No card was saved and nothing was charged.</p><p><a class="btn blue" href="/donate/">Return to giving options</a></p>',
        false,
      ),
    );
  function authority(req) {
    const value = readCookie(req.headers.cookie, MONTHLY_COOKIE);
    const p = monthlyAuthority(capKey, value, clock());
    return p ? { ...p, capability: value } : null;
  }
  function requestFor({ clientReference, amountCents, maxInstallments, endAt, termsVersion, id }) {
    const r = {
      id,
      clientReference,
      amountCents,
      frequency: 'monthly',
      election: ONLINE_DONATION_ELECTION,
      endAt,
      maxInstallments,
      termsVersion,
      attestations: Object.fromEntries(ATTESTATIONS.map(([k]) => [k, true])),
    };
    return { ...r, consentDigest: consentDigest(r) };
  }
  async function startSetup(res, request, replacesMandateId = null) {
    const recoveryCode = newRecoveryCode();
    const { fresh } = await service.beginSetup(request, { recoveryCode, replacesMandateId });
    const created = await setupDriver.create(request);
    await service.cards.recordSetup(request.id, created.sessionId);
    const capability = monthlyCapability(
      capKey,
      { enrollmentId: request.id, clientReference: request.clientReference },
      clock(),
    );
    const headers = replacesMandateId ? {} : { 'Set-Cookie': cookie(capability) };
    sendHtml(
      res,
      200,
      page(
        'Save your recovery code',
        (fresh
          ? '<p>Keep this code somewhere private. It is the only way to manage this ' +
            (replacesMandateId ? 'card change' : 'monthly schedule') +
            ' from another browser or device. It is shown only once and the campaign cannot read it back.</p><p class="recovery-code"><strong>' +
            safe(recoveryCode) +
            '</strong></p>'
          : '<p>This form was already submitted. Use the recovery code shown the first time. No second schedule was created.</p>') +
          '<p>Next, Stripe asks for your card on its own secure page. Saving the card does not charge it. The campaign treasury reviews the saved card before any monthly gift.</p>' +
          '<p><a class="btn blue" href="' +
          safe(created.hostedUrl) +
          '" rel="noopener noreferrer">Continue to Stripe’s secure card page</a></p>',
      ),
      headers,
    );
  }

  async function handle(req, res, pathname) {
    if (pathname !== '/donate/monthly' && !pathname.startsWith('/donate/monthly/')) return false;
    if (!enabled) {
      unavailable(res);
      return true;
    }
    const post = req.method === 'POST';
    if (!post && !['GET', 'HEAD'].includes(req.method)) {
      res.writeHead(405, { Allow: 'GET, HEAD, POST' });
      res.end();
      return true;
    }
    if (post && !validDonationOrigin(req, stripeConfig)) {
      sendHtml(res, 403, page('Request not accepted', '<p>Reload the page and try again.</p>', false));
      return true;
    }
    try {
      if (pathname === '/donate/monthly' && !post) {
        let rules;
        try {
          rules = await service.publicRules();
        } catch {
          unavailable(res);
          return true;
        }
        const endAt = rules.cutoffs[ONLINE_DONATION_ELECTION];
        const options = Array.from({ length: rules.maxInstallments }, (_, i) => i + 1)
          .map((n) => `<option value="${n}"${n === Math.min(12, rules.maxInstallments) ? ' selected' : ''}>${n}</option>`)
          .join('');
        sendHtml(
          res,
          200,
          page(
            'Give monthly',
            '<form method="post" action="/donate/monthly/setup">' +
              '<input type="hidden" name="form_token" value="' +
              safe(createCheckoutToken(formKey, clock())) +
              '">' +
              '<p><label>Monthly amount in U.S. dollars <input name="amount" inputmode="numeric" pattern="[0-9]{1,6}" required value="25"></label></p>' +
              '<p><label>Number of months (at most) <select name="months">' +
              options +
              '</select></label></p>' +
              '<p>Every gift is designated for the 2028 general election. No gift is collected after ' +
              safe(day(endAt)) +
              ', even if months remain. You can cancel at any time on this website; cancelling stops all future gifts.</p>' +
              '<fieldset><legend>I certify that all of the following are true:</legend>' +
              ATTESTATIONS.map(
                ([k, text]) =>
                  `<p><label><input type="checkbox" name="${k}" value="yes" required> ${safe(text)}</label></p>`,
              ).join('') +
              '</fieldset>' +
              '<p><label><input type="checkbox" name="agree" value="yes" required> I agree to the monthly schedule shown above and the campaign’s contribution terms (version ' +
              safe(rules.termsVersion) +
              ').</label></p>' +
              '<p><button class="btn blue">Continue</button></p></form>' +
              '<p><a href="/donate/monthly/manage">Manage an existing monthly schedule</a></p>',
          ),
        );
        return true;
      }
      if (pathname === '/donate/monthly/setup' && post) {
        const form = await readForm(req);
        const clientReference = checkCheckoutToken(formKey, form.get('form_token'), clock());
        const amount = form.get('amount') || '',
          months = Number(form.get('months'));
        const rules = await service.publicRules();
        if (
          !clientReference ||
          !/^[1-9][0-9]{0,5}$/.test(amount) ||
          !Number.isSafeInteger(months) ||
          months < 1 ||
          months > rules.maxInstallments ||
          form.get('agree') !== 'yes' ||
          ATTESTATIONS.some(([k]) => form.get(k) !== 'yes')
        ) {
          sendHtml(
            res,
            400,
            page('Please check the form', '<p>Every statement must be confirmed and the amount must be whole dollars. Nothing was saved.</p><p><a class="btn blue" href="/donate/monthly">Return to the form</a></p>', false),
          );
          return true;
        }
        const request = requestFor({
          id: enrollmentIdFor(formKey, clientReference),
          clientReference,
          amountCents: Number(amount) * 100,
          maxInstallments: months,
          endAt: rules.cutoffs[ONLINE_DONATION_ELECTION],
          termsVersion: rules.termsVersion,
        });
        await startSetup(res, request);
        return true;
      }
      if (pathname === '/donate/monthly/recover' && post) {
        const form = await readForm(req, 512);
        const found = await service.recover(form.get('code') || '');
        if (!found) {
          sendHtml(res, 404, page('Code not recognized', '<p>Check the code and try again.</p><p><a href="/donate/monthly/manage">Back</a></p>', false));
          return true;
        }
        see(res, '/donate/monthly/manage', {
          'Set-Cookie': cookie(monthlyCapability(capKey, found, clock())),
        });
        return true;
      }
      const who = authority(req);
      if (pathname === '/donate/monthly/manage' && !post) {
        if (!who) {
          sendHtml(
            res,
            200,
            page(
              'Manage monthly giving',
              '<p>This browser is not linked to a monthly schedule. Enter the recovery code you saved when you set it up. No volunteer account is needed.</p>' +
                '<form method="post" action="/donate/monthly/recover"><p><label>Recovery code <input name="code" autocomplete="off" required></label></p><p><button class="btn blue">Open my schedule</button></p></form>',
            ),
          );
          return true;
        }
        const view = await service.donorView(who.enrollmentId, who.clientReference);
        const csrf = csrfFor(capKey, who.capability, clock());
        const hidden = '<input type="hidden" name="form_token" value="' + safe(csrf) + '">';
        const e = view.enrollment,
          s = view.schedule;
        let body = '';
        if (!s) {
          body +=
            '<p>Your monthly gift of ' +
            safe(scheduleText(e)) +
            ' is ' +
            safe(
              e.status === 'cancelled'
                ? 'cancelled. No card will be charged.'
                : 'waiting for the campaign treasury to review the saved card. Nothing has been charged.',
            ) +
            '</p>';
        } else {
          body +=
            '<p>Schedule: ' +
            safe(scheduleText(s)) +
            '. Status: <strong>' +
            safe(s.status === 'active' ? 'active' : s.status === 'complete' ? 'finished' : 'cancelled') +
            '</strong>.</p>' +
            (s.nextScheduledAt
              ? '<p>Next gift: on or after ' + safe(day(s.nextScheduledAt)) + ', after treasury review.</p>'
              : '') +
            (view.installments.length
              ? '<ul>' +
                view.installments
                  .map((i) => '<li>Month ' + (i.installment + 1) + ': ' + safe(i.state) + '</li>')
                  .join('') +
                '</ul>'
              : '') +
            (view.replacement
              ? '<p>Card change request: ' + safe(view.replacement) + '.</p>'
              : '');
          if (view.confirmation)
            body +=
              '<form method="post" action="/donate/monthly/confirm">' +
              hidden +
              '<input type="hidden" name="period" value="' +
              safe(view.confirmation.periodId) +
              '"><p>Your bank needs you to confirm your first monthly gift. Confirming lets the campaign request it; the treasury collects it separately.</p><p><button class="btn blue">Confirm with my bank</button></p></form>';
          if (s.status === 'active')
            body +=
              '<form method="post" action="/donate/monthly/card">' +
              hidden +
              '<h2>Use a different card</h2>' +
              ATTESTATIONS.map(
                ([k, text]) =>
                  `<p><label><input type="checkbox" name="${k}" value="yes" required> ${safe(text)}</label></p>`,
              ).join('') +
              '<p><button class="btn outline">Change card</button></p></form>';
        }
        if ((s && s.status === 'active') || (!s && e.status !== 'cancelled'))
          body +=
            '<form method="post" action="/donate/monthly/cancel">' +
            hidden +
            '<h2>Cancel</h2><p>Cancelling stops every future monthly gift. Gifts already collected are not refunded automatically; contact the campaign for a refund.</p><p><label><input type="checkbox" name="confirm" value="cancel" required> Cancel all future gifts</label></p><p><button class="btn outline">Cancel monthly giving</button></p></form>';
        body +=
          '<form method="post" action="/donate/monthly/forget">' +
          hidden +
          '<p><button class="btn outline">Forget this schedule on this browser</button></p></form>';
        sendHtml(res, 200, page('Manage monthly giving', body));
        return true;
      }
      if (pathname === '/donate/monthly/confirmed' && !post) {
        if (!who) return see(res, '/donate/monthly/manage'), true;
        const periodId = new URL(req.url, 'https://localhost').searchParams.get('period') || '';
        try {
          const t = await service.confirmationTarget(who.enrollmentId, who.clientReference, periodId, {
            returning: true,
          });
          const seen = await captureDriver.inspect(t.approval, t.paymentIntentId);
          await service.recordConfirmationObservation(t.periodId, seen);
        } catch {
          /* The schedule page shows the authoritative current state. */
        }
        see(res, '/donate/monthly/manage');
        return true;
      }
      if (!post) return false;
      // Every remaining action is a donor-authorized POST with this browser's CSRF token.
      const form = await readForm(req, 1024);
      if (!who || !validCsrf(capKey, who.capability, form.get('form_token'), clock())) {
        sendHtml(res, 403, page('Request not accepted', '<p>Reload your schedule page and try again.</p>', false));
        return true;
      }
      if (pathname === '/donate/monthly/forget') {
        see(res, '/donate/monthly/manage', { 'Set-Cookie': forget });
        return true;
      }
      if (pathname === '/donate/monthly/cancel') {
        if (form.get('confirm') !== 'cancel') {
          sendHtml(res, 400, page('Not cancelled', '<p>Tick the confirmation box to cancel.</p><p><a href="/donate/monthly/manage">Back</a></p>', false));
          return true;
        }
        await service.donorCancel(who.enrollmentId, who.clientReference);
        see(res, '/donate/monthly/manage');
        return true;
      }
      if (pathname === '/donate/monthly/card') {
        if (ATTESTATIONS.some(([k]) => form.get(k) !== 'yes')) {
          sendHtml(res, 400, page('Card not changed', '<p>Every statement must be confirmed.</p><p><a href="/donate/monthly/manage">Back</a></p>', false));
          return true;
        }
        const view = await service.donorView(who.enrollmentId, who.clientReference);
        const s = view.schedule;
        if (!s || s.status !== 'active') {
          sendHtml(res, 409, page('Card not changed', '<p>Only an active schedule can use a different card.</p>', false));
          return true;
        }
        const clientReference = 'attempt_' + randomBytes(16).toString('hex');
        const request = requestFor({
          id: enrollmentIdFor(formKey, clientReference),
          clientReference,
          amountCents: s.amountCents,
          maxInstallments: s.maxInstallments,
          endAt: s.endAt,
          termsVersion: view.enrollment.termsVersion,
        });
        await startSetup(res, request, view.mandateId);
        return true;
      }
      if (pathname === '/donate/monthly/confirm') {
        const t = await service.confirmationTarget(
          who.enrollmentId,
          who.clientReference,
          form.get('period') || '',
        );
        const result = await captureDriver.donorConfirm(
          t.approval,
          t.paymentIntentId,
          stripeConfig.origin + '/donate/monthly/confirmed?period=' + t.periodId,
        );
        if (!result.redirectUrl) {
          await service.recordConfirmationObservation(t.periodId, result.seen);
          see(res, '/donate/monthly/manage');
          return true;
        }
        sendHtml(
          res,
          200,
          page(
            'Confirm with your bank',
            '<p>Your bank’s confirmation page is hosted by Stripe. After confirming you return here.</p><p><a class="btn blue" href="' +
              safe(result.redirectUrl) +
              '" rel="noopener noreferrer">Continue to bank confirmation</a></p>',
          ),
        );
        return true;
      }
      return false;
    } catch (error) {
      if (error?.status === 413 || error?.status === 415) {
        res.writeHead(error.status, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Use the form on this page.');
        return true;
      }
      const status = [403, 409].includes(error?.status) ? error.status : 503;
      console.error(
        JSON.stringify({
          event: 'monthly_donor_refused',
          code: typeof error?.code === 'string' && /^[a-z_]{3,60}$/.test(error.code) ? error.code : 'unexpected',
        }),
      );
      sendHtml(
        res,
        status,
        page(
          'Not completed',
          '<p>' +
            (status === 403
              ? 'This browser cannot manage that schedule.'
              : 'This could not be completed right now. Nothing new was charged and no second schedule was created.') +
            '</p><p><a href="/donate/monthly/manage">Return to your schedule</a></p>',
          false,
        ),
      );
      return true;
    }
  }
  return { handle, enabled: Boolean(enabled) };
}
