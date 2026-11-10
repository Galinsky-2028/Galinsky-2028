import { assert, exactKeys } from '../../../packages/core/validation.mjs';
import { financeId } from '../../../packages/core/treasury-workflow.mjs';
import { StripeManualCapture } from '../../../packages/core/stripe-manual-capture.mjs';
import { StripeCardSetup } from '../../../packages/core/stripe-card-setup.mjs';
import { CardContributionStore } from './card-contribution-store.mjs';
export function registerCardContributions(
  app,
  { store, config, writeSession, clock, transport = fetch },
) {
  const cards = new CardContributionStore({ store, config, clock });
  async function actor(req) {
    assert(
      config.staffIdentity && config.adminLoginReady && store.pool,
      'card_staff_unavailable',
      'Verified treasury staff and storage are required.',
      503,
    );
    return writeSession(req);
  }
  function driver(setup = false) {
    assert(
      config.treasurySandboxActions === true,
      'card_test_actions_unavailable',
      'Card TEST processor actions are disabled; live actions are not installed.',
      503,
    );
    return setup
      ? new StripeCardSetup({
          secretKey: config.stripeTestKey,
          origin: config.publicOrigin,
          transport,
        })
      : new StripeManualCapture({ secretKey: config.stripeTestKey, clock, transport });
  }
  const route = (path, handler) =>
    app.post('/api/staff/finance/card/' + path, { bodyLimit: 20000 }, async (req, reply) => {
      reply.header('Cache-Control', 'no-store');
      const staff = await actor(req);
      return handler(req, staff);
    });
  route('page', async (req, staff) => cards.page(staff, req.body));
  route('policies', async (req, staff) => {
    const b = exactKeys(req.body, ['policy', 'confirm']);
    assert(
      b.confirm === 'approve exact card-control rules',
      'card_policy_confirmation',
      'Confirm the documentary card policy.',
    );
    return cards.savePolicy(staff, b.policy);
  });
  route('enrollments/:id/review', async (req, staff) => {
    exactKeys(req.body, []);
    return cards.reviewEnrollment(staff, financeId(req.params.id));
  });
  route('enrollments/:id/verify-test', async (req, staff) => {
    const b = exactKeys(req.body, ['confirm']);
    assert(
      b.confirm === 'verify actual TEST card setup',
      'card_verification_confirmation',
      'Confirm this actual TEST setup verification.',
    );
    return cards.verifyEnrollment(staff, financeId(req.params.id), driver(true));
  });
  route('mandates', async (req, staff) => cards.approveMandate(staff, req.body));
  route('mandates/:id/cancel', async (req, staff) => {
    const b = exactKeys(req.body, ['version', 'confirm']);
    assert(
      Number.isSafeInteger(b.version) &&
        b.version > 0 &&
        b.confirm === 'cancel exact future schedule',
      'card_cancel_confirmation',
      'Confirm the exact current schedule cancellation.',
    );
    return cards.cancelMandate(staff, financeId(req.params.id), b.version);
  });
  route('periods', async (req, staff) => cards.reservePeriod(staff, req.body));
  route('commands', async (req, staff) => cards.prepareCommand(staff, req.body));
  route('commands/:id/perform-test', async (req, staff) => {
    const b = exactKeys(req.body, ['confirm']);
    assert(
      b.confirm === 'dispatch exact TEST command once',
      'card_dispatch_confirmation',
      'Confirm this exact TEST operation.',
    );
    return cards.performCommand(staff, financeId(req.params.id), driver());
  });
  route('commands/:id/reconcile-test', async (req, staff) => {
    const b = exactKeys(req.body, ['providerPaymentId', 'confirm']);
    assert(
      b.confirm === 'observe exact existing TEST intent',
      'card_reconcile_confirmation',
      'Confirm observation of this existing TEST intent.',
    );
    return cards.reconcileCommand(staff, financeId(req.params.id), b.providerPaymentId, driver());
  });
}
