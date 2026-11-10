import { assert, exactKeys } from '../../../packages/core/validation.mjs';
import { financeId } from '../../../packages/core/treasury-workflow.mjs';
export function registerTreasuryWorkflow(
  app,
  { store, config, writeSession, clock, transport = fetch },
) {
  async function actor(req) {
    assert(
      config.staffIdentity &&
        config.adminLoginReady &&
        typeof store.financeTransaction === 'function',
      'finance_unavailable',
      'Treasury casework requires configured verified staff identity and storage.',
      503,
    );
    const s = await writeSession(req),
      role = await store.adminRole(s.account, config.adminOwnerEmailKey);
    assert(
      ['owner', 'treasurer'].includes(role),
      'finance_forbidden',
      'Only the current owner or treasurer may use this workflow.',
      403,
    );
    assert(
      await store.staffMfaValid(s.account.id, s.hash, clock()),
      'mfa_required',
      'Verify your staff passkey before accessing treasury records.',
      403,
    );
    return s.account.id;
  }
  app.post('/api/staff/finance/overview', async (req) => {
    const id = await actor(req);
    exactKeys(req.body, []);
    const overview = await store.financeOverview();
    return { ...overview, actorId: id, sandboxActions: config.treasurySandboxActions === true };
  });
  app.post('/api/staff/finance/evidence', { bodyLimit: 210000 }, async (req) => {
    const id = await actor(req);
    return store.saveFinanceEvidence(req.body, id, config.treasuryKey);
  });
  app.post('/api/staff/finance/evidence/:id/read', async (req, reply) => {
    const id = await actor(req);
    exactKeys(req.body, []);
    const result = await store.readFinanceEvidence(
      financeId(req.params.id),
      id,
      config.treasuryKey,
    );
    return reply
      .header(
        'Content-Disposition',
        'attachment; filename="galinsky-private-evidence-' + req.params.id + '.bin"',
      )
      .header('X-Content-SHA256', result.digest)
      .type('application/octet-stream')
      .send(result.bytes);
  });
  app.post('/api/staff/finance/page', async (req) => {
    await actor(req);
    const b = exactKeys(req.body, ['collection', 'after']);
    return store.financePage(b.collection, b.after ?? null);
  });
  app.post('/api/staff/finance/policies', async (req) => {
    const id = await actor(req),
      b = exactKeys(req.body, ['policy', 'confirm']);
    assert(
      b.confirm === 'approve these treasury rules',
      'finance_policy_approval',
      'Explicitly approve the actual reviewed treasury rules and accounting mapping.',
    );
    return store.saveFinancePolicy(b.policy, id, clock());
  });
  app.post('/api/staff/finance/donors', async (req) => {
    const id = await actor(req),
      b = exactKeys(req.body, ['donor', 'expectedVersion']);
    assert(
      Number.isSafeInteger(b.expectedVersion) && b.expectedVersion >= 0,
      'finance_identity_version',
      'Use the exact current contributor revision.',
    );
    return store.saveFinanceDonor(b.donor, b.expectedVersion, id, config.treasuryKey);
  });
  app.post('/api/staff/finance/donors/:id/read', async (req) => {
    const id = await actor(req),
      b = exactKeys(req.body, ['version']);
    assert(
      Number.isSafeInteger(b.version) && b.version > 0,
      'finance_identity_version',
      'Choose the exact contributor revision.',
    );
    return store.financeDonor(financeId(req.params.id), b.version, id, config.treasuryKey);
  });
  app.post('/api/staff/finance/journal', async (req) => {
    const id = await actor(req),
      b = exactKeys(req.body, ['entry', 'confirm']);
    assert(
      b.confirm === 'record verified source evidence',
      'finance_source_confirmation',
      'Confirm the actual source evidence; this action records accounting facts.',
    );
    return store.postFinanceEntry(b.entry, id, config.treasuryKey, clock());
  });
  app.post('/api/staff/finance/settlements', async (req) => {
    const id = await actor(req);
    return store.saveFinanceSettlement(req.body, id, clock());
  });
  app.post('/api/staff/finance/deposits', async (req) => {
    const id = await actor(req);
    return store.saveFinanceDeposit(req.body, id, clock());
  });
  app.post('/api/staff/finance/cases', async (req) => {
    const id = await actor(req);
    return store.saveFinanceCase(req.body, id, clock());
  });
  app.post('/api/staff/finance/cases/:id', async (req) => {
    const id = await actor(req);
    return store.advanceFinanceCase(financeId(req.params.id), req.body, id, clock(), config);
  });
  app.post('/api/staff/finance/commands/refund-test', async (req) => {
    const id = await actor(req);
    assert(
      config.treasurySandboxActions === true,
      'sandbox_actions_unavailable',
      'Stripe test actions are not enabled. Live financial actions are not installed.',
      503,
    );
    return store.executeFinanceRefund(req.body, id, config.stripeTestKey, clock(), transport);
  });
  app.post('/api/staff/finance/commands/:id/reconcile', async (req) => {
    const id = await actor(req);
    return store.reconcileFinanceCommand(financeId(req.params.id), req.body, id);
  });
  app.post('/api/staff/finance/export', async (req, reply) => {
    const id = await actor(req);
    assert(
      await store.rate('finance-report:' + id, 3, clock() + 3600000),
      'finance_export_rate',
      'Wait before exporting another bulk report.',
      429,
    );
    const result = await store.exportFinance(req.body, id, config.treasuryKey, clock());
    return reply
      .header('Cache-Control', 'private, no-store')
      .header(
        'Content-Disposition',
        'attachment; filename="galinsky-treasury-approved.' + req.body.format + '"',
      )
      .header('X-Export-Reference', result.reference)
      .header('X-Content-SHA256', result.digest)
      .type(
        req.body.format === 'csv' ? 'text/csv; charset=utf-8' : 'application/json; charset=utf-8',
      )
      .send(result.bytes);
  });
}
