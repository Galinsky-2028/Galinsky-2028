import { assert, exactKeys, safeText, email } from './validation.mjs';
export const financeId = (value) => {
  assert(
    typeof value === 'string' &&
      /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value),
    'invalid_finance_id',
    'Use an exact treasury record reference.',
  );
  return value;
};
const digest = (x) =>
  assert(
    typeof x === 'string' && /^[a-f0-9]{64}$/.test(x),
    'finance_evidence',
    'Record the SHA-256 digest of the actual source evidence.',
  );
const amount = (x) =>
  assert(
    Number.isSafeInteger(x) && x > 0 && x <= 100000000,
    'finance_amount',
    'Use positive integer US cents within the input range.',
  );
const date = (x) => {
  assert(
    typeof x === 'string' &&
      /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x) &&
      Number.isFinite(Date.parse(x)) &&
      new Date(x).toISOString() === x,
    'finance_date',
    'Use an exact ISO UTC date.',
  );
  return x;
};
export const exportFields = Object.freeze([
  'gift_id',
  'source',
  'external_reference',
  'environment',
  'donor_reference',
  'donor_name',
  'street',
  'city',
  'region',
  'postal',
  'country',
  'occupation',
  'employer',
  'election',
  'gross_cents',
  'refund_cents',
  'fee_cents',
  'chargeback_cents',
  'net_cents',
  'made_at',
  'received_at',
  'source_digest',
  'event_id',
  'event_kind',
  'amount_cents',
  'effect_cents',
  'event_received_at',
  'event_source_digest',
  'primary_allocated_cents',
  'general_allocated_cents',
  'target_election',
  'prior_donor_reference',
  'donor_intent_digest',
]);
export function treasuryPolicy(input, now = Date.now()) {
  const b = exactKeys(input, [
    'id',
    'version',
    'validUntil',
    'evidenceDigest',
    'remedyDays',
    'deadlineBasis',
    'followupDays',
    'maxFollowups',
    'electionLimits',
    'sources',
    'exportSystem',
  ]);
  financeId(b.id);
  date(b.validUntil);
  digest(b.evidenceDigest);
  assert(
    Number.isSafeInteger(b.version) &&
      b.version > 0 &&
      Date.parse(b.validUntil) > now &&
      Date.parse(b.validUntil) <= now + 366 * 86400000,
    'finance_policy',
    'Use a current approved, expiring policy version.',
  );
  assert(
    ['received_at', 'made_at', 'case_opened_at'].includes(b.deadlineBasis),
    'finance_deadline_basis',
    'Choose the actual approved date basis for legal remedy deadlines.',
  );
  assert(
    Number.isSafeInteger(b.remedyDays) &&
      b.remedyDays >= 1 &&
      b.remedyDays <= 180 &&
      Number.isSafeInteger(b.followupDays) &&
      b.followupDays >= 1 &&
      b.followupDays <= 30 &&
      Number.isSafeInteger(b.maxFollowups) &&
      b.maxFollowups >= 1 &&
      b.maxFollowups <= 6,
    'finance_deadlines',
    'Record the approved bounded remedy/follow-up rules.',
  );
  exactKeys(b.electionLimits, ['primary', 'general']);
  amount(b.electionLimits.primary);
  amount(b.electionLimits.general);
  assert(
    Array.isArray(b.sources) && b.sources.length >= 1 && b.sources.length <= 20,
    'finance_sources',
    'Configure the approved contribution sources.',
  );
  const sources = b.sources.map((s) => {
    exactKeys(s, ['id', 'channel', 'environment']);
    assert(
      typeof s.id === 'string' &&
        /^[a-z][a-z0-9_-]{1,60}$/.test(s.id) &&
        !/(?:chase|wepay|paymentech)/i.test(s.id) &&
        ['card', 'cash', 'check', 'in_kind', 'other'].includes(s.channel) &&
        ['test', 'live'].includes(s.environment),
      'finance_source',
      'Use an approved independent source and explicit environment.',
    );
    assert(
      s.channel !== 'card' || s.id === (s.environment === 'test' ? 'stripe-test' : 'stripe'),
      'unsupported_finance_provider',
      'Only the implemented Stripe adapter may verify card source events.',
    );
    return { ...s };
  });
  assert(
    new Set(sources.map((s) => s.id)).size === sources.length,
    'finance_sources',
    'Source IDs must be unique.',
  );
  const mapping = exactKeys(b.exportSystem, ['id', 'columns', 'evidenceDigest']);
  digest(mapping.evidenceDigest);
  assert(
    typeof mapping.id === 'string' &&
      /^[a-zA-Z0-9_-]{2,80}$/.test(mapping.id) &&
      Array.isArray(mapping.columns) &&
      mapping.columns.length >= 8 &&
      mapping.columns.length <= exportFields.length,
    'finance_export_mapping',
    'Configure the actually approved accounting/import schema.',
  );
  const columns = mapping.columns.map((c) => {
    exactKeys(c, ['field', 'header']);
    assert(
      exportFields.includes(c.field) &&
        typeof c.header === 'string' &&
        /^[a-zA-Z][a-zA-Z0-9_ ]{0,60}$/.test(c.header),
      'finance_export_mapping',
      'Use declared fields and safe unique column headings.',
    );
    return { ...c };
  });
  assert(
    new Set(columns.map((c) => c.field)).size === columns.length &&
      new Set(columns.map((c) => c.header)).size === columns.length &&
      [
        'event_id',
        'event_kind',
        'gift_id',
        'source',
        'environment',
        'donor_reference',
        'election',
        'amount_cents',
        'effect_cents',
        'event_received_at',
      ].every((f) => columns.some((c) => c.field === f)),
    'finance_export_mapping',
    'Required reconciliation fields and unique headers are mandatory.',
  );
  return { ...b, sources, exportSystem: { ...mapping, columns } };
}
export function treasuryDonor(input) {
  const b = exactKeys(input, [
    'id',
    'name',
    'street',
    'city',
    'region',
    'postal',
    'country',
    'occupation',
    'employer',
    'email',
    'evidenceDigest',
  ]);
  financeId(b.id);
  digest(b.evidenceDigest);
  for (const k of ['name', 'street', 'city', 'region', 'postal', 'country'])
    assert(
      typeof b[k] === 'string' &&
        safeText(b[k], k === 'street' ? 240 : 140).trim().length > 0 &&
        !/[\r\n\x00-\x1f]/.test(b[k]),
      'finance_donor',
      'Enter the documented contributor identity and mailing address.',
    );
  for (const k of ['occupation', 'employer'])
    assert(
      b[k] === null ||
        (typeof b[k] === 'string' &&
          safeText(b[k], 140).trim().length > 0 &&
          !/[\r\n\x00-\x1f]/.test(b[k])),
      'finance_donor',
      'Supply documented occupation/employer or leave explicitly missing for follow-up.',
    );
  assert(
    b.email === null || email(b.email) === b.email,
    'finance_contact',
    'Use the documented contributor email or explicitly leave it absent.',
  );
  return { ...b };
}
export function treasuryEntry(input, policy, now = Date.now()) {
  const b = exactKeys(input, [
    'id',
    'kind',
    'giftId',
    'source',
    'externalReference',
    'environment',
    'amountCents',
    'donorId',
    'election',
    'targetElection',
    'madeAt',
    'receivedAt',
    'evidenceDigest',
    'intentDigest',
    'outcome',
  ]);
  financeId(b.id);
  financeId(b.giftId);
  digest(b.evidenceDigest);
  amount(b.amountCents);
  date(b.madeAt);
  date(b.receivedAt);
  assert(
    Date.parse(policy.validUntil) > now &&
      Date.parse(b.madeAt) <= Date.parse(b.receivedAt) &&
      Date.parse(b.receivedAt) <= now + 60000,
    'finance_policy',
    'Use the current ruleset and actual made/received dates.',
  );
  const source = policy.sources.find((s) => s.id === b.source && s.environment === b.environment);
  assert(
    source,
    'finance_source',
    'This source/environment is not approved in the current ruleset.',
  );
  assert(
    typeof b.externalReference === 'string' &&
      /^[a-zA-Z0-9_-]{1,128}$/.test(b.externalReference) &&
      [
        'gift',
        'refund',
        'fee',
        'dispute',
        'dispute_closed',
        'redesignation',
        'reattribution',
        'correction',
      ].includes(b.kind),
    'finance_entry',
    'Choose a supported event and immutable source reference.',
  );
  assert(
    ['primary', 'general'].includes(b.election),
    'finance_election',
    'Choose an approved election.',
  );
  if (b.kind === 'gift' || b.kind === 'reattribution') financeId(b.donorId);
  else
    assert(
      b.donorId === null,
      'finance_entry',
      'Donor changes require an explicit reattribution event.',
    );
  if (b.kind === 'redesignation') {
    assert(
      ['primary', 'general'].includes(b.targetElection) && b.targetElection !== b.election,
      'finance_election',
      'Choose a different permitted election.',
    );
    digest(b.intentDigest);
  } else assert(b.targetElection === null, 'finance_entry', 'Unexpected election reallocation.');
  if (b.kind === 'reattribution') digest(b.intentDigest);
  else if (b.kind !== 'redesignation')
    assert(b.intentDigest === null, 'finance_entry', 'Unexpected donor-intent reference.');
  if (b.kind === 'dispute_closed')
    assert(
      ['won', 'lost'].includes(b.outcome),
      'finance_dispute',
      'Record the authenticated final dispute outcome.',
    );
  else if (b.kind === 'correction')
    assert(
      source.channel !== 'card' && ['increase', 'decrease'].includes(b.outcome),
      'finance_correction',
      'Only a documented manual-channel accounting correction is supported. Signed provider facts cannot be overwritten.',
    );
  else assert(b.outcome === null, 'finance_entry', 'Unexpected dispute outcome.');
  return { ...b, policyId: policy.id, channel: source.channel };
}
export function projectTreasury(previous, event) {
  if (event.kind === 'gift') {
    assert(
      !previous && event.id === event.giftId,
      'finance_duplicate_gift',
      'A gift needs its own new immutable reference.',
      409,
    );
    return {
      id: event.giftId,
      donorId: event.donorId,
      source: event.source,
      environment: event.environment,
      grossCents: event.amountCents,
      refundedCents: 0,
      feeCents: 0,
      chargebackCents: 0,
      disputedCents: 0,
      allocations: { primary: 0, general: 0, [event.election]: event.amountCents },
      madeAt: event.madeAt,
      receivedAt: event.receivedAt,
      evidenceDigest: event.evidenceDigest,
      externalReference: event.externalReference,
      version: 1,
    };
  }
  assert(
    previous &&
      previous.id === event.giftId &&
      previous.source === event.source &&
      previous.environment === event.environment,
    'finance_gift_mismatch',
    'The event does not match the original gift/source.',
    409,
  );
  const s = structuredClone(previous),
    n = event.amountCents,
    available = s.grossCents - s.refundedCents - s.chargebackCents;
  if (event.kind === 'refund') {
    assert(
      !s.disputedCents && n <= available && n <= s.allocations[event.election],
      'finance_refund',
      'A refund cannot exceed the unrefunded election allocation or overlap a dispute.',
      409,
    );
    s.refundedCents += n;
    s.allocations[event.election] -= n;
  }
  if (event.kind === 'fee') s.feeCents += n;
  if (event.kind === 'correction') {
    assert(
      event.channel !== 'card' &&
        !s.disputedCents &&
        (event.outcome === 'increase' || n <= s.allocations[event.election]),
      'finance_correction',
      'A manual accounting correction cannot overwrite provider facts, overlap a dispute or consume unavailable funds.',
      409,
    );
    const delta = event.outcome === 'increase' ? n : -n;
    s.grossCents += delta;
    s.allocations[event.election] += delta;
    s.corrected = true;
  }
  if (event.kind === 'dispute') {
    assert(
      !s.disputedCents && n <= available && n <= s.allocations[event.election],
      'finance_dispute',
      'This dispute overlaps an existing dispute or exceeds the remaining allocation.',
      409,
    );
    s.disputedCents = n;
    s.disputeElection = event.election;
  }
  if (event.kind === 'dispute_closed') {
    assert(
      s.disputedCents === n && s.disputeElection === event.election,
      'finance_dispute',
      'The final dispute must match the open source dispute.',
      409,
    );
    if (event.outcome === 'lost') {
      s.chargebackCents += n;
      s.allocations[event.election] -= n;
    }
    s.disputedCents = 0;
    delete s.disputeElection;
  }
  if (event.kind === 'redesignation') {
    assert(
      !s.disputedCents && n <= s.allocations[event.election],
      'finance_designation',
      'Reallocation requires sufficient undisputed funds and documented donor intent.',
      409,
    );
    s.allocations[event.election] -= n;
    s.allocations[event.targetElection] += n;
  }
  if (event.kind === 'reattribution') {
    assert(
      !s.disputedCents && n === available,
      'finance_reattribution',
      'Reattribution must explicitly cover the whole remaining gift and documented donor intent.',
      409,
    );
    s.donorId = event.donorId;
  }
  s.version++;
  assert(
    [
      s.grossCents,
      s.refundedCents,
      s.feeCents,
      s.chargebackCents,
      ...Object.values(s.allocations),
    ].every(Number.isSafeInteger),
    'finance_overflow',
    'The projection exceeds safe integer precision.',
    409,
  );
  return s;
}
export const treasuryNet = (s) => s.grossCents - s.refundedCents - s.chargebackCents - s.feeCents;
export function settlementDocument(input, events) {
  const b = exactKeys(input, [
    'id',
    'source',
    'environment',
    'externalReference',
    'entryIds',
    'grossCents',
    'refundCents',
    'feeCents',
    'chargebackCents',
    'netCents',
    'settledAt',
    'evidenceDigest',
  ]);
  financeId(b.id);
  date(b.settledAt);
  digest(b.evidenceDigest);
  assert(
    typeof b.externalReference === 'string' &&
      /^[a-zA-Z0-9_-]{1,128}$/.test(b.externalReference) &&
      Array.isArray(b.entryIds) &&
      b.entryIds.length >= 1 &&
      b.entryIds.length <= 1000 &&
      new Set(b.entryIds).size === b.entryIds.length,
    'finance_settlement',
    'Choose unique source entries and a verified settlement reference.',
  );
  b.entryIds.forEach(financeId);
  assert(
    events.length === b.entryIds.length &&
      events.every(
        (e) =>
          b.entryIds.includes(e.id) &&
          e.source === b.source &&
          e.environment === b.environment &&
          ['gift', 'refund', 'fee', 'dispute_closed', 'correction'].includes(e.kind),
      ),
    'finance_settlement',
    'Settlement entries must belong to the exact source/environment and have settled monetary effects. Disputes require resolution first.',
    409,
  );
  const totals = { grossCents: 0, refundCents: 0, feeCents: 0, chargebackCents: 0 };
  for (const e of events) {
    if (e.kind === 'correction')
      totals.grossCents += e.outcome === 'increase' ? e.amountCents : -e.amountCents;
    else if (e.kind === 'dispute_closed') {
      if (e.outcome === 'lost') totals.chargebackCents += e.amountCents;
    } else
      totals[e.kind === 'gift' ? 'grossCents' : e.kind === 'refund' ? 'refundCents' : 'feeCents'] +=
        e.amountCents;
  }
  const net = totals.grossCents - totals.refundCents - totals.feeCents - totals.chargebackCents;
  assert(
    Object.values(totals).every(Number.isSafeInteger) &&
      ['grossCents', 'refundCents', 'feeCents', 'chargebackCents', 'netCents'].every((k) =>
        Number.isSafeInteger(b[k]),
      ),
    'finance_settlement',
    'Use exact safe integer settlement amounts.',
  );
  return {
    ...b,
    computed: { ...totals, netCents: net },
    balanced:
      totals.grossCents === b.grossCents &&
      totals.refundCents === b.refundCents &&
      totals.feeCents === b.feeCents &&
      totals.chargebackCents === b.chargebackCents &&
      net === b.netCents,
  };
}
export function financeCase(input, policy, now = Date.now(), giftDates = {}) {
  const b = exactKeys(input, ['id', 'giftId', 'kind', 'evidenceDigest']);
  financeId(b.id);
  financeId(b.giftId);
  digest(b.evidenceDigest);
  assert(
    [
      'suspect_source',
      'prohibited_source',
      'accounting_correction',
      'excess',
      'missing_information',
      'refund',
      'dispute',
      'redesignation',
      'reattribution',
      'cancellation',
      'settlement_mismatch',
    ].includes(b.kind),
    'finance_case',
    'Choose a supported finance exception.',
  );
  const anchor =
    policy.deadlineBasis === 'case_opened_at'
      ? now
      : Date.parse(giftDates[policy.deadlineBasis === 'received_at' ? 'receivedAt' : 'madeAt']);
  assert(
    Number.isFinite(anchor) && anchor <= now + 60000,
    'finance_deadline_basis',
    'The documented original made/received date is required for this case deadline.',
  );
  return {
    ...b,
    policyId: policy.id,
    deadlineBasis: policy.deadlineBasis,
    anchorAt: new Date(anchor).toISOString(),
    status: 'open',
    version: 1,
    followups: 0,
    maxFollowups: policy.maxFollowups,
    followupDays: policy.followupDays,
    nextFollowupAt: new Date(anchor).toISOString(),
    deadline: new Date(anchor + policy.remedyDays * 86400000).toISOString(),
    history: [],
  };
}
export function advanceFinanceCase(previous, input, now = Date.now()) {
  const b = exactKeys(input, ['version', 'action', 'evidenceDigest', 'occurredAt']);
  digest(b.evidenceDigest);
  assert(
    previous.version === b.version && previous.status !== 'closed',
    'stale_finance_case',
    'Reload the current open case.',
    409,
  );
  assert(
    ['followup', 'notify', 'review', 'close'].includes(b.action),
    'finance_case_action',
    'Choose a supported case action.',
  );
  const s = structuredClone(previous);
  const when = b.action === 'followup' && b.occurredAt ? Date.parse(date(b.occurredAt)) : now;
  assert(
    when <= now &&
      (['followup'].includes(b.action) || b.occurredAt === undefined || b.occurredAt === null),
    'finance_contact_date',
    'Only an actual documented manual contact may be backdated.',
  );
  if (['followup', 'notify'].includes(b.action)) {
    assert(
      s.followups < s.maxFollowups &&
        Date.parse(s.nextFollowupAt) <= when &&
        when <= Date.parse(s.deadline),
      'finance_followup',
      'The approved follow-up bound, interval or deadline prevents another contact.',
      409,
    );
    s.followups++;
    s.nextFollowupAt = new Date(when + s.followupDays * 86400000).toISOString();
  }
  s.status = b.action === 'close' ? 'closed' : b.action === 'review' ? 'under_review' : s.status;
  s.version++;
  s.history.push({
    action: b.action,
    evidenceDigest: b.evidenceDigest,
    at: new Date(now).toISOString(),
    occurredAt: new Date(when).toISOString(),
  });
  return s;
}
