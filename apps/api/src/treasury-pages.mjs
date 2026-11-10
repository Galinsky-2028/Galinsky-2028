import { assert, exactKeys } from '../../../packages/core/validation.mjs';
import { financeId } from '../../../packages/core/treasury-workflow.mjs';
export const financeCollections = [
  'gifts',
  'cases',
  'settlements',
  'deposits',
  'commands',
  'evidence',
  'journal',
  'unmatchedProviderEvents',
  'providerRemedyEvents',
];
const definitions = {
  gifts: { table: 'treasury_gifts', at: 'updated_at', value: 's.state' },
  cases: { table: 'treasury_cases', at: 'updated_at', value: 's.document' },
  settlements: {
    table: 'treasury_settlements',
    at: 'created_at',
    value:
      "s.document||jsonb_build_object('bankCents',COALESCE((SELECT sum((d.document->>'amountCents')::bigint) FROM g28.treasury_deposits d WHERE d.settlement_id=s.id),0)::text)",
  },
  deposits: { table: 'treasury_deposits', at: 'created_at', value: 's.document' },
  commands: {
    table: 'treasury_commands',
    at: 'updated_at',
    value:
      "jsonb_build_object('id',s.id,'case_id',s.case_id,'status',s.status,'provider_reference',s.provider_reference)",
  },
  evidence: {
    table: 'treasury_evidence',
    at: 'created_at',
    value: "jsonb_build_object('id',s.id,'digest',s.digest,'byte_count',s.byte_count)",
  },
  journal: {
    table: 'treasury_journal',
    at: 'posted_at',
    value:
      "jsonb_build_object('id',s.id,'gift_id',s.gift_id,'event_kind',s.event_kind,'source',s.source,'environment',s.environment,'external_reference',s.external_reference,'document',s.document)",
  },
};
export async function financePage(c, kind, after = null) {
  assert(
    financeCollections.includes(kind),
    'finance_collection',
    'Choose an available accounting collection.',
  );
  if (after !== null) {
    exactKeys(
      after,
      kind === 'unmatchedProviderEvents'
        ? ['at', 'provider', 'eventId']
        : kind === 'providerRemedyEvents'
          ? ['at', 'eventId']
          : ['at', 'id'],
    );
    assert(
      typeof after.at === 'string' &&
        /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/.test(after.at) &&
        Number.isFinite(Date.parse(after.at)) &&
        new Date(after.at).toISOString().slice(0, 19) === after.at.slice(0, 19),
      'finance_cursor',
      'Use the exact returned page cursor.',
    );
    if (['unmatchedProviderEvents', 'providerRemedyEvents'].includes(kind))
      assert(
        (kind !== 'unmatchedProviderEvents' || /^[a-zA-Z0-9_-]{1,128}$/.test(after.provider)) &&
          /^[a-zA-Z0-9_-]{1,150}$/.test(after.eventId),
        'finance_cursor',
        'Use an exact source-event cursor.',
      );
    else financeId(after.id);
  }
  let rows;
  if (kind === 'unmatchedProviderEvents')
    rows = (
      await c.query(
        "SELECT to_char(s.received_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS at,s.provider,s.event_id,jsonb_build_object('provider',s.provider,'event_id',s.event_id,'payment_id',s.payment_id,'event_kind',s.event_kind,'amount_cents',s.amount_cents,'occurred_at',s.occurred_at,'event_digest',s.event_digest) AS value FROM g28.financial_provider_events s WHERE NOT EXISTS(SELECT 1 FROM g28.treasury_journal j WHERE j.source=s.provider AND j.external_reference=s.event_id) AND ($1::timestamptz IS NULL OR (s.received_at,s.provider,s.event_id)<($1::timestamptz,$2::text,$3::text)) ORDER BY s.received_at DESC,s.provider DESC,s.event_id DESC LIMIT 101",
        [after?.at || null, after?.provider || null, after?.eventId || null],
      )
    ).rows;
  else if (kind === 'providerRemedyEvents')
    rows = (
      await c.query(
        "SELECT to_char(s.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS at,s.event_id,jsonb_build_object('provider',CASE WHEN s.livemode THEN 'stripe' ELSE 'stripe-test' END,'event_id',s.event_id,'provider_reference',s.provider_reference,'command_id',s.command_id,'payment_id',s.session_id,'event_kind',s.kind,'amount_cents',s.amount_cents,'occurred_at',s.occurred_at,'event_digest',s.event_sha256) AS value FROM g28.stripe_remedy_events s WHERE ($1::timestamptz IS NULL OR (s.occurred_at,s.event_id)<($1::timestamptz,$2::text)) ORDER BY s.occurred_at DESC,s.event_id DESC LIMIT 101",
        [after?.at || null, after?.eventId || null],
      )
    ).rows;
  else {
    const d = definitions[kind];
    rows = (
      await c.query(
        `SELECT s.id,to_char(s.${d.at} AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS at,${d.value} AS value FROM g28.${d.table} s WHERE ($1::timestamptz IS NULL OR (s.${d.at},s.id)<($1::timestamptz,$2::uuid)) ORDER BY s.${d.at} DESC,s.id DESC LIMIT 101`,
        [after?.at || null, after?.id || null],
      )
    ).rows;
  }
  const page = rows.slice(0, 100),
    last = page.at(-1),
    items = page.map((r) => {
      const v = r.value;
      if (kind === 'cases')
        return { ...v, overdue: v.status !== 'closed' && Date.parse(v.deadline) < Date.now() };
      if (kind === 'settlements')
        return {
          ...v,
          bankBalanced: v.balanced && BigInt(v.bankCents) === BigInt(v.computed.netCents),
        };
      return v;
    });
  return {
    items,
    next:
      rows.length > 100 && last
        ? {
            at: last.at,
            ...(kind === 'unmatchedProviderEvents'
              ? { provider: last.provider, eventId: last.event_id }
              : kind === 'providerRemedyEvents'
                ? { eventId: last.event_id }
                : { id: last.id }),
          }
        : null,
    notice:
      'Pages are ordered by source/update timestamp and exact reference. Concurrent changes may require refreshing the first page; writes always recheck the exact current version.',
  };
}
