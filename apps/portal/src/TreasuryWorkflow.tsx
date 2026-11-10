import React, { useEffect, useState, FormEvent } from 'react';
import { request } from './api';
import { exportFields } from '../../../packages/core/treasury-workflow.mjs';
type Source = { id: string; channel: string; environment: string };
type Policy = {
  id: string;
  version: number;
  validUntil: string;
  evidenceDigest: string;
  remedyDays: number;
  deadlineBasis: string;
  followupDays: number;
  maxFollowups: number;
  electionLimits: { primary: number; general: number };
  sources: Source[];
  exportSystem: {
    id: string;
    columns: { field: string; header: string }[];
    evidenceDigest: string;
  };
};
type Gift = {
  id: string;
  donorId: string;
  donorVersion: number;
  source: string;
  environment: string;
  grossCents: number;
  refundedCents: number;
  feeCents: number;
  chargebackCents: number;
  disputedCents: number;
  allocations: { primary: number; general: number };
  providerPaymentId: string | null;
  version: number;
};
type Case = {
  id: string;
  giftId: string;
  kind: string;
  status: string;
  version: number;
  followups: number;
  maxFollowups: number;
  deadline: string;
  nextFollowupAt: string;
  overdue: boolean;
};
type Event = {
  provider: string;
  event_id: string;
  payment_id: string;
  event_kind: string;
  amount_cents: number;
  occurred_at: string;
  event_digest: string;
  outcome?: string;
};
type Overview = {
  policy: Policy | null;
  gifts: Gift[];
  cases: Case[];
  settlements: {
    id: string;
    source: string;
    environment: string;
    netCents: number;
    bankCents: string;
    balanced: boolean;
    bankBalanced: boolean;
  }[];
  deposits: {
    id: string;
    settlementId: string;
    bankReference: string;
    amountCents: number;
    receivedAt: string;
    evidenceDigest: string;
  }[];
  commands: { id: string; case_id: string; status: string; provider_reference: string | null }[];
  evidence: { id: string; digest: string; byte_count: number }[];
  journal: {
    id: string;
    gift_id: string;
    source: string;
    environment: string;
    event_kind: string;
    external_reference: string;
  }[];
  unmatchedProviderEvents: Event[];
  providerRemedyEvents: (Event & { provider_reference: string; command_id: string | null })[];
  sandboxActions: boolean;
  notice: string;
  pages: Record<string, unknown>;
};
const value = (d: FormData, name: string) => String(d.get(name) || '');
const utc = (d: FormData, name: string) => new Date(value(d, name) + 'Z').toISOString();
const stamp = (date: string) => new Date(date).toISOString().slice(0, -1);
const amount = (s: string) => {
  if (!/^-?\d+(?:\.\d{1,2})?$/.test(s))
    throw Error('Enter an exact dollar amount with at most two decimal places.');
  const [a, b = ''] = s.replace('-', '').split('.'),
    n = Number(BigInt(a) * 100n + BigInt(b.padEnd(2, '0'))) * (s.startsWith('-') ? -1 : 1);
  if (!Number.isSafeInteger(n)) throw Error('Amount is outside the supported input range.');
  return n;
};
const money = (n: number) => '$' + (n / 100).toFixed(2);
function Evidence({
  items,
  name = 'evidenceDigest',
  label = 'Documentary evidence',
}: {
  items: Overview['evidence'];
  name?: string;
  label?: string;
}) {
  return (
    <label>
      {label}
      <select required name={name}>
        <option value="">Choose an uploaded source</option>
        {items.map((e) => (
          <option key={e.id} value={e.digest}>
            {e.id.slice(0, 8)} · {e.byte_count} bytes · {e.digest.slice(0, 12)}
          </option>
        ))}
      </select>
    </label>
  );
}
function Input({
  label,
  name,
  type = 'text',
  required = true,
  initial = '',
  ...rest
}: {
  label: string;
  name: string;
  type?: string;
  required?: boolean;
  initial?: string | number;
  [key: string]: unknown;
}) {
  return (
    <label>
      {label}
      <input name={name} type={type} required={required} defaultValue={initial} {...rest} />
    </label>
  );
}
export function TreasuryWorkflow({ csrf }: { csrf: string }) {
  const [collection, setCollection] = useState<
    | 'gifts'
    | 'cases'
    | 'settlements'
    | 'deposits'
    | 'commands'
    | 'evidence'
    | 'journal'
    | 'unmatchedProviderEvents'
    | 'providerRemedyEvents'
  >('gifts');
  const [data, setData] = useState<Overview | null>(null),
    [error, setError] = useState(''),
    [message, setMessage] = useState(''),
    [busy, setBusy] = useState(false),
    [kind, setKind] = useState('gift'),
    [selected, setSelected] = useState<Event | null>(null),
    [giftId, setGiftId] = useState(''),
    [sources, setSources] = useState<Source[]>([]);
  async function refresh() {
    const next = await request<Overview>('/api/staff/finance/overview', {}, csrf);
    setData(next);
    setSources(next.policy?.sources || [{ id: '', channel: 'cash', environment: 'test' }]);
  }
  useEffect(() => {
    void refresh().catch((e) => setError(e.message));
  }, []);
  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError('');
    setMessage('');
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function post(path: string, payload: unknown, notice: string) {
    await request('/api/staff/finance/' + path, payload, csrf);
    setMessage(notice);
    await refresh();
  }
  async function download(path: string, payload: unknown, filename: string) {
    const response = await fetch('/api/staff/finance/' + path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const failure = await response.json();
      throw Error(failure.message || 'Download failed.');
    }
    const url = URL.createObjectURL(await response.blob()),
      a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setMessage(
      'Private file downloaded. Audit/digest: ' +
        (response.headers.get('X-Export-Reference') ||
          response.headers.get('X-Content-SHA256') ||
          'recorded'),
    );
  }
  function form(handler: (data: FormData) => Promise<void>) {
    return (e: FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      const d = new FormData(e.currentTarget);
      void run(() => handler(d));
    };
  }
  const currentGift = data?.gifts.find((g) => g.id === giftId),
    p = data?.policy;
  return (
    <section className="spaced">
      <span className="eyebrow">RECONCILIATION & CASEWORK</span>
      <h2>Campaign accounting.</h2>
      <p>
        Record actual source evidence, resolve exceptions and reconcile provider payouts to bank
        records. No live payment, refund, bank transfer or filing is initiated here. Stripe actions,
        when explicitly configured, are test-only.
      </p>
      {error && (
        <p className="notice error" role="alert">
          {error}
        </p>
      )}
      {message && (
        <p className="notice" role="status">
          {message}
        </p>
      )}
      {data && (
        <>
          <p className="fine">{data.notice}</p>
          <button className="btn outline" disabled={busy} onClick={() => void run(refresh)}>
            Refresh accounting records
          </button>
          <div className="panel spaced">
            <label>
              More accounting records
              <select
                value={collection}
                onChange={(e) => setCollection(e.target.value as typeof collection)}
              >
                {Object.keys(data.pages).map((k) => (
                  <option key={k} value={k}>
                    {k.replaceAll('_', ' ')}
                  </option>
                ))}
              </select>
            </label>
            <button
              className="btn outline"
              disabled={busy || !data.pages[collection]}
              onClick={() =>
                void run(async () => {
                  const result = await request<{ items: unknown[]; next: unknown }>(
                    '/api/staff/finance/page',
                    { collection, after: data.pages[collection] },
                    csrf,
                  );
                  setData({
                    ...data,
                    [collection]: [...data[collection], ...result.items],
                    pages: { ...data.pages, [collection]: result.next },
                  });
                  setMessage(
                    'Additional records loaded. Refresh restarts the page view if records changed.',
                  );
                })
              }
            >
              Load next page of selected records
            </button>
          </div>
          <details className="panel spaced">
            <summary>
              <strong>Private source documents</strong>
            </summary>
            <p>
              Upload actual approval, source, bank or donor-intent documents. Files are encrypted at
              rest and available only through audited finance downloads. Do not upload card numbers,
              bank login secrets or private volunteer reports. Review downloaded files locally.
            </p>
            <form
              autoComplete="off"
              className="admin-fields"
              onSubmit={form(async (d) => {
                const file = d.get('file') as File;
                if (!file?.size || file.size > 150000)
                  throw Error('Choose a PDF, plain-text or CSV source below 150 KB.');
                const bytes = new Uint8Array(await file.arrayBuffer()),
                  content = btoa(Array.from(bytes, (x) => String.fromCharCode(x)).join(''));
                const saved = await request<{ id: string; digest: string }>(
                  '/api/staff/finance/evidence',
                  {
                    id: crypto.randomUUID(),
                    filename: file.name,
                    mediaType: file.type || 'text/plain',
                    content,
                  },
                  csrf,
                );
                setMessage(
                  'Private evidence stored. Reference ' + saved.id + ' · SHA-256 ' + saved.digest,
                );
                await refresh();
              })}
            >
              <label>
                Document (150 KB maximum)
                <input
                  name="file"
                  type="file"
                  accept="application/pdf,text/plain,text/csv"
                  required
                />
              </label>
              <button className="btn" disabled={busy}>
                Store private source document
              </button>
            </form>
            <ul>
              {data.evidence.map((e) => (
                <li key={e.id} style={{ overflowWrap: 'anywhere' }}>
                  {e.id} · {e.digest}
                  <button
                    className="text-button"
                    disabled={busy}
                    onClick={() =>
                      void run(() =>
                        download(
                          'evidence/' + e.id + '/read',
                          {},
                          'private-evidence-' + e.id + '.bin',
                        ),
                      )
                    }
                  >
                    Download for local review
                  </button>
                </li>
              ))}
            </ul>
          </details>
          <details className="panel spaced" open={!p}>
            <summary>
              <strong>Treasurer-approved rules and accounting mapping</strong>
            </summary>
            <p>
              Enter actual approved rules; this software does not determine legal deadlines or
              contribution limits. Each save creates an immutable next version. Use the actual
              accounting system and its reviewed column mapping.
            </p>
            <form
              autoComplete="off"
              className="admin-fields"
              onSubmit={form(async (d) => {
                const columns = exportFields
                  .filter((f: string) => d.get('include_' + f) === 'on')
                  .map((field: string) => ({ field, header: value(d, 'header_' + field) }));
                await post(
                  'policies',
                  {
                    policy: {
                      id: crypto.randomUUID(),
                      version: (p?.version || 0) + 1,
                      validUntil: utc(d, 'validUntil'),
                      evidenceDigest: value(d, 'evidenceDigest'),
                      remedyDays: Number(value(d, 'remedyDays')),
                      deadlineBasis: value(d, 'deadlineBasis'),
                      followupDays: Number(value(d, 'followupDays')),
                      maxFollowups: Number(value(d, 'maxFollowups')),
                      electionLimits: {
                        primary: amount(value(d, 'primary')),
                        general: amount(value(d, 'general')),
                      },
                      sources,
                      exportSystem: {
                        id: value(d, 'system'),
                        columns,
                        evidenceDigest: value(d, 'mappingEvidence'),
                      },
                    },
                    confirm: value(d, 'confirm'),
                  },
                  'Approved rules saved as an immutable new version.',
                );
              })}
            >
              <Input
                label="Rules valid until (UTC)"
                name="validUntil"
                type="datetime-local"
                step="0.001"
                initial={p ? stamp(p.validUntil) : ''}
              />
              <Evidence items={data.evidence} label="Approved rules evidence" />
              <Input
                label="Primary election aggregate limit (USD)"
                name="primary"
                inputMode="decimal"
                initial={p ? (p.electionLimits.primary / 100).toFixed(2) : ''}
              />
              <Input
                label="General election aggregate limit (USD)"
                name="general"
                inputMode="decimal"
                initial={p ? (p.electionLimits.general / 100).toFixed(2) : ''}
              />
              <label>
                Approved deadline runs from
                <select required name="deadlineBasis" defaultValue={p?.deadlineBasis || ''}>
                  <option value="">Choose the actual approved basis</option>
                  <option value="received_at">Original contribution receipt date</option>
                  <option value="made_at">Original contribution made date</option>
                  <option value="case_opened_at">
                    Case-opened date (only if the approved rule specifies this)
                  </option>
                </select>
              </label>
              <Input
                label="Approved remedy deadline (days)"
                name="remedyDays"
                type="number"
                min={1}
                max={180}
                initial={p?.remedyDays || ''}
              />
              <Input
                label="Minimum follow-up interval (days)"
                name="followupDays"
                type="number"
                min={1}
                max={30}
                initial={p?.followupDays || ''}
              />
              <Input
                label="Maximum follow-ups"
                name="maxFollowups"
                type="number"
                min={1}
                max={6}
                initial={p?.maxFollowups || ''}
              />
              <fieldset>
                <legend>Approved source channels</legend>
                <p className="fine">
                  Card sources use stripe-test or stripe. Other identifiers describe actual approved
                  manual channels. Test and live observations stay separate.
                </p>
                {sources.map((s, i) => (
                  <div className="panel spaced" key={i}>
                    <label>
                      Source identifier
                      <input
                        required
                        value={s.id}
                        onChange={(e) =>
                          setSources(
                            sources.map((x, j) => (j === i ? { ...x, id: e.target.value } : x)),
                          )
                        }
                      />
                    </label>
                    <label>
                      Channel
                      <select
                        value={s.channel}
                        onChange={(e) =>
                          setSources(
                            sources.map((x, j) =>
                              j === i ? { ...x, channel: e.target.value } : x,
                            ),
                          )
                        }
                      >
                        {['cash', 'check', 'in_kind', 'card', 'other'].map((c) => (
                          <option key={c}>{c}</option>
                        ))}
                      </select>
                    </label>
                    <label>
                      Environment
                      <select
                        value={s.environment}
                        onChange={(e) =>
                          setSources(
                            sources.map((x, j) =>
                              j === i ? { ...x, environment: e.target.value } : x,
                            ),
                          )
                        }
                      >
                        <option>test</option>
                        <option>live</option>
                      </select>
                    </label>
                    <button
                      type="button"
                      className="text-button"
                      onClick={() => setSources(sources.filter((_, j) => j !== i))}
                    >
                      Remove source from next ruleset
                    </button>
                  </div>
                ))}
                <button
                  className="btn outline"
                  type="button"
                  disabled={sources.length >= 20}
                  onClick={() =>
                    setSources([...sources, { id: '', channel: 'cash', environment: 'test' }])
                  }
                >
                  Add source channel
                </button>
              </fieldset>
              <Input
                label="Actual accounting/import system identifier"
                name="system"
                initial={p?.exportSystem.id || ''}
              />
              <Evidence
                items={data.evidence}
                name="mappingEvidence"
                label="Approved accounting mapping evidence"
              />
              <details>
                <summary>Review export columns</summary>
                {exportFields.map((f: string) => (
                  <div key={f}>
                    <label>
                      <input
                        name={'include_' + f}
                        type="checkbox"
                        defaultChecked={!p || p.exportSystem.columns.some((c) => c.field === f)}
                      />{' '}
                      Include {f.replaceAll('_', ' ')}
                    </label>
                    <Input
                      label={'Accounting heading for ' + f.replaceAll('_', ' ')}
                      name={'header_' + f}
                      initial={p?.exportSystem.columns.find((c) => c.field === f)?.header || f}
                    />
                  </div>
                ))}
              </details>
              <Input
                label="Type “approve these treasury rules”"
                name="confirm"
                pattern="approve these treasury rules"
              />
              <button className="btn" disabled={busy}>
                Approve and save next rules version
              </button>
            </form>
          </details>
          <details className="panel spaced">
            <summary>
              <strong>Source-verified contributor identity</strong>
            </summary>
            <p>
              Keep contributor identities separate unless documentary evidence establishes the same
              person. Name or email alone never merges people. Historical gifts retain their exact
              identity revision. Donor and volunteer accounts are independent.
            </p>
            <form
              autoComplete="off"
              className="admin-fields"
              onSubmit={form(async (d) => {
                const id = value(d, 'id') || crypto.randomUUID(),
                  result = await request<{ version: number }>(
                    '/api/staff/finance/donors',
                    {
                      expectedVersion: Number(value(d, 'version') || 0),
                      donor: {
                        id,
                        name: value(d, 'name'),
                        street: value(d, 'street'),
                        city: value(d, 'city'),
                        region: value(d, 'region'),
                        postal: value(d, 'postal'),
                        country: value(d, 'country'),
                        occupation: value(d, 'occupation') || null,
                        employer: value(d, 'employer') || null,
                        email: value(d, 'email') || null,
                        evidenceDigest: value(d, 'evidenceDigest'),
                      },
                    },
                    csrf,
                  );
                setMessage(
                  'Contributor reference ' +
                    id +
                    ' · revision ' +
                    result.version +
                    '. No automatic identity match was made.',
                );
                await refresh();
              })}
            >
              <Input
                label="Existing contributor reference (leave empty for a distinct person)"
                name="id"
                required={false}
              />
              <Input
                label="Expected current revision (0 for a new person)"
                name="version"
                type="number"
                min={0}
                initial="0"
              />
              {[
                'name',
                'street',
                'city',
                'region',
                'postal',
                'country',
                'occupation',
                'employer',
                'email',
              ].map((field) => (
                <Input
                  key={field}
                  label={
                    field === 'name'
                      ? 'Documented legal name'
                      : field === 'occupation' || field === 'employer'
                        ? field + ' (leave empty for documented follow-up)'
                        : field
                  }
                  name={field}
                  required={!['occupation', 'employer', 'email'].includes(field)}
                  maxLength={field === 'street' ? 240 : 140}
                />
              ))}
              <Evidence items={data.evidence} label="Contributor identity source" />
              <button className="btn" disabled={busy}>
                Save verified contributor revision
              </button>
            </form>
            <form
              autoComplete="off"
              className="admin-fields spaced"
              onSubmit={form(async (d) => {
                const result = await request<{
                  donor: Record<string, string | null>;
                  version: number;
                }>(
                  '/api/staff/finance/donors/' + encodeURIComponent(value(d, 'lookupId')) + '/read',
                  { version: Number(value(d, 'lookupVersion')) },
                  csrf,
                );
                setMessage(
                  Object.entries(result.donor)
                    .filter(([k]) => !['evidenceDigest', 'id'].includes(k))
                    .map(([k, v]) => k + ': ' + (v || 'missing'))
                    .join(' · '),
                );
              })}
            >
              <Input label="Contributor reference to inspect" name="lookupId" />
              <Input
                label="Exact contributor revision"
                name="lookupVersion"
                type="number"
                min={1}
              />
              <button className="btn outline" disabled={busy}>
                Open authorized contributor details
              </button>
            </form>
          </details>
          <section className="panel spaced">
            <h3>Unreconciled provider events</h3>
            {data.unmatchedProviderEvents.length === 0 ? (
              <p>No unmatched signed source effects in this view.</p>
            ) : (
              <ul>
                {data.unmatchedProviderEvents.map((e) => (
                  <li key={e.provider + e.event_id} style={{ overflowWrap: 'anywhere' }}>
                    {e.provider} · {e.event_kind} · {money(Number(e.amount_cents))} · {e.event_id}
                    <button
                      className="text-button"
                      onClick={() => {
                        setSelected(e);
                        setKind(
                          e.event_kind === 'captured'
                            ? 'gift'
                            : e.event_kind === 'disputed'
                              ? 'dispute'
                              : 'refund',
                        );
                        setGiftId(
                          data.gifts.find((g) => g.providerPaymentId === e.payment_id)?.id || '',
                        );
                      }}
                    >
                      Use exact source for journal entry
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section className="panel spaced">
            <h3>Signed provider remedy receipts</h3>
            <p>
              Pending and failed refunds remain distinct from monetary effects. Final dispute
              outcomes must use the exact authenticated source below.
            </p>
            <ul>
              {data.providerRemedyEvents.map((e) => (
                <li key={e.event_id} style={{ overflowWrap: 'anywhere' }}>
                  {e.provider} · {e.event_kind.replaceAll('_', ' ')} ·{' '}
                  {money(Number(e.amount_cents))} · Receipt {e.event_id} · Provider remedy{' '}
                  {e.provider_reference} · Command {e.command_id || 'none'}
                  {['dispute_won', 'chargeback'].includes(e.event_kind) && (
                    <button
                      className="text-button"
                      onClick={() => {
                        setSelected({
                          ...e,
                          event_kind: 'dispute_closed',
                          outcome: e.event_kind === 'dispute_won' ? 'won' : 'lost',
                        });
                        setKind('dispute_closed');
                        setGiftId(
                          data.gifts.find((g) => g.providerPaymentId === e.payment_id)?.id || '',
                        );
                      }}
                    >
                      Use authenticated final dispute outcome
                    </button>
                  )}
                </li>
              ))}
            </ul>
          </section>
          <details className="panel spaced" open={Boolean(selected)}>
            <summary>
              <strong>Append a financial source event</strong>
            </summary>
            <p>
              Record actual source effects; this form never initiates a charge, refund or transfer.
              Fees, donor-intent changes and manual-channel effects require documentary evidence.
              Card captures/refunds/disputes must match signed provider records.
            </p>
            <form
              autoComplete="off"
              className="admin-fields"
              key={selected?.event_id || 'manual-entry'}
              onSubmit={form(async (d) => {
                const id = crypto.randomUUID(),
                  source = p?.sources.find((s) => s.id === value(d, 'source'));
                if (!source) throw Error('Choose a currently approved source.');
                const entry = {
                  id,
                  kind,
                  giftId: kind === 'gift' ? id : giftId,
                  source: source.id,
                  externalReference: value(d, 'externalReference'),
                  environment: source.environment,
                  amountCents: amount(value(d, 'amount')),
                  donorId: ['gift', 'reattribution'].includes(kind) ? value(d, 'donorId') : null,
                  election: value(d, 'election'),
                  targetElection: kind === 'redesignation' ? value(d, 'targetElection') : null,
                  madeAt: utc(d, 'madeAt'),
                  receivedAt: utc(d, 'receivedAt'),
                  evidenceDigest: selected?.event_digest || value(d, 'evidenceDigest'),
                  intentDigest: ['redesignation', 'reattribution'].includes(kind)
                    ? value(d, 'intentDigest')
                    : null,
                  outcome: kind === 'dispute_closed' ? value(d, 'outcome') : null,
                };
                const result = await request<{ issues: string[] }>(
                  '/api/staff/finance/journal',
                  { entry, confirm: value(d, 'confirm') },
                  csrf,
                );
                setSelected(null);
                setMessage(
                  'Event ' +
                    id +
                    ' posted. Gift ' +
                    entry.giftId +
                    '. ' +
                    (result.issues.length
                      ? 'Review exceptions: ' + result.issues.join(', ')
                      : 'No automatic exception detected; this is not legal acceptance.'),
                );
                await refresh();
              })}
            >
              <label>
                Event type
                <select
                  value={kind}
                  onChange={(e) => {
                    setKind(e.target.value);
                    setSelected(null);
                  }}
                >
                  {[
                    'gift',
                    'refund',
                    'fee',
                    'dispute',
                    'dispute_closed',
                    'redesignation',
                    'reattribution',
                    'correction',
                  ].map((k) => (
                    <option key={k} value={k}>
                      {k.replaceAll('_', ' ')}
                    </option>
                  ))}
                </select>
              </label>
              {kind !== 'gift' && (
                <label>
                  Original gift
                  <select required value={giftId} onChange={(e) => setGiftId(e.target.value)}>
                    <option value="">Choose original gift</option>
                    {data.gifts.map((g) => (
                      <option value={g.id} key={g.id}>
                        {g.id} · {g.source} · {money(g.grossCents)}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              <label>
                Source
                <select
                  required
                  name="source"
                  defaultValue={selected?.provider || currentGift?.source || ''}
                >
                  <option value="">Choose approved source</option>
                  {p?.sources.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.id} · {s.environment} · {s.channel}
                    </option>
                  ))}
                </select>
              </label>
              <Input
                label="Immutable source or accounting correction reference"
                name="externalReference"
                initial={selected?.event_id || ''}
              />
              <Input
                label="Amount (USD)"
                name="amount"
                inputMode="decimal"
                initial={selected ? (Number(selected.amount_cents) / 100).toFixed(2) : ''}
              />
              {['gift', 'reattribution'].includes(kind) && (
                <Input label="Documented contributor reference" name="donorId" />
              )}
              <label>
                Election
                <select name="election">
                  <option>general</option>
                  <option>primary</option>
                </select>
              </label>
              {kind === 'redesignation' && (
                <label>
                  New permitted election
                  <select name="targetElection">
                    <option>primary</option>
                    <option>general</option>
                  </select>
                </label>
              )}
              {kind === 'dispute_closed' && (
                <label>
                  Authenticated final dispute outcome
                  <select name="outcome" defaultValue={selected?.outcome || 'won'}>
                    <option>won</option>
                    <option>lost</option>
                  </select>
                </label>
              )}
              {kind === 'correction' && (
                <label>
                  Documented manual accounting correction
                  <select name="outcome">
                    <option value="decrease">
                      Decrease recorded gross (no refund is initiated)
                    </option>
                    <option value="increase">
                      Increase recorded gross (no charge is initiated)
                    </option>
                  </select>
                </label>
              )}
              <Input
                label="Made date/time (UTC)"
                name="madeAt"
                type="datetime-local"
                step="0.001"
                initial={selected ? stamp(selected.occurred_at) : ''}
              />
              <Input
                label="Received date/time (UTC)"
                name="receivedAt"
                type="datetime-local"
                step="0.001"
                initial={selected ? stamp(selected.occurred_at) : ''}
              />
              {selected ? (
                <p>
                  Signed source SHA-256:{' '}
                  <code style={{ overflowWrap: 'anywhere' }}>{selected.event_digest}</code>
                </p>
              ) : (
                <Evidence
                  items={data.evidence}
                  label="Source or final processor outcome evidence"
                />
              )}
              {['redesignation', 'reattribution'].includes(kind) && (
                <Evidence
                  items={data.evidence}
                  name="intentDigest"
                  label="Documented donor intent and approved remedy"
                />
              )}
              <Input
                label="Type “record verified source evidence”"
                name="confirm"
                pattern="record verified source evidence"
              />
              <button className="btn" disabled={busy || !p}>
                Append verified financial event
              </button>
            </form>
          </details>
          <section className="panel spaced">
            <h3>Gift balances and allocations</h3>
            <ul>
              {data.gifts.map((g) => (
                <li key={g.id} className="spaced" style={{ overflowWrap: 'anywhere' }}>
                  <strong>{g.id}</strong>
                  <p>
                    {g.source} · {g.environment} · Contributor {g.donorId}:{g.donorVersion} ·
                    Provider payment {g.providerPaymentId || 'manual channel'}
                  </p>
                  <p>
                    Gross {money(g.grossCents)} · Refunded {money(g.refundedCents)} · Fees{' '}
                    {money(g.feeCents)} · Chargebacks {money(g.chargebackCents)} · Net{' '}
                    {money(g.grossCents - g.refundedCents - g.feeCents - g.chargebackCents)}
                  </p>
                  <p>
                    Primary allocation {money(g.allocations.primary)} · General allocation{' '}
                    {money(g.allocations.general)} · Open dispute {money(g.disputedCents)}
                  </p>
                </li>
              ))}
            </ul>
          </section>
          <details className="panel spaced">
            <summary>
              <strong>Provider/manual-source settlements and bank reconciliation</strong>
            </summary>
            <p>
              Match actual settlement statements to distinct journal effects, then record actual
              bank credits/debits. Mismatches remain visible. An entry can belong to only one
              settlement.
            </p>
            <form
              autoComplete="off"
              className="admin-fields"
              onSubmit={form(async (d) => {
                const source = p?.sources.find((s) => s.id === value(d, 'source'));
                if (!source) throw Error('Choose an approved source.');
                const id = crypto.randomUUID();
                await post(
                  'settlements',
                  {
                    id,
                    source: source.id,
                    environment: source.environment,
                    externalReference: value(d, 'externalReference'),
                    entryIds: d.getAll('entryIds').map(String),
                    grossCents: amount(value(d, 'gross')),
                    refundCents: value(d, 'refund') === '0' ? 0 : amount(value(d, 'refund')),
                    feeCents: value(d, 'fee') === '0' ? 0 : amount(value(d, 'fee')),
                    chargebackCents:
                      value(d, 'chargeback') === '0' ? 0 : amount(value(d, 'chargeback')),
                    netCents: amount(value(d, 'net')),
                    settledAt: utc(d, 'settledAt'),
                    evidenceDigest: value(d, 'evidenceDigest'),
                  },
                  'Settlement ' + id + ' recorded. Review the source and bank balance indicators.',
                );
              })}
            >
              <label>
                Settlement source
                <select required name="source">
                  <option value="">Choose source</option>
                  {p?.sources.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.id}
                    </option>
                  ))}
                </select>
              </label>
              <Input label="Actual payout/settlement reference" name="externalReference" />
              <fieldset>
                <legend>Exact journal effects in this settlement</legend>
                {data.journal.map((j) => (
                  <label key={j.id} style={{ overflowWrap: 'anywhere' }}>
                    <input type="checkbox" name="entryIds" value={j.id} />
                    {j.id} · {j.event_kind} · {j.source} · {j.environment}
                  </label>
                ))}
              </fieldset>
              {['gross', 'refund', 'fee', 'chargeback', 'net'].map((f) => (
                <Input
                  key={f}
                  label={'Reported ' + f + ' amount (USD)'}
                  name={f}
                  inputMode="decimal"
                />
              ))}
              <Input
                label="Actual settled date/time (UTC)"
                name="settledAt"
                type="datetime-local"
                step="0.001"
              />
              <Evidence items={data.evidence} label="Actual settlement statement" />
              <button className="btn" disabled={busy || !p}>
                Record settlement observation
              </button>
            </form>
            <form
              autoComplete="off"
              className="admin-fields spaced"
              onSubmit={form(async (d) => {
                const result = await request<{ balanced: boolean; notice: string }>(
                  '/api/staff/finance/deposits',
                  {
                    id: crypto.randomUUID(),
                    settlementId: value(d, 'settlementId'),
                    bankReference: value(d, 'bankReference'),
                    amountCents: amount(value(d, 'bankAmount')),
                    receivedAt: utc(d, 'bankReceivedAt'),
                    evidenceDigest: value(d, 'bankEvidence'),
                  },
                  csrf,
                );
                setMessage(result.notice);
                await refresh();
              })}
            >
              <label>
                Settlement to match
                <select name="settlementId" required>
                  <option value="">Choose settlement</option>
                  {data.settlements.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.id} · {s.source} · {s.environment}
                    </option>
                  ))}
                </select>
              </label>
              <Input label="Actual bank transaction reference" name="bankReference" />
              <Input
                label="Bank credit/debit (USD; negative for a debit)"
                name="bankAmount"
                inputMode="decimal"
              />
              <Input
                label="Actual bank receipt date/time (UTC)"
                name="bankReceivedAt"
                type="datetime-local"
                step="0.001"
              />
              <Evidence
                items={data.evidence}
                name="bankEvidence"
                label="Actual bank statement evidence"
              />
              <button className="btn" disabled={busy}>
                Record bank observation
              </button>
            </form>
            <ul>
              {data.settlements.map((s) => (
                <li key={s.id} style={{ overflowWrap: 'anywhere' }}>
                  {s.id} · {s.source} · {s.environment} · Expected net {money(s.netCents)} ·
                  Recorded bank {money(Number(s.bankCents))} ·{' '}
                  {s.balanced ? 'Source effects match' : 'SOURCE MISMATCH'} ·{' '}
                  {s.bankBalanced ? 'Bank amounts match' : 'BANK RECONCILIATION REQUIRED'}
                </li>
              ))}
            </ul>
            <h4>Bank observations</h4>
            <ul>
              {data.deposits.map((d) => (
                <li key={d.id} style={{ overflowWrap: 'anywhere' }}>
                  {d.id} · Settlement {d.settlementId} · Bank reference {d.bankReference} ·{' '}
                  {money(d.amountCents)} · {new Date(d.receivedAt).toLocaleString()} · Evidence{' '}
                  {d.evidenceDigest}
                </li>
              ))}
            </ul>
          </details>
          <details className="panel spaced">
            <summary>
              <strong>Finance exceptions, remedies and bounded follow-up</strong>
            </summary>
            <p>
              Deadlines and contact bounds come from the exact approved policy saved with each case.
              A case status or follow-up record is not legal certification. New financial effects
              must enter the signed-source journal separately.
            </p>
            <form
              autoComplete="off"
              className="admin-fields"
              onSubmit={form(async (d) => {
                await post(
                  'cases',
                  {
                    id: crypto.randomUUID(),
                    giftId: value(d, 'giftId'),
                    kind: value(d, 'kind'),
                    evidenceDigest: value(d, 'evidenceDigest'),
                  },
                  'Exception case opened with the current approved deadline and follow-up bounds.',
                );
              })}
            >
              <label>
                Gift
                <select required name="giftId">
                  <option value="">Choose gift</option>
                  {data.gifts.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.id}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Exception type
                <select name="kind">
                  {[
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
                  ].map((k) => (
                    <option key={k} value={k}>
                      {k.replaceAll('_', ' ')}
                    </option>
                  ))}
                </select>
              </label>
              <Evidence items={data.evidence} />
              <button className="btn" disabled={busy || !p}>
                Open documented exception
              </button>
            </form>
            {data.cases.map((c) => (
              <article className="panel spaced" key={c.id}>
                <h4 style={{ overflowWrap: 'anywhere' }}>
                  {c.kind} · {c.id}
                </h4>
                <p>
                  Gift {c.giftId} · {c.status} · Revision {c.version}
                </p>
                <p>
                  {c.overdue ? 'OVERDUE: review promptly. ' : ''}Approved deadline{' '}
                  {new Date(c.deadline).toLocaleString()} · Follow-ups {c.followups}/
                  {c.maxFollowups} · Next earliest {new Date(c.nextFollowupAt).toLocaleString()}
                </p>
                <form
                  autoComplete="off"
                  className="admin-fields"
                  onSubmit={form(async (d) => {
                    await post(
                      'cases/' + c.id,
                      {
                        version: c.version,
                        action: value(d, 'action'),
                        evidenceDigest: value(d, 'evidenceDigest'),
                        occurredAt: value(d, 'occurredAt') ? utc(d, 'occurredAt') : null,
                      },
                      'Case action recorded. Any requested notice is only queued until the delivery receipt confirms its provider status. No financial operation was initiated.',
                    );
                  })}
                >
                  <label>
                    Case action
                    <select name="action">
                      <option value="review">Mark under review</option>
                      <option value="followup">Record documented follow-up</option>
                      <option value="notify">Queue a generic transactional donor notice</option>
                      <option value="close">Close with evidence</option>
                    </select>
                  </label>
                  <Input
                    label="Actual manual follow-up date/time (UTC; otherwise leave empty)"
                    name="occurredAt"
                    type="datetime-local"
                    step="0.001"
                    required={false}
                  />
                  <Evidence items={data.evidence} />
                  <button className="btn outline" disabled={busy || c.status === 'closed'}>
                    Record case action
                  </button>
                </form>
                {c.kind === 'refund' && data.sandboxActions && (
                  <form
                    autoComplete="off"
                    className="admin-fields spaced"
                    onSubmit={form(async (d) => {
                      await post(
                        'commands/refund-test',
                        {
                          id: crypto.randomUUID(),
                          caseId: c.id,
                          caseVersion: c.version,
                          amountCents: amount(value(d, 'refundAmount')),
                          evidenceDigest: value(d, 'evidenceDigest'),
                          confirm: value(d, 'confirm'),
                        },
                        'Stripe TEST request recorded. Verify its signed refund event and post/reconcile the exact source before another request.',
                      );
                    })}
                  >
                    <Input
                      label="Approved Stripe TEST refund amount (USD)"
                      name="refundAmount"
                      inputMode="decimal"
                    />
                    <Evidence items={data.evidence} label="Approved test remedy" />
                    <Input
                      label="Type “request this Stripe TEST refund”"
                      name="confirm"
                      pattern="request this Stripe TEST refund"
                    />
                    <button className="btn outline" disabled={busy || c.status === 'closed'}>
                      Request approved Stripe TEST refund
                    </button>
                  </form>
                )}
              </article>
            ))}
            {data.commands.map((c) => (
              <article key={c.id} className="panel spaced">
                <p style={{ overflowWrap: 'anywhere' }}>
                  Provider command {c.id} · {c.status} ·{' '}
                  {c.provider_reference || 'No confirmed provider reference'}
                </p>
                <p>
                  Processing or uncertain commands must be reconciled before another request. This
                  application never automatically retries an uncertain refund.
                </p>
                <form
                  autoComplete="off"
                  className="admin-fields"
                  onSubmit={form(async (d) => {
                    await post(
                      'commands/' + c.id + '/reconcile',
                      value(d, 'providerEventId')
                        ? { providerEventId: value(d, 'providerEventId') }
                        : { journalEntryId: value(d, 'journalEntryId') },
                      'Command matched to its signed refund source and treasury posting.',
                    );
                  })}
                >
                  <Input
                    label="Exact posted refund journal reference (for a successful refund)"
                    name="journalEntryId"
                    required={false}
                  />
                  <Input
                    label="Or exact signed provider failure receipt (refund failed/canceled)"
                    name="providerEventId"
                    required={false}
                  />
                  <button className="btn outline" disabled={busy || c.status === 'reconciled'}>
                    Reconcile exact provider command
                  </button>
                </form>
              </article>
            ))}
          </details>
          <details className="panel spaced">
            <summary>
              <strong>Approved accounting export</strong>
            </summary>
            <p>
              One immutable source event per row. Test/live sources stay separate; gross, refunds,
              fees, chargebacks, net and election allocations have distinct totals. Identity export
              is explicit, audited and limited to the approved mapping. No filing is submitted
              automatically.
            </p>
            <form
              autoComplete="off"
              className="admin-fields"
              onSubmit={form(async (d) => {
                const format = value(d, 'format');
                await download(
                  'export',
                  {
                    from: utc(d, 'from'),
                    until: utc(d, 'until'),
                    environment: value(d, 'environment'),
                    format,
                    includeIdentity: d.get('includeIdentity') === 'on',
                    confirm: value(d, 'confirm'),
                  },
                  'galinsky-private-accounting.' + format,
                );
              })}
            >
              <Input
                label="Accounting period begins (UTC, inclusive)"
                name="from"
                type="datetime-local"
                step="0.001"
              />
              <Input
                label="Accounting period ends (UTC, exclusive)"
                name="until"
                type="datetime-local"
                step="0.001"
              />
              <label>
                Environment
                <select name="environment">
                  <option>test</option>
                  <option>live</option>
                </select>
              </label>
              <label>
                Format
                <select name="format">
                  <option value="json">JSON with totals and source context</option>
                  <option value="csv">Approved CSV import mapping</option>
                </select>
              </label>
              <label>
                <input type="checkbox" name="includeIdentity" /> Explicitly include authorized
                contributor identity fields
              </label>
              <Input
                label="Type “export approved treasury report”"
                name="confirm"
                pattern="export approved treasury report"
              />
              <button className="btn" disabled={busy || !p}>
                Download audited accounting export
              </button>
            </form>
          </details>
        </>
      )}
    </section>
  );
}
