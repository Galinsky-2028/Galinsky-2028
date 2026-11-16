import React, { useEffect, useState, FormEvent } from 'react';
import { request } from './api';

// Staff screens for TEST monthly card schedules. Every action calls an existing
// authenticated API that rechecks owner/treasurer authority, a fresh passkey, CSRF
// and current all-channel limits. Nothing here can capture funds without the
// separate exact capture step, and live processing is not installed.
type Enrollment = {
  id: string;
  status: string;
  environment: string;
  setup_session_id: string | null;
  replaces_mandate_id: string | null;
  request_document: {
    amountCents: number;
    frequency: string;
    election: string;
    maxInstallments: number;
    endAt: string;
    termsVersion: string;
  };
};
type Mandate = {
  id: string;
  status: string;
  version: number;
  document: { amountCents: number; frequency: string; maxInstallments: number; endAt: string; enrollmentId: string };
};
type Period = {
  id: string;
  mandate_id: string;
  installment: number;
  status: string;
  amount_cents: string | number;
  reservation_active: boolean;
  provider_payment_id: string | null;
  version: number;
};
type Command = { id: string; period_id: string; action: string; status: string; provider_reference: string | null };
type Due = { mandate_id: string; installment: number; mandate_version: number; due_at: string; window_ends_at: string };
type Page<T> = { items: T[]; after: string | null; more: boolean };
type Review = { id: string; billing: Record<string, string>; card: { funding: string; issuerCountry: string } };

const money = (n: number | string) => '$' + (Number(n) / 100).toFixed(2);
const day = (s: string) => new Date(s).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
const field = (d: FormData, n: string) => String(d.get(n) || '');

export function MonthlyGiving({ csrf }: { csrf: string }) {
  const [enrollments, setEnrollments] = useState<Enrollment[]>([]),
    [mandates, setMandates] = useState<Mandate[]>([]),
    [periods, setPeriods] = useState<Period[]>([]),
    [commands, setCommands] = useState<Command[]>([]),
    [due, setDue] = useState<Due[]>([]),
    [evidence, setEvidence] = useState<{ id: string; digest: string; byte_count: number }[]>([]),
    [review, setReview] = useState<Review | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [message, setMessage] = useState('');
  const api = <T,>(path: string, body: unknown) =>
    request<T>('/api/staff/finance/card/' + path, body, csrf);
  async function all<T>(collection: string) {
    const items: T[] = [];
    let after: string | null = null;
    for (let i = 0; i < 20; i++) {
      const page: Page<T> = await api<Page<T>>('page', { collection, after });
      items.push(...page.items);
      if (!page.more) break;
      after = page.after;
    }
    return items;
  }
  async function refresh() {
    const [e, m, p, c, q, o] = await Promise.all([
      all<Enrollment>('enrollments'),
      all<Mandate>('mandates'),
      all<Period>('periods'),
      all<Command>('commands'),
      api<{ items: Due[] }>('due', {}),
      request<{ evidence: { id: string; digest: string; byte_count: number }[] }>(
        '/api/staff/finance/overview',
        {},
        csrf,
      ),
    ]);
    setEnrollments(e);
    setMandates(m);
    setPeriods(p);
    setCommands(c);
    setDue(q.items);
    setEvidence(o.evidence || []);
  }
  useEffect(() => {
    void refresh().catch((e) => setError((e as Error).message));
  }, []);
  function act(handler: (d: FormData) => Promise<string>) {
    return (e: FormEvent<HTMLFormElement>) => {
      e.preventDefault();
      const d = new FormData(e.currentTarget);
      setBusy(true);
      setError('');
      setMessage('');
      void handler(d)
        .then(async (notice) => {
          setMessage(notice);
          await refresh();
        })
        .catch((x) => setError((x as Error).message))
        .finally(() => setBusy(false));
    };
  }
  const EvidenceSelect = ({ name = 'evidence' }: { name?: string }) => (
    <label>
      Documentary evidence
      <select required name={name}>
        <option value="">Choose an uploaded source</option>
        {evidence.map((x) => (
          <option key={x.id} value={x.digest}>
            {x.id.slice(0, 8)} · {x.byte_count} bytes · {x.digest.slice(0, 12)}
          </option>
        ))}
      </select>
    </label>
  );
  const Confirm = ({ phrase }: { phrase: string }) => (
    <label>
      Type “{phrase}”
      <input required name="confirm" pattern={phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} autoComplete="off" />
    </label>
  );
  const replacements = (mandateId: string) =>
    enrollments.filter((e) => e.replaces_mandate_id === mandateId && e.status === 'verified');
  const open = enrollments.filter(
    (e) => !e.replaces_mandate_id && ['pending', 'verified', 'requires_review'].includes(e.status),
  );
  const mandated = new Set(mandates.map((m) => m.document.enrollmentId));
  return (
    <section className="spaced monthly-giving">
      <span className="eyebrow">MONTHLY GIVING · STRIPE TEST ONLY</span>
      <h2>Monthly card schedules.</h2>
      <p>
        Review saved cards, approve schedules, work the due queue and replace cards. Each step is
        rechecked on the server against current treasurer authority, your fresh passkey and all-channel
        limits. Collected monthly gifts are refunded through a refund case under Campaign accounting.
      </p>
      {error && (
        <p className="admin-feedback error" role="alert">
          {error}
        </p>
      )}
      {message && (
        <p className="admin-feedback" role="status">
          {message}
        </p>
      )}

      <h3>Saved cards awaiting approval ({open.filter((e) => !mandated.has(e.id)).length})</h3>
      {open
        .filter((e) => !mandated.has(e.id))
        .map((e) => (
          <article className="panel spaced" key={e.id} data-enrollment={e.id}>
            <p>
              {money(e.request_document.amountCents)} {e.request_document.frequency} ×{' '}
              {e.request_document.maxInstallments}, {e.request_document.election} election, until{' '}
              {day(e.request_document.endAt)} · terms {e.request_document.termsVersion} · status{' '}
              <strong>{e.status}</strong>
            </p>
            {e.status !== 'verified' && (
              <form
                className="admin-fields"
                onSubmit={act(async () => {
                  await api('enrollments/' + e.id + '/verify-test', { confirm: 'verify actual TEST card setup' });
                  return 'Saved TEST card verified with the processor. No payment was authorized.';
                })}
              >
                <button className="btn outline" disabled={busy}>
                  Verify saved TEST card with Stripe
                </button>
              </form>
            )}
            {e.status === 'verified' && (
              <>
                <form
                  className="admin-fields"
                  onSubmit={act(async () => {
                    setReview(await api<Review>('enrollments/' + e.id + '/review', {}));
                    return 'Private billing identity opened (this read is audited).';
                  })}
                >
                  <button className="btn outline" disabled={busy}>
                    Review billing identity
                  </button>
                </form>
                {review?.id === e.id && (
                  <dl className="admin-review">
                    {Object.entries(review.billing).map(([k, v]) => (
                      <React.Fragment key={k}>
                        <dt>{k}</dt>
                        <dd>{v}</dd>
                      </React.Fragment>
                    ))}
                    <dt>card</dt>
                    <dd>
                      {review.card.funding} · issuer {review.card.issuerCountry}
                    </dd>
                  </dl>
                )}
                <form
                  className="admin-fields"
                  autoComplete="off"
                  onSubmit={act(async (d) => {
                    await api('mandates', {
                      id: crypto.randomUUID(),
                      enrollmentId: e.id,
                      donorId: field(d, 'donorId'),
                      donorVersion: Number(field(d, 'donorVersion')),
                      identityEvidenceDigest: field(d, 'evidence'),
                      confirm: field(d, 'confirm'),
                    });
                    return 'Schedule approved. The first installment appears in the due queue.';
                  })}
                >
                  <label>
                    Documented contributor ID
                    <input required name="donorId" pattern="[0-9a-f-]{36}" />
                  </label>
                  <label>
                    Contributor revision
                    <input required name="donorVersion" inputMode="numeric" pattern="[0-9]+" />
                  </label>
                  <EvidenceSelect />
                  <Confirm phrase="approve exact documented card mandate" />
                  <button className="btn" disabled={busy}>
                    Approve schedule
                  </button>
                </form>
              </>
            )}
          </article>
        ))}

      <h3>Due installments ({due.length})</h3>
      {due.length === 0 && <p>No installment is waiting for treasury review.</p>}
      {due.map((q) => (
        <form
          key={q.mandate_id + q.installment}
          className="panel admin-fields spaced"
          data-due={q.mandate_id + ':' + q.installment}
          onSubmit={act(async (d) => {
            await api('periods', {
              id: crypto.randomUUID(),
              mandateId: q.mandate_id,
              mandateVersion: q.mandate_version,
              index: q.installment,
              confirm: field(d, 'confirm'),
            });
            return 'Installment reserved against current limits. Prepare its authorization before the short reservation expires.';
          })}
        >
          <p>
            Schedule {q.mandate_id.slice(0, 8)} · month {q.installment + 1} · due {day(q.due_at)} · window
            closes {day(q.window_ends_at)}
          </p>
          <Confirm phrase="reserve exact due installment" />
          <button className="btn" disabled={busy}>
            Reserve installment
          </button>
        </form>
      ))}

      <h3>Installments in progress</h3>
      {periods
        .filter((p) => p.reservation_active)
        .map((p) => {
          const cmds = commands.filter((c) => c.period_id === p.id);
          const pending = cmds.filter((c) => ['processing', 'uncertain'].includes(c.status));
          const action =
            p.status === 'reserved' ? 'authorize' : p.status === 'authorized' ? 'capture' : null;
          return (
            <article className="panel spaced" key={p.id} data-period={p.id}>
              <p>
                Month {p.installment + 1} · {money(p.amount_cents)} · <strong>{p.status}</strong>
                {p.provider_payment_id ? ' · ' + p.provider_payment_id : ''}
              </p>
              {action && pending.length === 0 && (
                <form
                  className="admin-fields"
                  onSubmit={act(async (d) => {
                    await api('commands', {
                      id: crypto.randomUUID(),
                      periodId: p.id,
                      periodVersion: p.version,
                      action,
                      confirm: field(d, 'confirm'),
                    });
                    return 'Command recorded. Dispatch it once below.';
                  })}
                >
                  <Confirm phrase={'prepare exact ' + action} />
                  <button className="btn" disabled={busy}>
                    Prepare {action}
                  </button>
                </form>
              )}
              {p.provider_payment_id && !['captured_unposted', 'posted'].includes(p.status) && pending.length === 0 && (
                <form
                  className="admin-fields"
                  onSubmit={act(async (d) => {
                    await api('commands', {
                      id: crypto.randomUUID(),
                      periodId: p.id,
                      periodVersion: p.version,
                      action: 'cancel',
                      confirm: field(d, 'confirm'),
                    });
                    return 'Release recorded. Dispatch it once below.';
                  })}
                >
                  <Confirm phrase="prepare exact cancel" />
                  <button className="btn outline" disabled={busy}>
                    Prepare release (void hold)
                  </button>
                </form>
              )}
              {pending.map((c) => (
                <div key={c.id} className="admin-fields" data-command={c.id}>
                  <p>
                    {c.action} command {c.id.slice(0, 8)} · {c.status}
                  </p>
                  {c.status === 'processing' && (
                    <form
                      onSubmit={act(async (d) => {
                        await api('commands/' + c.id + '/perform-test', { confirm: field(d, 'confirm') });
                        return 'Sent once to Stripe TEST. Never repeat; reconcile if the result is uncertain.';
                      })}
                    >
                      <Confirm phrase="dispatch exact TEST command once" />
                      <button className="btn" disabled={busy}>
                        Dispatch once
                      </button>
                    </form>
                  )}
                  <form
                    onSubmit={act(async (d) => {
                      await api('commands/' + c.id + '/reconcile-test', {
                        providerPaymentId: field(d, 'pi'),
                        confirm: field(d, 'confirm'),
                      });
                      return 'Processor state observed and recorded.';
                    })}
                  >
                    <label>
                      Exact Stripe TEST intent
                      <input required name="pi" pattern="pi_[A-Za-z0-9]{8,100}" defaultValue={p.provider_payment_id || ''} />
                    </label>
                    <Confirm phrase="observe exact existing TEST intent" />
                    <button className="btn outline" disabled={busy}>
                      Reconcile
                    </button>
                  </form>
                </div>
              ))}
            </article>
          );
        })}

      <h3>Schedules</h3>
      {mandates.map((m) => (
        <article className="panel spaced" key={m.id} data-mandate={m.id}>
          <p>
            {m.id.slice(0, 8)} · {money(m.document.amountCents)} {m.document.frequency} ×{' '}
            {m.document.maxInstallments} until {day(m.document.endAt)} · <strong>{m.status}</strong> · v
            {m.version}
          </p>
          {m.status === 'active' &&
            replacements(m.id).map((r) => (
              <form
                key={r.id}
                className="admin-fields"
                onSubmit={act(async (d) => {
                  await api('mandates/' + m.id + '/replace-method', {
                    mandateVersion: m.version,
                    enrollmentId: r.id,
                    identityEvidenceDigest: field(d, 'evidence'),
                    confirm: field(d, 'confirm'),
                  });
                  return 'Saved card replaced for future installments.';
                })}
              >
                <p>Verified replacement card from the donor ({r.id.slice(0, 8)}).</p>
                <EvidenceSelect />
                <Confirm phrase="replace exact saved card for future installments" />
                <button className="btn" disabled={busy}>
                  Approve card replacement
                </button>
              </form>
            ))}
          {m.status === 'active' && (
            <form
              className="admin-fields"
              onSubmit={act(async (d) => {
                await api('mandates/' + m.id + '/cancel', {
                  version: m.version,
                  confirm: field(d, 'confirm'),
                });
                return 'Schedule cancelled. No new authorizations or captures.';
              })}
            >
              <Confirm phrase="cancel exact future schedule" />
              <button className="btn outline" disabled={busy}>
                Cancel schedule
              </button>
            </form>
          )}
        </article>
      ))}
      <h3>Replacement cards awaiting verification</h3>
      {enrollments
        .filter((e) => e.replaces_mandate_id && e.status === 'pending')
        .map((e) => (
          <form
            key={e.id}
            className="panel admin-fields spaced"
            onSubmit={act(async () => {
              await api('enrollments/' + e.id + '/verify-test', { confirm: 'verify actual TEST card setup' });
              return 'Replacement TEST card verified. Approve it on its schedule above.';
            })}
          >
            <p>Replacement for schedule {e.replaces_mandate_id?.slice(0, 8)}</p>
            <button className="btn outline" disabled={busy}>
              Verify replacement card with Stripe
            </button>
          </form>
        ))}
    </section>
  );
}
