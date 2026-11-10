import React, { useEffect, useMemo, useState } from 'react';
import { request } from './api';
import { createProtectedClient } from './protected-client.mjs';
import { protectedLocalList } from './protected-local.mjs';
type Device = {
  id: string;
  accountId: string;
  identityId: string;
  rootFingerprint: string;
  fingerprint: string;
  label: string;
  state: string;
  scope: string;
  identityHash: string;
};
type Client = ReturnType<typeof createProtectedClient>;
type Own = ReturnType<Client['publicState']>;
type Opened = {
  id: string;
  kind: string;
  status: string;
  retainUntil: string;
  messages: { context: { sequence: number }; payload: { text: string; attachment?: unknown } }[];
  draft: unknown;
  recipients: { device: string; account: string; verified: boolean }[];
};
type Peer = Awaited<ReturnType<Client['peer']>>;
const prefix = '/api/protected/v2';
export function ProtectedReports({
  csrf,
  accountId,
  role,
  enabled,
  intakeEnabled = enabled,
}: {
  csrf: string;
  accountId: string;
  role: string;
  enabled: boolean;
  intakeEnabled?: boolean;
}) {
  const [own, setOwn] = useState<Own | null>(null),
    [phrase, setPhrase] = useState(''),
    [label, setLabel] = useState('My protected device'),
    [devices, setDevices] = useState<Device[]>([]),
    [items, setItems] = useState<{ id: string; version: number }[]>([]),
    [localIds, setLocalIds] = useState<string[]>([]);
  const [kind, setKind] = useState('incident'),
    [target, setTarget] = useState(''),
    [fingerprint, setFingerprint] = useState(''),
    [identityId, setIdentityId] = useState(''),
    [rootFingerprint, setRootFingerprint] = useState(''),
    [peer, setPeer] = useState<Peer | null>(null),
    [comparison, setComparison] = useState(''),
    [independent, setIndependent] = useState(false);
  const [opened, setOpened] = useState<Opened | null>(null),
    [text, setText] = useState(''),
    [file, setFile] = useState<File | null>(null),
    [error, setError] = useState(''),
    [message, setMessage] = useState(''),
    [busy, setBusy] = useState(false),
    [holdDigest, setHoldDigest] = useState('');
  const [lossAccepted, setLossAccepted] = useState(false);
  const [linkRequest, setLinkRequest] = useState(''),
    [newFingerprint, setNewFingerprint] = useState('');
  const client = useMemo(
    () =>
      createProtectedClient({
        account: accountId,
        api: (path: string, body?: unknown) => request(path, body, csrf),
        onLock: () => {
          setOwn(null);
          setOpened(null);
          setText('');
          setFile(null);
          setPhrase('');
          setComparison('');
          setIndependent(false);
          setPeer(null);
        },
      }),
    [accountId, csrf],
  );
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const reset = () => {
      clearTimeout(timer);
      timer = setTimeout(() => client.lock(), 10 * 60 * 1000);
    };
    const hide = () => {
      if (document.hidden) client.lock();
    };
    reset();
    document.addEventListener('pointerdown', reset);
    document.addEventListener('keydown', reset);
    document.addEventListener('visibilitychange', hide);
    return () => {
      clearTimeout(timer);
      document.removeEventListener('pointerdown', reset);
      document.removeEventListener('keydown', reset);
      document.removeEventListener('visibilitychange', hide);
      client.close();
    };
  }, [client]);
  useEffect(() => {
    if (!own) return;
    const timer = setInterval(() => {
      void client.expirePending().catch(() => client.lock());
    }, 60000);
    return () => clearInterval(timer);
  }, [client, own]);
  const security = ['owner', 'security-admin'].includes(role);
  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError('');
    setMessage('');
    try {
      await action();
    } catch (e) {
      setPeer(null);
      setError((e as Error).message || 'This operation could not be authenticated.');
    } finally {
      setBusy(false);
    }
  }
  async function refresh() {
    const all: Device[] = [];
    let after: string | null = null;
    do {
      const page: { devices: Device[]; next: string | null } = await request<{
        devices: Device[];
        next: string | null;
      }>(prefix + '/directory?kind=' + kind + (after ? '&after=' + after : ''));
      all.push(...page.devices);
      after = page.next;
    } while (after && all.length < 1000);
    setDevices(all);
    if (intakeEnabled) {
      const inbox = await request<{ records: { id: string; version: number }[] }>(
        prefix + '/records',
      );
      setItems(inbox.records);
    }
    const rows = await protectedLocalList(accountId);
    setLocalIds(
      rows
        .filter((r: { key: string }) => r.key.startsWith('thread:'))
        .map((r: { key: string }) => r.key.split(':').at(-1)),
    );
  }
  useEffect(() => {
    if (enabled) void run(refresh);
  }, [enabled, kind]);
  async function unlock(create: boolean) {
    const password = phrase;
    setPhrase('');
    await run(async () => {
      const value = create
        ? await client.enroll(password, label, lossAccepted)
        : await client.unlock(password);
      setOwn(value);
      setMessage(
        'Device unlocked locally. Your private keys and unlock phrase stay in this browser.',
      );
      await refresh();
    });
  }
  async function load(id: string) {
    await run(async () => {
      setOpened(await client.synchronize(id));
      setText('');
      setFile(null);
    });
  }
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    await run(async () => {
      let attachment;
      if (file) {
        if (file.size > 150000) throw Error('Keep attachments at or below 150 KB.');
        attachment = { name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) };
      }
      const result = opened
        ? await client.reply({ id: opened.id, text, attachment })
        : await client.send({
            kind,
            devices: [target],
            fingerprints: { [target]: fingerprint },
            text,
            attachment,
          });
      setText('');
      setFile(null);
      setOpened(await client.synchronize(result.id));
      setMessage('Encrypted message received. Check this inbox for replies.');
      await refresh();
    });
  }
  async function download(sequence: number) {
    if (!opened) return;
    await run(async () => {
      const result = await client.attachment(opened.id, sequence),
        blob = new Blob([new Uint8Array(result.bytes)], { type: 'application/octet-stream' }),
        url = URL.createObjectURL(blob),
        a = document.createElement('a');
      a.href = url;
      a.download = 'quarantined-' + result.name.replace(/[^a-zA-Z0-9._-]/g, '_') + '.bin';
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }
  return (
    <>
      <span className="eyebrow">PRIVATE SUPPORT</span>
      <h1>Protected messages.</h1>
      <p className="notice">
        If someone is in immediate danger, contact local emergency services. This inbox is not
        monitored continuously.
      </p>
      {!enabled ? (
        <p role="status">
          Protected reporting is not open. No confidential submission can be stored.
        </p>
      ) : (
        <>
          <p>
            Messages use a separate account root, signed device identities and a ratcheted MLS group
            for the exact original recipients. Compare identity verification values through an
            independent trusted channel before sending. The website and your device must remain
            trustworthy.
          </p>
          {!intakeEnabled && (
            <p role="status" className="notice">
              Device setup is available. Confidential intake remains closed.
            </p>
          )}
          {error && (
            <p role="alert" className="notice error">
              {error}
            </p>
          )}
          {message && (
            <p role="status" className="notice">
              {message}
            </p>
          )}
          <section className="panel spaced">
            <h2>Your protected device</h2>
            <p>
              This browser keeps an encrypted local vault. There is no recovery backup in this
              client. Losing this browser’s storage loses its keys and message history. A password
              reset cannot restore them.
            </p>
            {own ? (
              <>
                <p>
                  Unlocked device <code>{own.deviceId}</code>
                </p>
                <p style={{ overflowWrap: 'anywhere' }}>
                  Identity ID: {own.identityId}
                  <br />
                  Account root fingerprint: {own.rootFingerprint}
                  <br />
                  Device fingerprint: {own.deviceFingerprint}
                </p>
                <p>
                  Share your identity ID and root fingerprint through your separate trusted channel
                  so the other person can compare the same verification value.
                </p>
                <button className="btn outline" onClick={() => client.lock()}>
                  Lock device
                </button>
                <button
                  className="btn outline"
                  disabled={busy}
                  onClick={() =>
                    void run(async () => {
                      await client.publishPackages(4);
                      setMessage('Fresh one-time encrypted-delivery packages published.');
                    })
                  }
                >
                  Prepare this device to receive new messages
                </button>
              </>
            ) : (
              <>
                <label>
                  Local unlock phrase (16 characters minimum)
                  <input
                    type="password"
                    autoComplete="off"
                    minLength={16}
                    maxLength={256}
                    value={phrase}
                    onChange={(e) => setPhrase(e.target.value)}
                  />
                </label>
                <label>
                  Device label
                  <input maxLength={60} value={label} onChange={(e) => setLabel(e.target.value)} />
                </label>
                <button
                  className="btn"
                  disabled={busy || phrase.length < 16}
                  onClick={() => void unlock(false)}
                >
                  Unlock this browser’s device
                </button>
                <button
                  className="btn outline"
                  disabled={busy || phrase.length < 16 || !lossAccepted}
                  onClick={() => void unlock(true)}
                >
                  Create first account root and device
                </button>
                <label className="check">
                  <input
                    type="checkbox"
                    checked={lossAccepted}
                    onChange={(e) => setLossAccepted(e.target.checked)}
                  />
                  <span>
                    I understand this browser has no recovery backup and losing its storage
                    permanently loses its keys.
                  </span>
                </label>
              </>
            )}
            {!own && (
              <>
                <h3>Link another browser to your existing root</h3>
                <label>
                  Your existing account identity ID
                  <input
                    value={identityId}
                    onChange={(e) => setIdentityId(e.target.value)}
                    maxLength={36}
                  />
                </label>
                <label>
                  Your root fingerprint confirmed on your existing root device
                  <input
                    value={rootFingerprint}
                    onChange={(e) => setRootFingerprint(e.target.value)}
                    maxLength={64}
                  />
                </label>
                <button
                  className="btn outline"
                  disabled={busy || phrase.length < 16 || !lossAccepted}
                  onClick={() => {
                    const password = phrase;
                    setPhrase('');
                    void run(async () => {
                      const result = await client.prepareLinked(
                        password,
                        identityId,
                        rootFingerprint,
                        label,
                        lossAccepted,
                      );
                      setLinkRequest(JSON.stringify(result.request));
                      setNewFingerprint(result.deviceFingerprint);
                      setMessage(
                        'Private keys saved in this browser’s encrypted vault. Send only the public request to your existing root device. After authorization, unlock this browser to finish.',
                      );
                    });
                  }}
                >
                  Prepare public device-link request
                </button>
              </>
            )}
            {(linkRequest || own?.hasRoot) && (
              <>
                <h3>Root-authorized device enrollment</h3>
                <p>
                  This request contains public keys and signatures only. Compare the new device
                  fingerprint through your separate trusted channel before authorizing. Linked
                  devices receive no old thread keys or inherited staff approval.
                </p>
                <label>
                  Public enrollment request
                  <textarea
                    value={linkRequest}
                    onChange={(e) => setLinkRequest(e.target.value)}
                    maxLength={40000}
                  />
                </label>
                <label>
                  New device fingerprint confirmed independently
                  <input
                    value={newFingerprint}
                    onChange={(e) => setNewFingerprint(e.target.value)}
                    maxLength={64}
                  />
                </label>
                {own?.hasRoot && (
                  <button
                    className="btn outline"
                    disabled={busy || !newFingerprint}
                    onClick={() =>
                      void run(async () => {
                        await client.authorizeLinked(JSON.parse(linkRequest), newFingerprint);
                        setOwn(client.publicState());
                        setLinkRequest('');
                        setNewFingerprint('');
                        setMessage(
                          'Exact new device authorized by this account root. Unlock the linked browser to finish enrollment.',
                        );
                      })
                    }
                  >
                    Authorize exact new device with account root
                  </button>
                )}
              </>
            )}
            <p className="fine">
              The vault locks when this page is hidden or after ten minutes without interaction.
              Revocation stops future routing access; it cannot erase copies already decrypted or
              downloaded.
            </p>
          </section>
          {own && (
            <>
              <section className="panel spaced">
                <h2>Compare account roots</h2>
                <label>
                  Other person’s identity ID
                  <input
                    value={identityId}
                    onChange={(e) => {
                      setIdentityId(e.target.value);
                      setPeer(null);
                    }}
                    maxLength={36}
                  />
                </label>
                <label>
                  Account root fingerprint from your independent trusted channel
                  <input
                    value={rootFingerprint}
                    onChange={(e) => {
                      setRootFingerprint(e.target.value);
                      setPeer(null);
                    }}
                    maxLength={64}
                  />
                </label>
                <button
                  className="btn outline"
                  disabled={busy}
                  onClick={() =>
                    void run(async () => {
                      setPeer(await client.peer(identityId, rootFingerprint));
                      setComparison('');
                      setIndependent(false);
                    })
                  }
                >
                  Read signed identity and comparison value
                </button>
                {peer && (
                  <>
                    <p>Verification status: {peer.verification.status}</p>
                    <p style={{ overflowWrap: 'anywhere' }}>
                      Compare all twelve groups with the other person:{' '}
                      <strong>{peer.safety.numeric}</strong>
                    </p>
                    <label>
                      Full numeric value read through the independent channel
                      <input
                        value={comparison}
                        onChange={(e) => setComparison(e.target.value)}
                        maxLength={71}
                      />
                    </label>
                    <label className="check">
                      <input
                        type="checkbox"
                        checked={independent}
                        onChange={(e) => setIndependent(e.target.checked)}
                      />
                      <span>
                        I compared this value with the intended person through an independent
                        trusted channel.
                      </span>
                    </label>
                    <button
                      className="btn"
                      disabled={busy || !independent}
                      onClick={() =>
                        void run(async () => {
                          await client.verify(peer.accountId, {
                            method: 'numeric',
                            comparison,
                            independent,
                            confirmed: true,
                          });
                          setPeer(await client.peer(identityId, rootFingerprint));
                          setMessage('Exact current account roots verified locally.');
                        })
                      }
                    >
                      Confirm independent comparison
                    </button>
                  </>
                )}
              </section>
              <section className="panel spaced">
                <h2>Named recipients</h2>
                <label>
                  Record type
                  <select
                    value={kind}
                    onChange={(e) => {
                      setKind(e.target.value);
                      setTarget('');
                      setFingerprint('');
                    }}
                  >
                    {['incident', 'help', 'correction', 'profile', 'operational_note'].map((k) => (
                      <option key={k}>{k}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Recipient device
                  <select
                    value={target}
                    onChange={(e) => {
                      setTarget(e.target.value);
                      setFingerprint('');
                    }}
                  >
                    <option value="">Choose a named staff device</option>
                    {devices
                      .filter(
                        (d) =>
                          d.accountId !== accountId && d.state === 'approved' && d.scope === kind,
                      )
                      .map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.label} · {d.accountId}
                        </option>
                      ))}
                  </select>
                </label>
                {devices.find((d) => d.id === target) && (
                  <p style={{ overflowWrap: 'anywhere' }}>
                    Identity ID: {devices.find((d) => d.id === target)?.identityId}
                    <br />
                    Device fingerprint: {devices.find((d) => d.id === target)?.fingerprint}
                  </p>
                )}
                <label>
                  Exact recipient device fingerprint confirmed independently
                  <input
                    value={fingerprint}
                    onChange={(e) => setFingerprint(e.target.value)}
                    maxLength={64}
                  />
                </label>
                {security &&
                  devices.map((d) => (
                    <article key={d.id}>
                      <p style={{ overflowWrap: 'anywhere' }}>
                        {d.label} · {d.fingerprint} · {d.state}
                      </p>
                      <button
                        className="btn outline"
                        disabled={busy || fingerprint !== d.fingerprint}
                        onClick={() =>
                          void run(async () => {
                            await request(
                              prefix + '/devices/' + d.id + '/approve',
                              {
                                fingerprint: d.fingerprint,
                                identityHash: d.identityHash,
                                scope: kind,
                                confirm: 'verified recipient identity independently',
                              },
                              csrf,
                            );
                            await refresh();
                          })
                        }
                      >
                        Approve exact fingerprint for selected type
                      </button>
                      <button
                        className="btn outline"
                        disabled={busy}
                        onClick={() =>
                          void run(async () => {
                            await request(
                              prefix + '/devices/' + d.id + '/quarantine',
                              { confirm: 'withdraw device routing access' },
                              csrf,
                            );
                            await refresh();
                          })
                        }
                      >
                        Withdraw future routing access
                      </button>
                    </article>
                  ))}
              </section>
              {intakeEnabled && (
                <>
                  <section className="panel spaced">
                    <h2>Your encrypted inbox</h2>
                    <button
                      className="btn outline"
                      disabled={busy}
                      onClick={() => void run(refresh)}
                    >
                      Refresh inbox
                    </button>
                    <ul>
                      {items.map((i) => (
                        <li key={i.id}>
                          <button className="text-button" onClick={() => void load(i.id)}>
                            {i.id} · {i.version} message(s)
                          </button>
                        </li>
                      ))}
                    </ul>
                    {localIds.map((id) => (
                      <p key={id}>
                        <code>{id}</code>{' '}
                        <button
                          className="btn outline"
                          disabled={busy}
                          onClick={() =>
                            void run(async () => {
                              await client.retry(id);
                              setOpened(await client.synchronize(id));
                              await refresh();
                            })
                          }
                        >
                          Retry exact pending encrypted message
                        </button>
                      </p>
                    ))}
                    {opened && (
                      <>
                        <h3>Record {opened.id}</h3>
                        <p>
                          {opened.status} · retention{' '}
                          {new Date(opened.retainUntil).toLocaleDateString()}
                        </p>
                        {opened.recipients.some((r) => !r.verified) && (
                          <p className="notice">
                            An original sender’s account root has not been independently verified.
                            Reading this signed message does not establish their real-world
                            identity. Verify before replying.
                          </p>
                        )}
                        {opened.messages.map((m, i) => (
                          <article key={i} className="panel spaced">
                            <h3>Message {i + 1}</h3>
                            <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                              {m.payload.text}
                            </p>
                            {!!m.payload.attachment && (
                              <>
                                <p>
                                  Quarantined attachment. Review untrusted files only on an approved
                                  device. This page does not execute or preview them.
                                </p>
                                <button
                                  className="btn outline"
                                  disabled={busy}
                                  onClick={() => void download(i + 1)}
                                >
                                  Download inert attachment for local review
                                </button>
                              </>
                            )}
                          </article>
                        ))}
                        {!!opened.draft && (
                          <p className="notice">
                            A competing message won the sequence. Your unsent draft remains in this
                            encrypted local vault. Review the thread before sending a new reply.
                          </p>
                        )}
                        {(['owner', 'safety-reviewer'].includes(role) ||
                          (role === 'editor' && opened.kind === 'correction')) &&
                          ['acknowledged', 'escalated', 'closed'].map((status) => (
                            <button
                              key={status}
                              className="btn outline"
                              disabled={busy}
                              onClick={() =>
                                void run(async () => {
                                  await request(
                                    prefix + '/records/' + opened.id + '/status',
                                    {
                                      deviceId: own.deviceId,
                                      status,
                                      version: opened.messages.length,
                                    },
                                    csrf,
                                  );
                                  setOpened(await client.synchronize(opened.id));
                                })
                              }
                            >
                              Mark {status}
                            </button>
                          ))}
                        {security && (
                          <>
                            <label>
                              Legal-hold evidence SHA-256
                              <input
                                value={holdDigest}
                                onChange={(e) => setHoldDigest(e.target.value)}
                                maxLength={64}
                              />
                            </label>
                            {[true, false].map((held) => (
                              <button
                                key={String(held)}
                                className="btn outline"
                                disabled={busy}
                                onClick={() =>
                                  void run(async () => {
                                    await request(
                                      prefix + '/records/' + opened.id + '/hold',
                                      { held, evidenceDigest: holdDigest },
                                      csrf,
                                    );
                                    setMessage(
                                      held ? 'Legal hold recorded.' : 'Legal hold released.',
                                    );
                                  })
                                }
                              >
                                {held ? 'Set legal hold' : 'Release legal hold'}
                              </button>
                            ))}
                          </>
                        )}
                        <button
                          className="btn outline"
                          onClick={() => {
                            setOpened(null);
                            setText('');
                            setFile(null);
                          }}
                        >
                          Start a new record
                        </button>
                      </>
                    )}
                  </section>
                  <form className="panel spaced" onSubmit={submit}>
                    <h2>{opened ? 'Reply to original recipients' : 'Write a protected message'}</h2>
                    <label>
                      Message
                      <textarea
                        required
                        maxLength={6000}
                        value={text}
                        onChange={(e) => setText(e.target.value)}
                      />
                    </label>
                    <label>
                      Optional private attachment (150 KB maximum)
                      <input type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} />
                    </label>
                    <button className="btn" disabled={busy || opened?.status === 'closed'}>
                      Encrypt & submit
                    </button>
                  </form>
                </>
              )}
              {security && (
                <section className="panel spaced">
                  <h2>Retention cleanup</h2>
                  <p>Ordinary encrypted records expire after 90 days. Active legal holds remain.</p>
                  <button
                    className="btn outline"
                    disabled={busy}
                    onClick={() =>
                      void run(async () => {
                        const result = await request<{ deleted: number }>(
                          prefix + '/lifecycle/purge',
                          {},
                          csrf,
                        );
                        setMessage(result.deleted + ' expired records deleted.');
                        await refresh();
                      })
                    }
                  >
                    Delete expired, unheld ciphertext
                  </button>
                </section>
              )}
            </>
          )}
        </>
      )}
    </>
  );
}
