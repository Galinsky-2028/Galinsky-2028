// Stateful MLS delivery: durable encrypted outbox before network, exact retry,
// atomic private KeyPackage consumption and thread checkpoint on recipient join.
import {
  canonical,
  publicProtectedKey,
  verifyProtected,
  unlockProtectedKey,
  signProtected,
} from '../../../packages/core/protected-crypto.mjs';
import {
  identityStateHash,
  applyProtectedIdentityEvent,
} from '../../../packages/core/protected-identity.mjs';
import {
  MLS_PROFILE,
  newMlsKeyPackage,
  createProtectedMlsGroup,
  joinProtectedMlsGroup,
  sealProtectedMls,
  openProtectedMls,
  storeMlsState,
  restoreMlsState,
} from '../../../packages/core/protected-mls.mjs';
import {
  protectedMlsEnvelope,
  encodeProtectedMlsBundle,
} from '../../../packages/core/protected-mls-envelope.mjs';
import {
  encryptProtectedAttachment,
  decryptProtectedAttachment,
} from '../../../packages/core/protected-attachment.mjs';
import {
  sealProtectedThreadVault,
  openProtectedThreadVault,
} from '../../../packages/core/protected-vault.mjs';
import {
  protectedSafetyValue,
  reconcileProtectedSafety,
} from '../../../packages/core/protected-verification.mjs';
import {
  threadEntry,
  protectedLocalGet,
  protectedLocalList,
  protectedLocalCommit,
} from './protected-local.mjs';
const prefix = '/api/protected/v2',
  need = (x, msg) => {
    if (!x) throw Error(msg);
  };
export async function expireProtectedLocalThreads(account, session, token, guard) {
  const rows = await protectedLocalList(account);
  guard(token);
  for (const row of rows.filter((r) => r.key.startsWith('thread:'))) {
    const id = row.key.split(':').at(-1),
      value = await openProtectedThreadVault(session, row.envelope, {
        record: id,
        minGeneration: row.generation,
      });
    guard(token);
    if (!value.pending || Date.now() - value.pending.createdAt <= 86400000) continue;
    value.draft = value.pending.payload;
    value.pending = null;
    value.state = null;
    value.lostState = true;
    const generation = row.generation + 1,
      envelope = await sealProtectedThreadVault(session, {
        record: id,
        generation,
        payload: value,
      });
    guard(token);
    await protectedLocalCommit([
      { key: row.key, expected: row.generation, next: { ...row, generation, envelope } },
    ]);
    guard(token);
  }
}
export function createProtectedThreads({
  account,
  api,
  exclusive,
  save,
  guard,
  getSession,
  history,
}) {
  async function readLocal(id) {
    const row = await protectedLocalGet(threadEntry(account, id));
    return {
      row,
      value: row
        ? await openProtectedThreadVault(getSession(), row.envelope, {
            record: id,
            minGeneration: row.generation,
          })
        : null,
    };
  }
  async function persist(root, payload, token, id, local, value) {
    const generation = (local?.generation || 0) + 1,
      envelope = await sealProtectedThreadVault(getSession(), {
        record: id,
        generation,
        payload: value,
      });
    guard(token);
    const next = {
      key: threadEntry(account, id),
      account,
      device: getSession().device,
      generation,
      envelope,
    };
    const row = await save(root, payload, token, {
      key: next.key,
      expected: local?.generation || 0,
      next,
    });
    return { row, local: next };
  }
  async function currentHeads(root, payload, token, keys, verified) {
    const identities = new Map(),
      own = await api(prefix + '/identity');
    guard(token);
    const mine = await history(own, {
      identityId: payload.identity.identityId,
      sequence: payload.identity.sequence,
      hash: payload.identityHash,
    });
    identities.set(mine.state.identityId, mine);
    payload.identity = mine.state;
    payload.identityHash = mine.hash;
    for (const key of keys) {
      if (identities.has(key.identityId)) continue;
      const contact = payload.contacts[key.accountId];
      need(
        contact?.identityId === key.identityId,
        'Compare and pin this recipient’s current account root independently first.',
      );
      let packet;
      try {
        packet = await api(
          prefix +
            '/identities/' +
            contact.identityId +
            '?fingerprint=' +
            contact.state.rootFingerprint,
        );
      } catch (error) {
        contact.verification = { ...contact.verification, status: 'invalidated' };
        await save(root, payload, token);
        throw error;
      }
      guard(token);
      let checked;
      try {
        checked = await history(packet, contact.anchor);
      } catch (error) {
        contact.verification = { ...contact.verification, status: 'invalidated' };
        await save(root, payload, token);
        throw error;
      }
      const safety = await protectedSafetyValue(mine.state, checked.state);
      contact.verification = reconcileProtectedSafety(contact.verification, safety);
      contact.state = checked.state;
      contact.anchor = {
        identityId: checked.state.identityId,
        sequence: checked.state.sequence,
        hash: checked.hash,
      };
      if (verified && contact.verification.status !== 'verified') {
        await save(root, payload, token);
        throw Error(
          'Recipient verification changed. Compare the current numeric value through an independent trusted channel.',
        );
      }
      identities.set(checked.state.identityId, checked);
    }
    for (const key of keys) {
      const signed = identities.get(key.identityId)?.state.devices.find((d) => d.id === key.device);
      need(
        signed?.state === 'active' &&
          signed.generation === key.generation &&
          signed.publicKey === key.publicKey &&
          signed.mlsSigningKey === key.signatureKey,
        'An original recipient device changed. Start a fresh verified group.',
      );
    }
    return [...identities.values()]
      .map((x) => ({ id: x.state.identityId, sequence: x.state.sequence, hash: x.hash }))
      .sort((a, b) => a.id.localeCompare(b.id));
  }
  async function packagePayload(text, attachment, parent) {
    need(
      typeof text === 'string' && text.trim().length > 0 && text.length <= 6000,
      'Enter a message of at most 6,000 characters.',
    );
    const payload = { text: text.trim() };
    let chunks = [];
    if (attachment) {
      const encrypted = await encryptProtectedAttachment(attachment, parent);
      payload.attachment = encrypted.manifest;
      chunks = encrypted.chunks;
    }
    return { payload, chunks };
  }
  async function signedFrame(context, bundle, payload) {
    const key = await unlockProtectedKey(payload.device.privateKey, payload.device.secret),
      unsigned = { context, ciphertext: encodeProtectedMlsBundle(bundle) };
    return { ...unsigned, signature: await signProtected(unsigned, key) };
  }
  async function acknowledge(root, payload, token, id, local, value) {
    const pending = value.pending;
    need(pending, 'No pending encrypted message exists.');
    need(
      Date.now() - pending.createdAt <= 86400000,
      'This pending message expired. Explicitly discard its draft before starting again.',
    );
    const receipt = await api(prefix + '/records', pending.frame);
    guard(token);
    need(
      receipt.id === id && receipt.version >= pending.frame.context.sequence,
      'The encrypted message acknowledgement did not match.',
    );
    value.state = pending.after;
    value.messages.push({ frame: pending.frame, payload: pending.payload });
    value.pending = null;
    await persist(root, payload, token, id, local, value);
    return { id, version: value.messages.length };
  }
  async function send({ kind, devices, fingerprints, text, attachment }) {
    return exclusive(async ({ row, token, payload }) => {
      need(
        Array.isArray(devices) &&
          devices.length >= 1 &&
          devices.length <= 11 &&
          new Set(devices).size === devices.length,
        'Choose one to eleven exact recipient devices.',
      );
      let after = null,
        directory = [];
      do {
        const page = await api(
          prefix + '/directory?kind=' + encodeURIComponent(kind) + (after ? '&after=' + after : ''),
        );
        guard(token);
        directory.push(...page.devices);
        after = page.next;
      } while (after && directory.length < 1000);
      const own = payload.identity.devices.find((d) => d.id === getSession().device),
        keys = [
          {
            device: own.id,
            identityId: payload.identity.identityId,
            accountId: account,
            generation: own.generation,
            publicKey: own.publicKey,
            signatureKey: own.mlsSigningKey,
          },
        ];
      for (const id of devices) {
        const d = directory.find(
          (x) =>
            x.id === id && x.accountId !== account && x.state === 'approved' && x.scope === kind,
        );
        need(
          d && fingerprints?.[id] === d.fingerprint,
          'Independently confirm the exact selected recipient device fingerprint.',
        );
        keys.push({
          device: d.id,
          identityId: d.identityId,
          accountId: d.accountId,
          generation: d.generation,
          publicKey: d.publicKey,
          signatureKey: d.mlsSigningKey,
        });
      }
      keys.sort((a, b) => a.device.localeCompare(b.device));
      const heads = await currentHeads(row, payload, token, keys, true);
      guard(token);
      const id = crypto.randomUUID(),
        recipients = keys.map((k) => k.device).sort(),
        key = await unlockProtectedKey(payload.device.privateKey, payload.device.secret),
        proof = {
          action: 'claim',
          profile: MLS_PROFILE,
          recordId: id,
          deviceId: getSession().device,
          recipients,
          kind,
          generation: own.generation,
        },
        claim = await api(prefix + '/claims', {
          recordId: id,
          deviceId: getSession().device,
          recipients,
          kind,
          generation: own.generation,
          signature: await signProtected(proof, key),
        });
      guard(token);
      need(
        canonical(heads) === canonical(claim.identityHeads),
        'Recipient identity changed during package reservation. No message was sent.',
      );
      need(
        canonical(claim.members) ===
          canonical(keys.map((k) => ({ device: k.device, signatureKey: k.signatureKey }))),
        'The one-time package roster does not match the verified root-signed device keys. No message was sent.',
      );
      need(
        canonical(claim.packages.map((p) => p.device).sort()) ===
          canonical(recipients.filter((d) => d !== getSession().device)),
        'The package reservation changed the exact recipient devices.',
      );
      const pair = await newMlsKeyPackage(getSession().device, payload.mls),
        created = await createProtectedMlsGroup({
          groupId: id,
          own: { device: getSession().device, package: pair },
          others: claim.packages.map((p) => ({ device: p.device, wire: p.wire })),
          members: claim.members,
        });
      guard(token);
      const context = {
          profile: MLS_PROFILE,
          recordId: id,
          sequence: 1,
          kind,
          sender: getSession().device,
          recipients,
          generation: own.generation,
          epoch: 2,
          identityHeads: heads,
        },
        privateContent = await packagePayload(text, attachment, id + ':1'),
        before = storeMlsState(created.state),
        sent = await sealProtectedMls({
          state: created.state,
          context,
          payload: privateContent.payload,
          members: claim.members,
        }),
        bundle = {
          format: 'g28-mls-record-v1',
          members: claim.members,
          setup: {
            claimId: id,
            creatorPackage: pair.wire,
            membershipCommit: created.membershipCommit,
            welcome: created.welcome,
            packages: claim.packages.map(({ device, id, hash }) => ({ device, id, hash })),
          },
          commit: sent.commit,
          message: sent.message,
          chunks: privateContent.chunks,
        },
        frame = await signedFrame(context, bundle, payload);
      guard(token);
      const value = {
        version: 1,
        id,
        kind,
        members: claim.members,
        keys,
        state: before,
        messages: [],
        pending: {
          createdAt: Date.now(),
          before,
          after: storeMlsState(sent.state),
          frame,
          payload: privateContent.payload,
        },
        draft: null,
      };
      const saved = await persist(row, payload, token, id, null, value);
      return acknowledge(saved.row, payload, token, id, saved.local, value);
    });
  }
  async function synchronize(id) {
    return exclusive(async ({ row, token, payload }) => {
      const response = await api(prefix + '/records/' + id + '?deviceId=' + getSession().device);
      guard(token);
      const record = response.record;
      need(record.id === id && record.protocol === MLS_PROFILE, 'Unsupported protected record.');
      const keys = record.memberKeys
          .map((k) => ({
            device: k.device,
            identityId: k.identityId,
            accountId: k.accountId,
            generation: k.generation,
            publicKey: k.publicKey,
            signatureKey: k.signatureKey,
          }))
          .sort((a, b) => a.device.localeCompare(b.device)),
        members = keys
          .map((k) => ({ device: k.device, signatureKey: k.signatureKey }))
          .sort((a, b) => a.device.localeCompare(b.device));
      // Authenticated signed history for every frame, independent of directory labels.
      const chains = new Map();
      for (const packet of response.identities) {
        let state = packet.initialState;
        const states = new Map([[state.sequence, { state, hash: await identityStateHash(state) }]]);
        for (const item of packet.events) {
          state = await applyProtectedIdentityEvent(
            state,
            item.document,
            item.rootSignature,
            item.deviceSignature,
          );
          const hash = await identityStateHash(state);
          need(hash === item.stateHash, 'An identity event hash was altered.');
          states.set(state.sequence, { state, hash });
        }
        await history({
          identity: state,
          stateHash: await identityStateHash(state),
          history: packet,
        });
        chains.set(state.identityId, states);
      }
      for (const message of record.messages) {
        const parsed = protectedMlsEnvelope(message);
        need(
          canonical(parsed.bundle.members) === canonical(members),
          'The thread recipient set changed.',
        );
        for (const key of keys) {
          const head = message.context.identityHeads.find((h) => h.id === key.identityId),
            signed = head && chains.get(head.id)?.get(head.sequence),
            d = signed?.state.devices.find((d) => d.id === key.device);
          need(
            signed?.state.accountId === key.accountId &&
              signed?.hash === head?.hash &&
              d?.state === 'active' &&
              d.generation === key.generation &&
              d.publicKey === key.publicKey &&
              d.mlsSigningKey === key.signatureKey,
            'The thread lacks valid root-signed original device authority.',
          );
        }
        const sender = keys.find((k) => k.device === message.context.sender);
        need(
          sender &&
            (await verifyProtected(
              { context: message.context, ciphertext: message.ciphertext },
              message.signature,
              (await publicProtectedKey(sender.publicKey)).key,
            )),
          'An encrypted message sender signature failed.',
        );
      }
      // Check current roots/generations too: old history cannot authorize new data.
      // Reading an unverified reporter is permitted but never labels them verified.
      for (const key of keys) {
        if (key.accountId === account || payload.contacts[key.accountId]) continue;
        const states = chains.get(key.identityId),
          latest = [...states.values()].at(-1);
        payload.contacts[key.accountId] = {
          identityId: key.identityId,
          state: latest.state,
          anchor: {
            identityId: key.identityId,
            sequence: latest.state.sequence,
            hash: latest.hash,
          },
          verification: { status: 'unverified' },
        };
      }
      await currentHeads(row, payload, token, keys, false);
      guard(token);
      const local = await readLocal(id);
      guard(token);
      let value = local.value;
      need(
        !value?.lostState,
        'This thread’s unacknowledged encryption state expired. Its draft remains local; start a fresh verified record.',
      );
      if (value?.pending) {
        const pending = value.pending,
          winner = record.messages[pending.frame.context.sequence - 1];
        if (winner) {
          if (canonical(winner) === canonical(pending.frame)) {
            value.state = pending.after;
            value.messages.push({ frame: pending.frame, payload: pending.payload });
            value.pending = null;
          } else {
            value.state = pending.before;
            value.draft = pending.payload;
            value.pending = null;
          }
        } else {
          need(
            Date.now() - pending.createdAt <= 86400000,
            'This pending draft expired. Explicitly discard it.',
          );
          throw Error(
            'An encrypted message is awaiting acknowledgement. Retry the exact pending message before advancing.',
          );
        }
      }
      if (!value) {
        const first = protectedMlsEnvelope(record.messages[0]),
          setup = first.bundle.setup,
          entry = setup.packages.find((p) => p.device === getSession().device),
          pair = entry && payload.packages[entry.id];
        need(
          pair,
          'The original one-time private key is absent from this browser. Recovery cannot recreate thread history.',
        );
        const joined = await joinProtectedMlsGroup({
          groupId: id,
          welcome: setup.welcome,
          own: { device: getSession().device, package: pair },
          members,
        });
        guard(token);
        value = {
          version: 1,
          id,
          kind: record.kind,
          members,
          keys,
          state: storeMlsState(joined),
          messages: [],
          pending: null,
          draft: null,
        };
        delete payload.packages[entry.id];
      }
      need(canonical(value.keys) === canonical(keys), 'Original thread keys changed.');
      for (let i = 0; i < value.messages.length; i++)
        need(
          canonical(value.messages[i].frame) === canonical(record.messages[i]),
          'The server rolled back or replaced accepted thread history.',
        );
      for (const message of record.messages.slice(value.messages.length)) {
        const parsed = protectedMlsEnvelope(message),
          opened = await openProtectedMls({
            state: restoreMlsState(value.state, members, id),
            context: message.context,
            commit: parsed.bundle.commit,
            message: parsed.bundle.message,
            members,
          });
        guard(token);
        value.state = storeMlsState(opened.state);
        value.messages.push({ frame: message, payload: opened.payload });
      }
      await persist(row, payload, token, id, local.row, value);
      return {
        id,
        kind: record.kind,
        status: record.status,
        retainUntil: record.retainUntil,
        messages: value.messages.map((m) => ({ context: m.frame.context, payload: m.payload })),
        draft: value.draft,
        recipients: keys.map((k) => ({
          device: k.device,
          account: k.accountId,
          verified:
            k.accountId === account ||
            payload.contacts[k.accountId]?.verification?.status === 'verified',
        })),
      };
    });
  }
  async function reply({ id, text, attachment }) {
    return exclusive(async ({ row, token, payload }) => {
      const local = await readLocal(id),
        value = local.value;
      guard(token);
      need(
        value && !value.pending && !value.lostState,
        'Open and synchronize this record before replying.',
      );
      const heads = await currentHeads(row, payload, token, value.keys, true),
        own = value.keys.find((k) => k.device === getSession().device),
        sequence = value.messages.length + 1,
        context = {
          profile: MLS_PROFILE,
          recordId: id,
          sequence,
          kind: value.kind,
          sender: getSession().device,
          recipients: value.keys.map((k) => k.device).sort(),
          generation: own.generation,
          epoch: sequence + 1,
          identityHeads: heads,
        },
        content = await packagePayload(text, attachment, id + ':' + sequence),
        before = value.state,
        sent = await sealProtectedMls({
          state: restoreMlsState(before, value.members, id),
          context,
          payload: content.payload,
          members: value.members,
        }),
        bundle = {
          format: 'g28-mls-record-v1',
          members: value.members,
          setup: null,
          commit: sent.commit,
          message: sent.message,
          chunks: content.chunks,
        },
        frame = await signedFrame(context, bundle, payload);
      guard(token);
      value.pending = {
        createdAt: Date.now(),
        before,
        after: storeMlsState(sent.state),
        frame,
        payload: content.payload,
      };
      const saved = await persist(row, payload, token, id, local.row, value);
      return acknowledge(saved.row, payload, token, id, saved.local, value);
    });
  }
  async function retry(id) {
    return exclusive(async ({ row, token, payload }) => {
      const local = await readLocal(id);
      guard(token);
      need(local.value?.pending, 'No pending message exists.');
      return acknowledge(row, payload, token, id, local.row, local.value);
    });
  }
  async function attachment(id, sequence) {
    return exclusive(async ({ token }) => {
      const local = await readLocal(id);
      guard(token);
      const message = local.value?.messages[sequence - 1];
      need(message?.payload?.attachment, 'No attachment exists.');
      const bundle = protectedMlsEnvelope(message.frame).bundle,
        result = await decryptProtectedAttachment(
          message.payload.attachment,
          bundle.chunks,
          id + ':' + sequence,
        );
      guard(token);
      return result;
    });
  }
  return {
    send,
    reply,
    synchronize,
    retry,
    attachment,
    expirePending: () => exclusive(async () => ({ expiredChecked: true })),
  };
}
