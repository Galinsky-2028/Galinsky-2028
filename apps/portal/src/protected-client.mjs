// Browser-local key custody. Only public signed identity transitions cross api().
import {
  newProtectedKey,
  publicProtectedKey,
  verifyProtected,
  unlockProtectedKey,
  signProtected,
  canonical,
} from '../../../packages/core/protected-crypto.mjs';
import {
  initialProtectedIdentity,
  protectedIdentityEvent,
  applyProtectedIdentityEvent,
  identityStateHash,
} from '../../../packages/core/protected-identity.mjs';
import { newMlsSigningKeys, newMlsKeyPackage } from '../../../packages/core/protected-mls.mjs';
import {
  createProtectedDeviceVault,
  unlockProtectedDeviceVault,
  updateProtectedDeviceVault,
  resumeProtectedDeviceVault,
  lockProtectedVault,
} from '../../../packages/core/protected-vault.mjs';
import {
  protectedSafetyValue,
  confirmProtectedSafety,
  reconcileProtectedSafety,
} from '../../../packages/core/protected-verification.mjs';
import { createProtectedThreads, expireProtectedLocalThreads } from './protected-threads.mjs';
import {
  deviceEntry,
  pendingDeviceEntry,
  protectedLocalGet,
  protectedLocalCommit,
  withProtectedLock,
} from './protected-local.mjs';
const prefix = '/api/protected/v2';
const need = (condition, message) => {
  if (!condition) throw Error(message);
};
const secret = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(32)), (x) =>
    x.toString(16).padStart(2, '0'),
  ).join('');
export function createProtectedClient({ account, api, onLock = () => {} }) {
  let session = null,
    epoch = 0,
    closed = false;
  const channel =
    typeof BroadcastChannel === 'function' ? new BroadcastChannel('g28-protected-lock') : null;
  function lock(broadcast = true) {
    epoch++;
    lockProtectedVault(session);
    session = null;
    onLock();
    if (broadcast) channel?.postMessage({ account, action: 'lock' });
  }
  if (channel)
    channel.onmessage = (e) => {
      if (e.data?.account === account && e.data.action === 'lock') lock(false);
    };
  const guard = (token) =>
    need(!closed && epoch === token, 'The protected device was locked. Unlock before continuing.');
  async function exclusive(fn) {
    const token = epoch;
    return withProtectedLock(account, async () => {
      guard(token);
      need(session?.active, 'Unlock this browser’s protected device first.');
      const row = await protectedLocalGet(deviceEntry(account));
      guard(token);
      need(
        row && row.device === session.device,
        'This browser’s device changed. Lock and unlock again.',
      );
      await resumeProtectedDeviceVault(row.envelope, session);
      guard(token);
      await expireProtectedLocalThreads(account, session, token, guard);
      guard(token);
      return fn({ row, token, payload: structuredClone(session.payload) });
    });
  }
  async function save(row, payload, token, threadChange) {
    guard(token);
    const result = await updateProtectedDeviceVault(row.envelope, session, payload);
    guard(token);
    const next = { ...row, generation: result.generation, envelope: result.envelope };
    await protectedLocalCommit([
      { key: row.key, expected: row.generation, next },
      ...(threadChange ? [threadChange] : []),
    ]);
    guard(token);
    session.generation = result.generation;
    session.payload = payload;
    return next;
  }
  async function history(packet, anchor) {
    need(
      packet?.history?.initialState && Array.isArray(packet.history.events),
      'The server did not supply a signed identity history.',
    );
    let state = packet.history.initialState;
    const hashes = new Map([[state.sequence, await identityStateHash(state)]]);
    const initial = await initialProtectedIdentity({
      accountId: state.accountId,
      identityId: state.identityId,
      rootPublicKey: state.rootPublicKey,
    });
    need(
      canonical(initial) === canonical(state),
      'The identity history did not start at its account root.',
    );
    for (const item of packet.history.events) {
      state = await applyProtectedIdentityEvent(
        state,
        item.document,
        item.rootSignature,
        item.deviceSignature,
      );
      const hash = await identityStateHash(state);
      need(hash === item.stateHash, 'The signed identity history was altered.');
      hashes.set(state.sequence, hash);
    }
    const hash = await identityStateHash(state);
    need(
      canonical(state) === canonical(packet.identity) && hash === packet.stateHash,
      'The public identity does not match its signed history.',
    );
    if (anchor)
      need(
        state.identityId === anchor.identityId &&
          state.sequence >= anchor.sequence &&
          hashes.get(anchor.sequence) === anchor.hash,
        'The server rolled back or replaced a pinned identity. Reverify the new root independently.',
      );
    return { state, hash };
  }
  async function enroll(password, label, acknowledgeNoRecovery = false) {
    need(
      acknowledgeNoRecovery === true,
      'Acknowledge permanent key loss without a recovery backup before creating keys.',
    );
    need(
      typeof password === 'string' && password.length >= 16,
      'Use a local unlock phrase of at least 16 characters.',
    );
    const token = epoch;
    return withProtectedLock(account, async () => {
      guard(token);
      need(
        !(await protectedLocalGet(deviceEntry(account))),
        'This browser already has a protected device. Unlock it instead.',
      );
      const pending = await protectedLocalGet(pendingDeviceEntry(account));
      need(
        !pending,
        'A device enrollment is pending. Unlock it and retry its exact signed transition.',
      );
      const current = await api(prefix + '/identity');
      guard(token);
      need(
        !current.identity,
        'This account already has an identity. Enroll from an authorized root device or explicitly replace the identity.',
      );
      const rootSecret = secret(),
        deviceSecret = secret(),
        root = await newProtectedKey(account, rootSecret),
        device = await newProtectedKey(account, deviceSecret),
        mls = await newMlsSigningKeys();
      guard(token);
      const identityId = crypto.randomUUID(),
        deviceId = crypto.randomUUID(),
        initial = await initialProtectedIdentity({
          accountId: account,
          identityId,
          rootPublicKey: root.publicKey,
        }),
        event = await protectedIdentityEvent(initial, {
          id: crypto.randomUUID(),
          action: 'enroll',
          subject: {
            id: deviceId,
            generation: 1,
            publicKey: device.publicKey,
            mlsSigningKey: mls.publicKey,
          },
        }),
        rootKey = await unlockProtectedKey(root.privateKey, rootSecret),
        deviceKey = await unlockProtectedKey(device.privateKey, deviceSecret);
      const transition = {
        identityId,
        rootPublicKey: root.publicKey,
        event,
        rootSignature: await signProtected(event, rootKey),
        deviceSignature: await signProtected(event, deviceKey),
        label,
        replace: false,
        confirm: 'authorize this signed device transition',
      };
      const state = await applyProtectedIdentityEvent(
          initial,
          event,
          transition.rootSignature,
          transition.deviceSignature,
        ),
        hash = await identityStateHash(state),
        payload = {
          version: 1,
          root: { ...root, secret: rootSecret },
          device: { ...device, secret: deviceSecret, id: deviceId },
          mls,
          identity: state,
          identityHash: hash,
          contacts: {},
          packages: {},
          pendingTransition: transition,
        };
      const vault = await createProtectedDeviceVault({
        account,
        device: deviceId,
        password,
        payload,
      });
      guard(token);
      const row = {
        key: pendingDeviceEntry(account),
        account,
        device: deviceId,
        generation: 1,
        envelope: vault.envelope,
      };
      try {
        await protectedLocalCommit([{ key: row.key, expected: 0, next: row }]);
        guard(token);
        session = vault.session;
        return await finishEnrollment(row, token);
      } catch (error) {
        lockProtectedVault(vault.session);
        session = null;
        throw error;
      }
    });
  }
  async function finishEnrollment(row, token) {
    guard(token);
    const transition = session.payload.pendingTransition;
    need(transition, 'No signed enrollment is pending.');
    let result;
    if (transition.rootSignature) {
      result = await api(prefix + '/identity', transition);
      guard(token);
    }
    const packet = await api(prefix + '/identity');
    guard(token);
    const checked = await history(packet, {
      identityId: session.payload.identity.identityId,
      sequence: session.payload.identity.sequence,
      hash: session.payload.identityHash,
    });
    guard(token);
    need(
      !result || result.state.identityId === checked.state.identityId,
      'Enrollment acknowledgement belongs to another identity.',
    );
    const accepted = packet.history.events.find((e) => e.document.id === transition.event.id);
    need(
      accepted &&
        canonical(accepted.document) === canonical(transition.event) &&
        accepted.deviceSignature === transition.deviceSignature,
      'The root device has not authorized this exact enrollment yet.',
    );
    const own = checked.state.devices.find((d) => d.id === session.device);
    need(
      own?.state === 'active' &&
        own.publicKey === session.payload.device.publicKey &&
        own.mlsSigningKey === session.payload.mls.publicKey,
      'The authorized device keys do not match this local vault.',
    );
    const payload = {
      ...session.payload,
      identity: checked.state,
      identityHash: checked.hash,
      pendingTransition: null,
    };
    const updated = await updateProtectedDeviceVault(row.envelope, session, payload);
    guard(token);
    const next = {
      ...row,
      key: deviceEntry(account),
      generation: updated.generation,
      envelope: updated.envelope,
    };
    await protectedLocalCommit([
      { key: row.key, expected: row.generation, next: null },
      { key: next.key, expected: 0, next },
    ]);
    guard(token);
    session.generation = next.generation;
    session.payload = payload;
    return publicState();
  }
  async function unlock(password) {
    lock();
    const token = epoch;
    return withProtectedLock(account, async () => {
      const pending = await protectedLocalGet(pendingDeviceEntry(account)),
        row = pending || (await protectedLocalGet(deviceEntry(account)));
      guard(token);
      need(row, 'No protected device exists in this browser.');
      let opened;
      try {
        opened = await unlockProtectedDeviceVault(row.envelope, password, {
          account,
          device: row.device,
          minGeneration: row.generation,
        });
      } catch {
        throw Error('The local unlock phrase or encrypted vault could not be authenticated.');
      }
      try {
        guard(token);
        session = opened;
        if (pending) return await finishEnrollment(pending, token);
        const packet = await api(prefix + '/identity');
        guard(token);
        const checked = await history(packet, {
          identityId: session.payload.identity.identityId,
          sequence: session.payload.identity.sequence,
          hash: session.payload.identityHash,
        });
        guard(token);
        const own = checked.state.devices.find((d) => d.id === row.device);
        need(
          own?.state === 'active' &&
            own.publicKey === session.payload.device.publicKey &&
            own.mlsSigningKey === session.payload.mls.publicKey,
          'This device was revoked or its keys changed.',
        );
        await save(
          row,
          { ...session.payload, identity: checked.state, identityHash: checked.hash },
          token,
        );
        await expireProtectedLocalThreads(account, session, token, guard);
        guard(token);
        return publicState();
      } catch (error) {
        lockProtectedVault(opened);
        session = null;
        throw error;
      }
    });
  }
  function publicState() {
    need(session?.active, 'Unlock this device first.');
    const p = session.payload;
    return {
      deviceId: session.device,
      identityId: p.identity.identityId,
      rootFingerprint: p.identity.rootFingerprint,
      deviceFingerprint: p.identity.devices.find((d) => d.id === session.device).fingerprint,
      hasRoot: !!p.root,
      sequence: p.identity.sequence,
    };
  }
  async function peer(identityId, fingerprint) {
    return exclusive(async ({ row, token, payload }) => {
      const packet = await api(
        prefix +
          '/identities/' +
          encodeURIComponent(identityId) +
          '?fingerprint=' +
          encodeURIComponent(fingerprint),
      );
      guard(token);
      // Root replacement invalidates the previous account pin before returning UI data.
      const accountId = packet.identity?.accountId,
        previous = payload.contacts[accountId];
      let checked;
      try {
        if (previous?.identityId === identityId) checked = await history(packet, previous.anchor);
        else checked = await history(packet);
      } catch (error) {
        if (previous) {
          previous.verification = { ...previous.verification, status: 'invalidated' };
          await save(row, payload, token);
        }
        throw error;
      }
      guard(token);
      const safety = await protectedSafetyValue(payload.identity, checked.state),
        verification = reconcileProtectedSafety(previous?.verification, safety),
        contact = {
          identityId,
          state: checked.state,
          anchor: { identityId, sequence: checked.state.sequence, hash: checked.hash },
          verification,
        };
      payload.contacts[accountId] = contact;
      await save(row, payload, token);
      return { accountId, state: checked.state, safety, verification };
    });
  }
  async function verify(accountId, comparison) {
    return exclusive(async ({ row, token, payload }) => {
      const contact = payload.contacts[accountId];
      need(contact, 'Read and check the current public identity first.');
      const packet = await api(
        prefix +
          '/identities/' +
          contact.identityId +
          '?fingerprint=' +
          contact.state.rootFingerprint,
      );
      guard(token);
      let checked;
      try {
        checked = await history(packet, contact.anchor);
      } catch (error) {
        contact.verification = { ...contact.verification, status: 'invalidated' };
        await save(row, payload, token);
        throw error;
      }
      const safety = await protectedSafetyValue(payload.identity, checked.state);
      guard(token);
      contact.verification = confirmProtectedSafety(safety, comparison);
      contact.state = checked.state;
      contact.anchor = {
        identityId: contact.identityId,
        sequence: checked.state.sequence,
        hash: checked.hash,
      };
      await save(row, payload, token);
      return contact.verification;
    });
  }
  async function prepareLinked(
    password,
    identityId,
    rootFingerprint,
    label,
    acknowledgeNoRecovery = false,
  ) {
    need(
      acknowledgeNoRecovery === true,
      'Acknowledge permanent key loss without a recovery backup before creating keys.',
    );
    const token = epoch;
    return withProtectedLock(account, async () => {
      guard(token);
      need(
        !(await protectedLocalGet(deviceEntry(account))) &&
          !(await protectedLocalGet(pendingDeviceEntry(account))),
        'Unlock the existing or pending local device first.',
      );
      const packet = await api(
        prefix +
          '/identities/' +
          encodeURIComponent(identityId) +
          '?fingerprint=' +
          encodeURIComponent(rootFingerprint),
      );
      guard(token);
      const checked = await history(packet);
      need(checked.state.accountId === account, 'Enroll only into your own account root.');
      const deviceSecret = secret(),
        device = await newProtectedKey(account, deviceSecret),
        mls = await newMlsSigningKeys(),
        deviceId = crypto.randomUUID(),
        event = await protectedIdentityEvent(checked.state, {
          id: crypto.randomUUID(),
          action: 'enroll',
          subject: {
            id: deviceId,
            generation: 1,
            publicKey: device.publicKey,
            mlsSigningKey: mls.publicKey,
          },
        }),
        deviceKey = await unlockProtectedKey(device.privateKey, deviceSecret),
        transition = {
          identityId,
          rootPublicKey: checked.state.rootPublicKey,
          event,
          rootSignature: null,
          deviceSignature: await signProtected(event, deviceKey),
          label,
          replace: false,
          confirm: 'authorize this signed device transition',
        },
        payload = {
          version: 1,
          root: null,
          device: { ...device, secret: deviceSecret, id: deviceId },
          mls,
          identity: checked.state,
          identityHash: checked.hash,
          contacts: {},
          packages: {},
          pendingTransition: transition,
        };
      const vault = await createProtectedDeviceVault({
        account,
        device: deviceId,
        password,
        payload,
      });
      try {
        guard(token);
        const row = {
          key: pendingDeviceEntry(account),
          account,
          device: deviceId,
          generation: 1,
          envelope: vault.envelope,
        };
        await protectedLocalCommit([{ key: row.key, expected: 0, next: row }]);
        guard(token);
        return {
          request: transition,
          deviceFingerprint: (await publicProtectedKey(device.publicKey)).fingerprint,
        };
      } finally {
        lockProtectedVault(vault.session);
      }
    });
  }
  async function authorizeLinked(request, fingerprint) {
    return exclusive(async ({ row, token, payload }) => {
      need(payload.root, 'Use the device holding this account root to authorize enrollment.');
      need(
        request?.rootSignature === null &&
          request.replace === false &&
          request.identityId === payload.identity.identityId &&
          request.rootPublicKey === payload.identity.rootPublicKey &&
          request.event?.action === 'enroll' &&
          request.event.subject.generation === 1,
        'Review an exact new-device enrollment request for this root.',
      );
      const publicKey = await publicProtectedKey(request.event.subject.publicKey);
      need(
        publicKey.fingerprint === fingerprint,
        'Confirm the new device fingerprint through a separate trusted channel.',
      );
      need(
        await verifyProtected(request.event, request.deviceSignature, publicKey.key),
        'The new device did not prove possession of its signing key.',
      );
      const current = await api(prefix + '/identity');
      guard(token);
      const checked = await history(current, {
        identityId: payload.identity.identityId,
        sequence: payload.identity.sequence,
        hash: payload.identityHash,
      });
      const prior = current.history.events.find((e) => e.document.id === request.event.id);
      if (prior) {
        need(
          canonical(prior.document) === canonical(request.event) &&
            prior.deviceSignature === request.deviceSignature,
          'The enrollment request conflicts with an accepted event.',
        );
        await save(row, { ...payload, identity: checked.state, identityHash: checked.hash }, token);
        return { authorized: true };
      }
      const rootKey = await unlockProtectedKey(payload.root.privateKey, payload.root.secret),
        rootSignature = await signProtected(request.event, rootKey);
      await applyProtectedIdentityEvent(
        checked.state,
        request.event,
        rootSignature,
        request.deviceSignature,
      );
      guard(token);
      await api(prefix + '/identity', { ...request, rootSignature });
      guard(token);
      const accepted = await history(await api(prefix + '/identity'), {
        identityId: checked.state.identityId,
        sequence: checked.state.sequence,
        hash: checked.hash,
      });
      guard(token);
      await save(row, { ...payload, identity: accepted.state, identityHash: accepted.hash }, token);
      return { authorized: true };
    });
  }
  async function publishPackages(count = 4) {
    need(
      Number.isInteger(count) && count >= 1 && count <= 8,
      'Publish at most eight one-time packages.',
    );
    return exclusive(async ({ row, token, payload }) => {
      // Persist private packages before publishing public bytes. Retry unchanged
      // entries after a lost ACK: the server never recycles a reserved package.
      let pending = Object.entries(payload.packages).filter(([, p]) => p.pending);
      if (!pending.length) {
        for (let i = 0; i < count; i++) {
          const id = crypto.randomUUID(),
            pair = await newMlsKeyPackage(session.device, payload.mls);
          guard(token);
          payload.packages[id] = { ...pair, pending: true };
        }
        row = await save(row, payload, token);
        pending = Object.entries(payload.packages).filter(([, p]) => p.pending);
      }
      const result = await api(prefix + '/key-packages', {
        deviceId: session.device,
        packages: pending.map(([id, p]) => ({ id, wire: p.wire })),
      });
      guard(token);
      for (const [id] of pending) payload.packages[id].pending = false;
      await save(row, payload, token);
      return result;
    });
  }
  return {
    ...createProtectedThreads({
      account,
      api,
      exclusive,
      save,
      guard,
      getSession: () => session,
      history,
    }),
    enroll,
    prepareLinked,
    authorizeLinked,
    unlock,
    peer,
    verify,
    publishPackages,
    publicState,
    lock,
    close() {
      closed = true;
      lock();
      channel?.close();
    },
  };
}
