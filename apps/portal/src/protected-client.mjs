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
import {
  MLS_PROFILE,
  newMlsSigningKeys,
  newMlsKeyPackage,
} from '../../../packages/core/protected-mls.mjs';
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
  protectedLocalList,
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
      try {
        await resumeProtectedDeviceVault(row.envelope, session);
      } catch {
        lock();
        throw Error('This browser’s encrypted vault changed. Unlock the current device again.');
      }
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
  async function enroll(password, label, acknowledgeNoRecovery = false, replace = false) {
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
        replace || !(await protectedLocalGet(deviceEntry(account))),
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
        replace ? !!current.identity : !current.identity,
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
        replace,
        confirm: replace
          ? 'start a new unverified identity'
          : 'authorize this signed device transition',
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
    const replacing = transition.replace === true || transition.event.action === 'rotate',
      previous = await protectedLocalGet(next.key);
    need(replacing || !previous, 'A different protected device already exists in this browser.');
    const oldThreads = replacing
      ? (await protectedLocalList(account)).filter((r) => r.key.startsWith('thread:'))
      : [];
    guard(token);
    await protectedLocalCommit([
      { key: row.key, expected: row.generation, next: null },
      { key: next.key, expected: previous?.generation || 0, next },
      ...oldThreads.map((r) => ({ key: r.key, expected: r.generation, next: null })),
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
      devices: p.identity.devices.map((d) => ({
        id: d.id,
        generation: d.generation,
        state: d.state,
        fingerprint: d.fingerprint,
      })),
      pendingAuthority: !!p.pendingAuthority,
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
        request &&
          typeof request === 'object' &&
          !Array.isArray(request) &&
          Object.keys(request).sort().join(',') ===
            'confirm,deviceSignature,event,identityId,label,replace,rootPublicKey,rootSignature',
        'Use only the exact public signed device request; unexpected fields are never sent.',
      );
      need(
        request?.rootSignature === null &&
          request.replace === false &&
          request.identityId === payload.identity.identityId &&
          request.rootPublicKey === payload.identity.rootPublicKey &&
          ['enroll', 'rotate'].includes(request.event?.action) &&
          Number.isSafeInteger(request.event.subject.generation),
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
  async function rotateDevice(password, label, acknowledgeNoRecovery, confirmation) {
    need(
      acknowledgeNoRecovery === true &&
        confirmation === 'rotate device and permanently lose old local history',
      'Confirm that rotation permanently removes this browser’s old thread keys and local history.',
    );
    return exclusive(async ({ row, payload, token }) => {
      need(
        !payload.pendingAuthority && !(await protectedLocalGet(pendingDeviceEntry(account))),
        'Finish the existing pending authority/device change first.',
      );
      const packet = await api(prefix + '/identity');
      guard(token);
      const checked = await history(packet, {
          identityId: payload.identity.identityId,
          sequence: payload.identity.sequence,
          hash: payload.identityHash,
        }),
        own = checked.state.devices.find((d) => d.id === session.device);
      need(own?.state === 'active', 'Only an active original device can request rotation.');
      const deviceSecret = secret(),
        device = await newProtectedKey(account, deviceSecret),
        mls = await newMlsSigningKeys(),
        event = await protectedIdentityEvent(checked.state, {
          id: crypto.randomUUID(),
          action: 'rotate',
          subject: {
            id: own.id,
            generation: own.generation + 1,
            publicKey: device.publicKey,
            mlsSigningKey: mls.publicKey,
          },
        }),
        deviceKey = await unlockProtectedKey(device.privateKey, deviceSecret),
        rootKey = payload.root
          ? await unlockProtectedKey(payload.root.privateKey, payload.root.secret)
          : null,
        transition = {
          identityId: checked.state.identityId,
          rootPublicKey: checked.state.rootPublicKey,
          event,
          rootSignature: rootKey ? await signProtected(event, rootKey) : null,
          deviceSignature: await signProtected(event, deviceKey),
          label,
          replace: false,
          confirm: 'authorize this signed device transition',
        },
        state = rootKey
          ? await applyProtectedIdentityEvent(
              checked.state,
              event,
              transition.rootSignature,
              transition.deviceSignature,
            )
          : checked.state,
        nextPayload = {
          version: 1,
          root: payload.root,
          device: { ...device, secret: deviceSecret, id: own.id },
          mls,
          identity: state,
          identityHash: await identityStateHash(state),
          contacts: payload.contacts,
          packages: {},
          pendingTransition: transition,
          pendingAuthority: null,
        },
        vault = await createProtectedDeviceVault({
          account,
          device: own.id,
          password,
          payload: nextPayload,
          generation: row.generation + 1,
        });
      try {
        guard(token);
        const pending = {
          key: pendingDeviceEntry(account),
          account,
          device: own.id,
          generation: vault.envelope.header.generation,
          envelope: vault.envelope,
        };
        await protectedLocalCommit([{ key: pending.key, expected: 0, next: pending }]);
        guard(token);
        if (rootKey) {
          lockProtectedVault(session);
          session = vault.session;
          const own = await finishEnrollment(pending, token);
          return { completed: true, own };
        }
        lock();
        return {
          completed: false,
          request: transition,
          deviceFingerprint: (await publicProtectedKey(device.publicKey)).fingerprint,
        };
      } catch (error) {
        if (session === vault.session) lock();
        throw error;
      } finally {
        if (session !== vault.session) lockProtectedVault(vault.session);
      }
    });
  }
  async function refreshPendingDevice(password) {
    lock();
    const token = epoch;
    return withProtectedLock(account, async () => {
      const row = await protectedLocalGet(pendingDeviceEntry(account));
      guard(token);
      need(row, 'No public device request is pending.');
      const opened = await unlockProtectedDeviceVault(row.envelope, password, {
        account,
        device: row.device,
        minGeneration: row.generation,
      });
      try {
        guard(token);
        const payload = structuredClone(opened.payload),
          old = payload.pendingTransition;
        need(
          old &&
            !old.rootSignature &&
            !old.replace &&
            ['enroll', 'rotate'].includes(old.event.action),
          'Unlock and retry this signed root transition exactly; it cannot be replaced by an unsigned request.',
        );
        const packet = await api(prefix + '/identity');
        guard(token);
        const checked = await history(packet, {
          identityId: payload.identity.identityId,
          sequence: payload.identity.sequence,
          hash: payload.identityHash,
        });
        if (packet.history.events.some((e) => e.document.id === old.event.id)) {
          session = opened;
          return { completed: true, own: await finishEnrollment(row, token) };
        }
        const event = await protectedIdentityEvent(checked.state, {
            id: crypto.randomUUID(),
            action: old.event.action,
            subject: old.event.subject,
          }),
          key = await unlockProtectedKey(payload.device.privateKey, payload.device.secret),
          request = { ...old, event, deviceSignature: await signProtected(event, key) };
        payload.identity = checked.state;
        payload.identityHash = checked.hash;
        payload.pendingTransition = request;
        const updated = await updateProtectedDeviceVault(row.envelope, opened, payload);
        guard(token);
        await protectedLocalCommit([
          {
            key: row.key,
            expected: row.generation,
            next: { ...row, generation: updated.generation, envelope: updated.envelope },
          },
        ]);
        guard(token);
        return {
          completed: false,
          request,
          deviceFingerprint: (await publicProtectedKey(payload.device.publicKey)).fingerprint,
        };
      } catch (error) {
        if (session === opened) lock();
        throw error;
      } finally {
        if (session !== opened) lockProtectedVault(opened);
      }
    });
  }
  async function discardPendingDevice(confirmation) {
    need(
      confirmation === 'delete pending local keys even if already authorized',
      'Confirm irreversible pending-key deletion, including keys whose acknowledgement may have been lost.',
    );
    lock();
    const token = epoch;
    return withProtectedLock(account, async () => {
      const row = await protectedLocalGet(pendingDeviceEntry(account));
      guard(token);
      need(row, 'No pending device keys exist.');
      await protectedLocalCommit([{ key: row.key, expected: row.generation, next: null }]);
      guard(token);
      return { deleted: true };
    });
  }
  async function finishAuthority(row, payload, token) {
    const transition = payload.pendingAuthority;
    need(transition, 'No signed root-authority transition is pending.');
    await api(prefix + '/identity', transition);
    guard(token);
    const packet = await api(prefix + '/identity');
    guard(token);
    const checked = await history(packet, {
      identityId: payload.identity.identityId,
      sequence: payload.identity.sequence,
      hash: payload.identityHash,
    });
    const accepted = packet.history.events.find((e) => e.document.id === transition.event.id);
    need(
      accepted && canonical(accepted.document) === canonical(transition.event),
      'The root authority acknowledgement does not match this exact transition.',
    );
    await save(
      row,
      { ...payload, identity: checked.state, identityHash: checked.hash, pendingAuthority: null },
      token,
    );
    return publicState();
  }
  async function revokeDevice(deviceId, fingerprint, confirmation) {
    need(
      confirmation === 'revoke this exact device',
      'Confirm revoking this exact device; downloaded copies cannot be erased.',
    );
    return exclusive(async ({ row, payload, token }) => {
      need(payload.root, 'Use the account-root device for a signed cryptographic revocation.');
      need(
        !payload.pendingAuthority,
        'Retry the existing root-authority change before creating another.',
      );
      const packet = await api(prefix + '/identity');
      guard(token);
      const checked = await history(packet, {
          identityId: payload.identity.identityId,
          sequence: payload.identity.sequence,
          hash: payload.identityHash,
        }),
        device = checked.state.devices.find((d) => d.id === deviceId);
      need(
        device?.state === 'active' && device.fingerprint === fingerprint,
        'Confirm the exact current device fingerprint before revoking.',
      );
      const event = await protectedIdentityEvent(checked.state, {
          id: crypto.randomUUID(),
          action: 'revoke',
          subject: { id: device.id, generation: device.generation },
        }),
        rootKey = await unlockProtectedKey(payload.root.privateKey, payload.root.secret),
        rootSignature = await signProtected(event, rootKey);
      await applyProtectedIdentityEvent(checked.state, event, rootSignature, null);
      guard(token);
      payload.identity = checked.state;
      payload.identityHash = checked.hash;
      payload.pendingAuthority = {
        identityId: checked.state.identityId,
        rootPublicKey: checked.state.rootPublicKey,
        event,
        rootSignature,
        deviceSignature: null,
        label: 'Root-revoked device',
        replace: false,
        confirm: 'authorize this signed device transition',
      };
      row = await save(row, payload, token);
      return finishAuthority(row, payload, token);
    });
  }
  async function retryAuthority() {
    return exclusive(async ({ row, payload, token }) => finishAuthority(row, payload, token));
  }
  async function exportCiphertext(id, confirmation) {
    need(
      confirmation === 'export exact original-recipient ciphertext',
      'Confirm exporting this exact record’s original-recipient ciphertext. This does not recreate erased epoch keys.',
    );
    return exclusive(async ({ payload, token }) => {
      const response = await api(prefix + '/records/' + id + '?deviceId=' + session.device);
      guard(token);
      const own = payload.identity.devices.find((d) => d.id === session.device),
        version = response.record.messages.length,
        proof = {
          action: 'export',
          profile: MLS_PROFILE,
          recordId: id,
          version,
          deviceId: session.device,
          generation: own.generation,
        },
        key = await unlockProtectedKey(payload.device.privateKey, payload.device.secret),
        signature = await signProtected(proof, key);
      guard(token);
      const result = await api(prefix + '/records/' + id + '/export', {
        deviceId: session.device,
        version,
        signature,
        confirm: 'export exact encrypted record',
      });
      guard(token);
      return result;
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
    enroll: (password, label, acknowledgeNoRecovery) =>
      enroll(password, label, acknowledgeNoRecovery, false),
    replaceRoot: async (password, label, acknowledgeNoRecovery, confirmation) => {
      need(
        confirmation === 'replace root and permanently lose old local history',
        'Confirm permanent loss of this browser’s old protected history and all old-root verification before replacing the root.',
      );
      lock();
      return enroll(password, label, acknowledgeNoRecovery, true);
    },
    refreshPendingDevice,
    discardPendingDevice,
    rotateDevice,
    revokeDevice,
    retryAuthority,
    exportCiphertext,
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
