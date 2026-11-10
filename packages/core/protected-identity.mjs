// Exact account-root identity profile. Account authentication and staff grants
// are routing/availability controls, never substitutes for these signatures.
import { canonical, publicProtectedKey, verifyProtected } from './protected-crypto.mjs';
import { mlsBytes } from './protected-mls.mjs';
export const IDENTITY_PROFILE = 'identity-account-root@0.1.0';
const utf8 = new TextEncoder(),
  hex = (bytes) => Array.from(bytes, (x) => x.toString(16).padStart(2, '0')).join('');
const need = (value) => {
  if (!value) throw Error('The protected identity transition is unauthorized, stale or invalid.');
};
const uuid = (s) =>
  typeof s === 'string' &&
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(s);
const exact = (v, keys) =>
  need(
    v &&
      typeof v === 'object' &&
      !Array.isArray(v) &&
      Object.keys(v).sort().join(',') === [...keys].sort().join(','),
  );
const hash = async (data) =>
  hex(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(data))));
const keyId = (alg, raw) => hash('G28:identity-public-key:v1:' + alg + ':' + hex(raw));
export const identityStateHash = (state) => hash(canonical(state));
async function publicIdentityKey(publicKey, account) {
  const parsed = await publicProtectedKey(publicKey);
  need(parsed.key.users[0].userID.userID === account);
  const encryption = await parsed.key.getEncryptionKey(),
    signingRaw = parsed.key.keyPacket.publicParams.A,
    agreementRaw = encryption.keyPacket.publicParams.A;
  need(
    signingRaw instanceof Uint8Array &&
      signingRaw.length === 32 &&
      agreementRaw instanceof Uint8Array &&
      agreementRaw.length === 32,
  );
  return {
    ...parsed,
    signingId: await keyId('Ed25519', signingRaw),
    agreementId: await keyId('X25519', agreementRaw),
  };
}
export async function initialProtectedIdentity({ accountId, identityId, rootPublicKey }) {
  need(uuid(accountId) && uuid(identityId));
  const root = await publicIdentityKey(rootPublicKey, accountId);
  return {
    profile: IDENTITY_PROFILE,
    accountId,
    identityId,
    rootPublicKey,
    rootFingerprint: root.fingerprint,
    sequence: 0,
    devices: [],
    retiredKeys: [],
  };
}
async function currentState(state) {
  exact(state, [
    'profile',
    'accountId',
    'identityId',
    'rootPublicKey',
    'rootFingerprint',
    'sequence',
    'devices',
    'retiredKeys',
  ]);
  need(
    state.profile === IDENTITY_PROFILE &&
      uuid(state.accountId) &&
      uuid(state.identityId) &&
      Number.isSafeInteger(state.sequence) &&
      state.sequence >= 0 &&
      state.sequence < 1000 &&
      Array.isArray(state.devices) &&
      state.devices.length <= 64 &&
      Array.isArray(state.retiredKeys) &&
      new Set(state.retiredKeys).size === state.retiredKeys.length &&
      state.retiredKeys.every((k) => /^[a-f0-9]{64}$/.test(k)),
  );
  const root = await publicIdentityKey(state.rootPublicKey, state.accountId);
  need(root.fingerprint === state.rootFingerprint);
  const ids = new Set(),
    keys = new Set([root.signingId, root.agreementId]);
  let active = 0;
  for (const d of state.devices) {
    exact(d, [
      'id',
      'generation',
      'state',
      'publicKey',
      'fingerprint',
      'signingId',
      'agreementId',
      'mlsSigningKey',
      'mlsSigningId',
    ]);
    need(
      uuid(d.id) &&
        !ids.has(d.id) &&
        Number.isSafeInteger(d.generation) &&
        d.generation >= 1 &&
        ['active', 'revoked'].includes(d.state),
    );
    ids.add(d.id);
    const p = await publicIdentityKey(d.publicKey, state.accountId),
      mls = mlsBytes(d.mlsSigningKey, 64);
    need(
      mls.length === 32 &&
        p.fingerprint === d.fingerprint &&
        p.signingId === d.signingId &&
        p.agreementId === d.agreementId &&
        (await keyId('Ed25519', mls)) === d.mlsSigningId,
    );
    for (const k of [d.signingId, d.agreementId, d.mlsSigningId]) {
      need(!keys.has(k));
      keys.add(k);
      if (d.state === 'active') need(!state.retiredKeys.includes(k));
      else need(state.retiredKeys.includes(k));
    }
    if (d.state === 'active') active++;
  }
  need(
    active <= 12 &&
      (state.sequence === 0
        ? state.devices.length === 0 && state.retiredKeys.length === 0
        : active >= 1),
  );
  return { root, keys, active };
}
export async function protectedIdentityEvent(state, { id, action, subject }) {
  await currentState(state);
  need(uuid(id) && ['enroll', 'rotate', 'revoke'].includes(action));
  return {
    profile: IDENTITY_PROFILE,
    identityId: state.identityId,
    accountId: state.accountId,
    id,
    sequence: state.sequence + 1,
    previousStateHash: await identityStateHash(state),
    action,
    subject,
  };
}
export async function applyProtectedIdentityEvent(state, event, rootSignature, deviceSignature) {
  const { root, keys, active } = await currentState(state);
  exact(event, [
    'profile',
    'identityId',
    'accountId',
    'id',
    'sequence',
    'previousStateHash',
    'action',
    'subject',
  ]);
  need(
    event.profile === IDENTITY_PROFILE &&
      event.identityId === state.identityId &&
      event.accountId === state.accountId &&
      uuid(event.id) &&
      event.sequence === state.sequence + 1 &&
      event.previousStateHash === (await identityStateHash(state)) &&
      ['enroll', 'rotate', 'revoke'].includes(event.action),
  );
  need(
    typeof rootSignature === 'string' &&
      rootSignature.length <= 4000 &&
      (await verifyProtected(event, rootSignature, root.key)),
  );
  const next = structuredClone(state),
    b = event.subject,
    old = state.devices.find((d) => d.id === b?.id);
  need(uuid(b?.id));
  if (event.action === 'revoke') {
    exact(b, ['id', 'generation']);
    need(old?.state === 'active' && old.generation === b.generation && active > 1);
    next.devices.find((d) => d.id === b.id).state = 'revoked';
    next.retiredKeys.push(old.signingId, old.agreementId, old.mlsSigningId);
  } else {
    exact(b, ['id', 'generation', 'publicKey', 'mlsSigningKey']);
    need(Number.isSafeInteger(b.generation));
    if (event.action === 'enroll')
      need(!old && b.generation === 1 && state.devices.length < 64 && active < 12);
    else need(old?.state === 'active' && b.generation === old.generation + 1);
    const p = await publicIdentityKey(b.publicKey, state.accountId),
      mls = mlsBytes(b.mlsSigningKey, 64);
    need(mls.length === 32);
    const added = [p.signingId, p.agreementId, await keyId('Ed25519', mls)];
    need(
      new Set(added).size === 3 &&
        added.every((k) => !keys.has(k) && !state.retiredKeys.includes(k)),
    );
    need(
      typeof deviceSignature === 'string' &&
        deviceSignature.length <= 4000 &&
        (await verifyProtected(event, deviceSignature, p.key)),
    );
    const device = {
      id: b.id,
      generation: b.generation,
      state: 'active',
      publicKey: b.publicKey,
      fingerprint: p.fingerprint,
      signingId: p.signingId,
      agreementId: p.agreementId,
      mlsSigningKey: b.mlsSigningKey,
      mlsSigningId: added[2],
    };
    if (old) {
      next.devices[next.devices.findIndex((d) => d.id === b.id)] = device;
      next.retiredKeys.push(old.signingId, old.agreementId, old.mlsSigningId);
    } else next.devices.push(device);
  }
  next.sequence = event.sequence;
  next.devices.sort((a, b) => a.id.localeCompare(b.id));
  next.retiredKeys = [...new Set(next.retiredKeys)].sort();
  await currentState(next);
  return next;
}

export async function protectedIdentityKeyClaims(state) {
  const { root } = await currentState(state);
  return [
    { keyId: root.signingId, subjectId: state.identityId, generation: 1, kind: 'root-signing' },
    { keyId: root.agreementId, subjectId: state.identityId, generation: 1, kind: 'root-agreement' },
    ...state.devices.flatMap((d) => [
      { keyId: d.signingId, subjectId: d.id, generation: d.generation, kind: 'device-signing' },
      { keyId: d.agreementId, subjectId: d.id, generation: d.generation, kind: 'device-agreement' },
      { keyId: d.mlsSigningId, subjectId: d.id, generation: d.generation, kind: 'mls-signing' },
    ]),
  ];
}
