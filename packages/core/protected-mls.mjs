// RFC9420 MLS1.0, suite 0x0001. Identity verification is supplied by the
// authenticated device-state layer, never by the delivery service alone.
import {
  generateKeyPackageWithKey,
  createGroup,
  createCommit,
  joinGroup,
  createApplicationMessage,
  processPublicMessage,
  encodeMlsMessage,
  decodeMlsMessage,
  encodeGroupState,
  decodeGroupState,
  emptyPskIndex,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
} from 'ts-mls';
import { defaultClientConfig } from 'ts-mls/clientConfig.js';
import { getGroupMembers, getOwnLeafNode } from 'ts-mls/clientState.js';
import { unprotectPrivateMessage } from 'ts-mls/messageProtection.js';
import { verifyKeyPackage, makeKeyPackageRef } from 'ts-mls/keyPackage.js';
import { verifyLeafNodeSignatureKeyPackage } from 'ts-mls/leafNode.js';
import { canonical } from './protected-crypto.mjs';
export const MLS_PROFILE = 'group-mls-rfc9420@0.1.0';
export const MLS_IMPLEMENTATION = 'ts-mls@1.6.4/g28-fresh-update-path-1';
export const MLS_SUITE = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';
const encoder = new TextEncoder(),
  decoder = new TextDecoder('utf-8', { fatal: true });
const fail = () => {
  throw Error('The protected MLS message or verified device state is invalid.');
};
const need = (value) => {
  if (!value) fail();
};
export const mlsBase64 = (bytes) => {
  const chunks = [];
  for (let i = 0; i < bytes.length; i += 8192)
    chunks.push(String.fromCharCode(...bytes.subarray(i, i + 8192)));
  return btoa(chunks.join(''));
};
export function mlsBytes(value, max = 400000) {
  need(
    typeof value === 'string' &&
      value.length <= max &&
      value.length % 4 === 0 &&
      !/[^A-Za-z0-9+/=]/.test(value),
  );
  const pad = value.indexOf('=');
  need(pad === -1 || (pad >= value.length - 2 && /^={1,2}$/.test(value.slice(pad))));
  let raw;
  try {
    raw = atob(value);
  } catch {
    fail();
  }
  need(btoa(raw) === value);
  const result = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) result[i] = raw.charCodeAt(i);
  return result;
}
const equal = (a, b) => mlsBase64(a) === mlsBase64(b);
const impl = () => getCiphersuiteImpl(getCiphersuiteFromName(MLS_SUITE));
const capabilities = {
  versions: ['mls10'],
  ciphersuites: [MLS_SUITE],
  credentials: ['basic'],
  extensions: [],
  proposals: [],
};
function decode(value, wireformat) {
  const bytes = mlsBytes(value),
    result = decodeMlsMessage(bytes, 0);
  need(
    result &&
      result[1] === bytes.length &&
      result[0].version === 'mls10' &&
      result[0].wireformat === wireformat,
  );
  return result[0];
}
const encode = (message) => mlsBase64(encodeMlsMessage(message));
function policy(members) {
  need(
    Array.isArray(members) &&
      members.length >= 2 &&
      members.length <= 12 &&
      new Set(members.map((x) => x.device)).size === members.length,
  );
  for (const m of members)
    need(
      typeof m.device === 'string' &&
        /^[a-f0-9-]{36}$/.test(m.device) &&
        mlsBytes(m.signatureKey).length === 32,
    );
  return {
    ...defaultClientConfig,
    keyRetentionConfig: {
      retainKeysForGenerations: 0,
      retainKeysForEpochs: 0,
      maximumForwardRatchetSteps: 8,
    },
    authService: {
      async validateCredential(credential, key) {
        return (
          credential.credentialType === 'basic' &&
          members.some(
            (m) =>
              decoder.decode(credential.identity) === m.device &&
              equal(key, mlsBytes(m.signatureKey)),
          )
        );
      },
    },
  };
}
function roster(state, members, groupId) {
  need(
    state.groupContext.version === 'mls10' &&
      state.groupContext.extensions.length === 0 &&
      state.groupContext.cipherSuite === MLS_SUITE &&
      decoder.decode(state.groupContext.groupId) === groupId,
  );
  const actual = getGroupMembers(state).map((l) => ({
    device: decoder.decode(l.credential.identity),
    signatureKey: mlsBase64(l.signaturePublicKey),
  }));
  need(
    canonical(actual.sort((a, b) => a.device.localeCompare(b.device))) ===
      canonical(
        [...members]
          .map(({ device, signatureKey }) => ({ device, signatureKey }))
          .sort((a, b) => a.device.localeCompare(b.device)),
      ),
  );
}
function erase(value) {
  if (value instanceof Uint8Array) value.fill(0);
  else if (value instanceof Map) for (const x of value.values()) erase(x);
  else if (Array.isArray(value)) for (const x of value) erase(x);
  else if (value && typeof value === 'object') for (const x of Object.values(value)) erase(x);
}
// Upstream 1.6.4 retains all epochs when configured with zero (slice(-0)).
// Explicitly wipe and drop old receiver secrets before persisting any new
// state; never erase public tree/context arrays that may share references.
function forgetHistory(state) {
  for (const old of state.historicalReceiverData.values()) {
    erase(old.secretTree);
    erase(old.senderDataSecret);
    erase(old.resumptionPsk);
  }
  state.historicalReceiverData = new Map();
  return state;
}
function consume(result) {
  for (const value of result.consumed) if (value instanceof Uint8Array) value.fill(0);
  return forgetHistory(result.newState);
}
export async function newMlsSigningKeys() {
  const keys = await (await impl()).signature.keygen();
  return { publicKey: mlsBase64(keys.publicKey), privateKey: mlsBase64(keys.signKey) };
}
export async function newMlsKeyPackage(device, keys, now = Date.now()) {
  const cs = await impl(),
    p = await generateKeyPackageWithKey(
      { credentialType: 'basic', identity: encoder.encode(device) },
      capabilities,
      {
        notBefore: BigInt(Math.floor(now / 1000) - 60),
        notAfter: BigInt(Math.floor(now / 1000) + 7 * 86400),
      },
      [],
      { publicKey: mlsBytes(keys.publicKey), signKey: mlsBytes(keys.privateKey) },
      cs,
    );
  return {
    wire: encode({ version: 'mls10', wireformat: 'mls_key_package', keyPackage: p.publicPackage }),
    private: {
      initPrivateKey: mlsBase64(p.privatePackage.initPrivateKey),
      hpkePrivateKey: mlsBase64(p.privatePackage.hpkePrivateKey),
      signaturePrivateKey: mlsBase64(p.privatePackage.signaturePrivateKey),
    },
  };
}
async function keyPackage(wire, member, now, requireCurrent) {
  const p = decode(wire, 'mls_key_package').keyPackage;
  need(
    p.cipherSuite === MLS_SUITE &&
      p.leafNode.credential.credentialType === 'basic' &&
      decoder.decode(p.leafNode.credential.identity) === member.device &&
      equal(p.leafNode.signaturePublicKey, mlsBytes(member.signatureKey)) &&
      (await verifyKeyPackage(p, (await impl()).signature)),
  );
  if (requireCurrent)
    need(
      p.leafNode.lifetime.notBefore <= BigInt(Math.floor(now / 1000)) &&
        p.leafNode.lifetime.notAfter > BigInt(Math.floor(now / 1000)),
    );
  return p;
}
const privatePackage = (value) => ({
  initPrivateKey: mlsBytes(value.initPrivateKey),
  hpkePrivateKey: mlsBytes(value.hpkePrivateKey),
  signaturePrivateKey: mlsBytes(value.signaturePrivateKey),
});
export async function createProtectedMlsGroup({ groupId, own, others, members, now = Date.now() }) {
  const cs = await impl(),
    config = policy(members),
    mine = members.find((m) => m.device === own.device);
  need(mine && others.length === members.length - 1);
  const self = await keyPackage(own.package.wire, mine, now, true),
    privateKeys = privatePackage(own.package.private),
    state = await createGroup(encoder.encode(groupId), self, privateKeys, [], cs, config);
  const adds = await Promise.all(
    [...others]
      .sort((a, b) => a.device.localeCompare(b.device))
      .map(async (o) => {
        const m = members.find((m) => m.device === o.device);
        need(m);
        return { proposalType: 'add', add: { keyPackage: await keyPackage(o.wire, m, now, true) } };
      }),
  );
  const result = await createCommit(
    { state, cipherSuite: cs },
    { extraProposals: adds, ratchetTreeExtension: true, wireAsPublicMessage: true },
  );
  need(result.commit.publicMessage?.content.commit?.path && result.welcome);
  const next = consume(result);
  retirePrivate(state, next);
  retireValues(privateKeys, privateParts(next));
  roster(next, members, groupId);
  return {
    state: next,
    membershipCommit: encode(result.commit),
    welcome: encode({ version: 'mls10', wireformat: 'mls_welcome', welcome: result.welcome }),
  };
}
export async function joinProtectedMlsGroup({ groupId, welcome, own, members }) {
  const cs = await impl(),
    m = members.find((m) => m.device === own.device);
  need(m);
  const p = await keyPackage(own.package.wire, m, Date.now(), false),
    w = decode(welcome, 'mls_welcome').welcome;
  need(w.cipherSuite === MLS_SUITE);
  const privateKeys = privatePackage(own.package.private);
  let state;
  try {
    state = forgetHistory(
      await joinGroup(w, p, privateKeys, emptyPskIndex, cs, undefined, undefined, policy(members)),
    );
    roster(state, members, groupId);
    retireValues(privateKeys, privateParts(state));
    return state;
  } catch (error) {
    erase(privateKeys);
    destroyState(state);
    throw error;
  }
}

export function storeMlsState(state) {
  need(state.historicalReceiverData.size === 0);
  return mlsBase64(encodeGroupState(state));
}
function decodeState(bytes, members, groupId) {
  const parsed = decodeGroupState(bytes, 0);
  need(parsed && parsed[1] === bytes.length);
  const state = { ...parsed[0], clientConfig: policy(members) };
  need(state.historicalReceiverData.size === 0);
  roster(state, members, groupId);
  return state;
}
export function restoreMlsState(wire, members, groupId) {
  return decodeState(mlsBytes(wire, 1000000), members, groupId);
}
function cloneState(state, members, groupId) {
  return decodeState(encodeGroupState(state), members, groupId);
}
function boundContext(state, context, members) {
  roster(state, members, context.recordId);
  need(
    context.profile === MLS_PROFILE &&
      Number.isSafeInteger(context.epoch) &&
      context.epoch === Number(state.groupContext.epoch) + 1 &&
      Number.isSafeInteger(context.sequence) &&
      context.sequence >= 1 &&
      context.sequence <= 100 &&
      members.some((m) => m.device === context.sender) &&
      canonical(context.recipients) === canonical(members.map((m) => m.device).sort()),
  );
}
function senderIs(state, sender, device) {
  return (
    sender.senderType === 'member' &&
    decoder.decode(
      state.ratchetTree[2 * sender.leafIndex]?.leaf?.credential.identity || new Uint8Array(),
    ) === device
  );
}
function privateParts(state) {
  return [
    state.keySchedule,
    state.secretTree,
    state.privatePath,
    state.signaturePrivateKey,
    ...[...state.historicalReceiverData.values()].flatMap((v) => [
      v.secretTree,
      v.senderDataSecret,
      v.resumptionPsk,
    ]),
  ];
}
function byteViews(value, out = []) {
  if (value instanceof Uint8Array) out.push(value);
  else if (value instanceof Map) for (const v of value.values()) byteViews(v, out);
  else if (Array.isArray(value)) for (const v of value) byteViews(v, out);
  else if (value && typeof value === 'object')
    for (const v of Object.values(value)) byteViews(v, out);
  return out;
}
function retireValues(old, current) {
  const keep = byteViews(current);
  for (const v of byteViews(old))
    if (
      !keep.some(
        (k) =>
          k.buffer === v.buffer &&
          k.byteOffset < v.byteOffset + v.byteLength &&
          v.byteOffset < k.byteOffset + k.byteLength,
      )
    )
      v.fill(0);
}
function retirePrivate(old, current) {
  retireValues(privateParts(old), privateParts(current));
}
function destroyState(state) {
  if (!state) return;
  erase(state.keySchedule);
  erase(state.secretTree);
  erase(state.privatePath);
  erase(state.signaturePrivateKey);
  forgetHistory(state);
}
export async function sealProtectedMls({ state, context, payload, members }) {
  payload = structuredClone(payload);
  context = structuredClone(context);
  members = structuredClone(members);
  boundContext(state, context, members);
  need(decoder.decode(getOwnLeafNode(state).credential.identity) === context.sender);
  let working = cloneState(state, members, context.recordId);
  try {
    const cs = await impl(),
      aad = encoder.encode(canonical(context)),
      commit = await createCommit(
        { state: working, cipherSuite: cs },
        { wireAsPublicMessage: true, authenticatedData: aad },
      );
    need(commit.commit.publicMessage?.content.commit?.path);
    const previous = working;
    working = consume(commit);
    retirePrivate(previous, working);
    roster(working, members, context.recordId);
    need(Number(working.groupContext.epoch) === context.epoch);
    const sent = await createApplicationMessage(
        working,
        encoder.encode(canonical({ context, payload })),
        cs,
        aad,
      ),
      next = consume(sent);
    retirePrivate(working, next);
    const result = {
      state: next,
      commit: encode(commit.commit),
      message: encode({
        version: 'mls10',
        wireformat: 'mls_private_message',
        privateMessage: sent.privateMessage,
      }),
    };
    destroyState(state);
    return result;
  } catch (error) {
    destroyState(working);
    throw error;
  }
}
export async function openProtectedMls({ state, context, commit, message, members }) {
  context = structuredClone(context);
  members = structuredClone(members);
  boundContext(state, context, members);
  let working = cloneState(state, members, context.recordId);
  try {
    const cs = await impl(),
      aad = encoder.encode(canonical(context)),
      c = decode(commit, 'mls_public_message').publicMessage;
    need(
      c.content.contentType === 'commit' &&
        c.content.commit.path &&
        c.content.commit.proposals.length === 0 &&
        equal(c.content.authenticatedData, aad) &&
        senderIs(working, c.content.sender, context.sender),
    );
    const applied = await processPublicMessage(working, c, emptyPskIndex, cs);
    const previous = working;
    working = consume(applied);
    retirePrivate(previous, working);
    roster(working, members, context.recordId);
    need(Number(working.groupContext.epoch) === context.epoch);
    const pm = decode(message, 'mls_private_message').privateMessage;
    need(
      pm.contentType === 'application' &&
        equal(pm.authenticatedData, aad) &&
        Number(pm.epoch) === context.epoch,
    );
    const opened = await unprotectPrivateMessage(
      working.keySchedule.senderDataSecret,
      pm,
      working.secretTree,
      working.ratchetTree,
      working.groupContext,
      working.clientConfig.keyRetentionConfig,
      cs,
    );
    need(
      opened.content.content.contentType === 'application' &&
        senderIs(working, opened.content.content.sender, context.sender),
    );
    const body = JSON.parse(decoder.decode(opened.content.content.applicationData));
    need(canonical(body.context) === canonical(context));
    const next = consume({
      newState: { ...working, secretTree: opened.tree },
      consumed: opened.consumed,
    });
    retirePrivate(working, next);
    destroyState(state);
    return { state: next, payload: body.payload };
  } catch (error) {
    destroyState(working);
    throw error;
  }
}

export async function protectedMlsKeyPackageMetadata(wire, member, now = Date.now()) {
  const p = await keyPackage(wire, member, now, true),
    cs = await impl();
  need(await verifyLeafNodeSignatureKeyPackage(p.leafNode, cs.signature));
  need(
    p.extensions.length === 0 &&
      p.leafNode.extensions.length === 0 &&
      canonical(p.leafNode.capabilities) === canonical(capabilities),
  );
  const expires = Number(p.leafNode.lifetime.notAfter) * 1000;
  need(
    Number.isSafeInteger(expires) &&
      expires > now &&
      expires <= now + 7 * 86400000 + 120000 &&
      p.leafNode.lifetime.notAfter - p.leafNode.lifetime.notBefore <= 604860n,
  );
  const digest = async (b) =>
    Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', b)), (x) =>
      x.toString(16).padStart(2, '0'),
    ).join('');
  return {
    packageSha256: await digest(mlsBytes(wire)),
    initSha256: await digest(p.initKey),
    keyPackageRef: mlsBase64(await makeKeyPackageRef(p, cs.hash)),
    expiresAt: new Date(expires).toISOString(),
  };
}
