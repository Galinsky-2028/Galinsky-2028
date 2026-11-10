// Client-local software vault. No server escrow or private-key export API.
// The passphrase unlocks this browser's stored vault; it cannot recreate a
// deleted browser profile. Selected history policy is backup-none@0.1.0.
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { canonical } from './protected-crypto.mjs';
import { mlsBase64, mlsBytes } from './protected-mls.mjs';
export const VAULT_PROFILE = 'secret-software-vault@0.1.0';
export const HISTORY_POLICY = 'backup-none@0.1.0';
const utf8 = new TextEncoder(),
  decode = new TextDecoder('utf-8', { fatal: true }),
  MAX = 24 * 1024 * 1024;
const need = (value) => {
  if (!value) throw Error('The local protected vault could not be authenticated.');
};
const random = (n) => crypto.getRandomValues(new Uint8Array(n));
const bytes = (s, n) => {
  const b = mlsBytes(s, MAX * 2);
  need(n === undefined || b.length === n);
  return b;
};
const id = (s) =>
  typeof s === 'string' &&
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(s);
const exact = (v, keys) =>
  need(
    v &&
      typeof v === 'object' &&
      !Array.isArray(v) &&
      Object.keys(v).sort().join(',') === [...keys].sort().join(','),
  );
const associated = (header, domain) => utf8.encode(canonical({ domain, header }));
async function hkdf(raw, salt, info) {
  const key = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: utf8.encode(info) },
    key,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}
async function passwordKey(password, kdf, account, device) {
  need(typeof password === 'string' && password.length >= 16 && password.length <= 256);
  exact(kdf, ['algorithm', 'version', 'memoryKiB', 'passes', 'parallelism', 'salt', 'hkdfSalt']);
  need(
    kdf.algorithm === 'Argon2id/HKDF-SHA256' &&
      kdf.version === 19 &&
      kdf.memoryKiB === 65536 &&
      kdf.passes === 3 &&
      kdf.parallelism === 1,
  );
  const salt = bytes(kdf.salt, 16),
    hkdfSalt = bytes(kdf.hkdfSalt, 32),
    raw = await argon2idAsync(password, salt, {
      version: 19,
      m: 65536,
      t: 3,
      p: 1,
      dkLen: 32,
      asyncTick: 10,
    });
  try {
    return await hkdf(raw, hkdfSalt, 'G28:device-vault-KEK:v1:' + account + ':' + device);
  } finally {
    raw.fill(0);
  }
}
async function seal(header, payload, kek) {
  const plaintext = utf8.encode(canonical(payload));
  need(plaintext.length <= MAX);
  const raw = random(32),
    dek = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']),
    wrapIv = random(12),
    iv = random(12);
  try {
    const wrapped = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: wrapIv,
          additionalData: associated(header, 'G28-VAULT-DEK-v1'),
          tagLength: 128,
        },
        kek,
        raw,
      ),
      wrap = { iv: mlsBase64(wrapIv), ciphertext: mlsBase64(new Uint8Array(wrapped)) };
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: associated({ ...header, wrap }, 'G28-VAULT-CONTENT-v1'),
        tagLength: 128,
      },
      dek,
      plaintext,
    );
    return {
      header,
      wrap,
      body: { iv: mlsBase64(iv), ciphertext: mlsBase64(new Uint8Array(ciphertext)) },
    };
  } finally {
    raw.fill(0);
    plaintext.fill(0);
  }
}
function envelope(value) {
  exact(value, ['header', 'wrap', 'body']);
  for (const p of [value.wrap, value.body]) {
    exact(p, ['iv', 'ciphertext']);
    bytes(p.iv, 12);
  }
  need(bytes(value.wrap.ciphertext, 48).length === 48);
  const ciphertext = bytes(value.body.ciphertext);
  need(ciphertext.length >= 16 && ciphertext.length <= MAX + 16);
  return value;
}
async function open(value, kek) {
  const { header, wrap, body } = envelope(value),
    raw = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: bytes(wrap.iv, 12),
          additionalData: associated(header, 'G28-VAULT-DEK-v1'),
          tagLength: 128,
        },
        kek,
        bytes(wrap.ciphertext, 48),
      ),
    );
  need(raw.length === 32);
  let plaintext;
  try {
    const dek = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: bytes(body.iv, 12),
          additionalData: associated({ ...header, wrap }, 'G28-VAULT-CONTENT-v1'),
          tagLength: 128,
        },
        dek,
        bytes(body.ciphertext),
      ),
    );
    return JSON.parse(decode.decode(plaintext));
  } finally {
    raw.fill(0);
    plaintext?.fill(0);
  }
}
function header(h, { account, device, record, minGeneration = 1 }, kind) {
  exact(
    h,
    kind === 'device'
      ? ['format', 'profile', 'historyPolicy', 'kind', 'account', 'device', 'generation', 'kdf']
      : ['format', 'profile', 'historyPolicy', 'kind', 'account', 'device', 'record', 'generation'],
  );
  need(
    h.format === 'g28-local-vault-v1' &&
      h.profile === VAULT_PROFILE &&
      h.historyPolicy === HISTORY_POLICY &&
      h.kind === kind &&
      id(account) &&
      id(device) &&
      h.account === account &&
      h.device === device &&
      Number.isSafeInteger(h.generation) &&
      h.generation >= 1 &&
      Number.isSafeInteger(minGeneration) &&
      minGeneration >= 1 &&
      h.generation >= minGeneration,
  );
  if (kind === 'thread') need(id(record) && h.record === record);
}
export async function createProtectedDeviceVault({
  account,
  device,
  password,
  payload,
  generation = 1,
}) {
  need(id(account) && id(device) && Number.isSafeInteger(generation) && generation >= 1);
  const kdf = {
      algorithm: 'Argon2id/HKDF-SHA256',
      version: 19,
      memoryKiB: 65536,
      passes: 3,
      parallelism: 1,
      salt: mlsBase64(random(16)),
      hkdfSalt: mlsBase64(random(32)),
    },
    h = {
      format: 'g28-local-vault-v1',
      profile: VAULT_PROFILE,
      historyPolicy: HISTORY_POLICY,
      kind: 'device',
      account,
      device,
      generation,
      kdf,
    },
    kek = await passwordKey(password, kdf, account, device),
    master = random(32);
  try {
    return {
      envelope: await seal(h, { masterKey: mlsBase64(master), payload }, kek),
      session: { active: true, account, device, generation, kek, master: master.slice(), payload },
    };
  } finally {
    master.fill(0);
  }
}
export async function unlockProtectedDeviceVault(value, password, expected) {
  envelope(value);
  header(value.header, expected, 'device');
  const h = value.header,
    kek = await passwordKey(password, h.kdf, h.account, h.device),
    opened = await open(value, kek);
  exact(opened, ['masterKey', 'payload']);
  return {
    active: true,
    account: h.account,
    device: h.device,
    generation: h.generation,
    kek,
    master: bytes(opened.masterKey, 32),
    payload: opened.payload,
  };
}
export async function updateProtectedDeviceVault(value, session, payload) {
  envelope(value);
  header(
    value.header,
    { account: session.account, device: session.device, minGeneration: session.generation },
    'device',
  );
  need(
    session.active === true &&
      session.kek &&
      session.generation < Number.MAX_SAFE_INTEGER &&
      value.header.generation === session.generation &&
      session.master instanceof Uint8Array &&
      session.master.length === 32,
  );
  const h = { ...value.header, generation: session.generation + 1 };
  const next = await seal(h, { masterKey: mlsBase64(session.master), payload }, session.kek);
  need(session.active === true);
  return { envelope: next, generation: h.generation };
}
async function threadKey(session, record) {
  need(
    session.active === true &&
      session.kek &&
      id(record) &&
      session.master instanceof Uint8Array &&
      session.master.length === 32,
  );
  const key = await hkdf(
    session.master,
    utf8.encode(record),
    'G28:thread-vault-KEK:v1:' + session.account + ':' + session.device + ':' + record,
  );
  need(session.active === true);
  return key;
}
export async function sealProtectedThreadVault(session, { record, generation, payload }) {
  need(
    id(session.account) &&
      id(session.device) &&
      id(record) &&
      Number.isSafeInteger(generation) &&
      generation >= 1,
  );
  const h = {
    format: 'g28-local-vault-v1',
    profile: VAULT_PROFILE,
    historyPolicy: HISTORY_POLICY,
    kind: 'thread',
    account: session.account,
    device: session.device,
    record,
    generation,
  };
  const result = await seal(h, payload, await threadKey(session, record));
  need(session.active === true);
  return result;
}
export async function openProtectedThreadVault(session, value, expected) {
  envelope(value);
  header(
    value.header,
    {
      account: session.account,
      device: session.device,
      record: expected.record,
      minGeneration: expected.minGeneration,
    },
    'thread',
  );
  const result = await open(value, await threadKey(session, expected.record));
  need(session.active === true);
  return result;
}
export function lockProtectedVault(session) {
  session.active = false;
  session.master?.fill(0);
  session.kek = null;
  session.payload = null;
}
