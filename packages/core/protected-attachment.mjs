// E2EESA attachment-chunked-aead@0.1.0. Only the encrypted chunks go to
// storage. The private manifest MUST travel inside authenticated MLS content.
import { canonical } from './protected-crypto.mjs';
import { mlsBase64, mlsBytes } from './protected-mls.mjs';
export const ATTACHMENT_PROFILE = 'attachment-chunked-aead@0.1.0';
const CHUNK = 65536,
  MAX = 150000,
  utf8 = new TextEncoder();
const fields = [
  'schema_version',
  'format_version',
  'profile_ref',
  'attachment_id',
  'parent_message_id',
  'attachment_key_id',
  'attachment_master_key_hex',
  'content_aead_algorithm_id',
  'hash_algorithm_id',
  'nonce_prefix_hex',
  'chunk_size_bytes',
  'chunk_count',
  'plaintext_size_bytes',
  'filename',
  'media_type',
  'whole_plaintext_hash_hex',
  'storage_object_id',
  'manifest_context_digest_hex',
];
const need = (ok) => {
  if (!ok) throw Error('The encrypted attachment or private manifest is invalid.');
};
const hex = (bytes) => Array.from(bytes, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (value) => {
  need(typeof value === 'string' && /^(?:[a-f0-9]{2})+$/.test(value));
  return Uint8Array.from(value.match(/../g), (x) => parseInt(x, 16));
};
const sha = async (bytes) => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
export async function attachmentManifestDigest(manifest) {
  const payload = Object.fromEntries(
    Object.entries(manifest).filter(
      ([k]) => !['attachment_master_key_hex', 'manifest_context_digest_hex'].includes(k),
    ),
  );
  return sha(
    utf8.encode(canonical({ domain: 'E2EESA-ATTACHMENT-MANIFEST-v1', manifest: payload })),
  );
}
export function attachmentNonce(prefix, index) {
  need(/^[a-f0-9]{8}$/.test(prefix) && Number.isSafeInteger(index) && index >= 0);
  const nonce = new Uint8Array(12);
  nonce.set(unhex(prefix));
  new DataView(nonce.buffer).setBigUint64(4, BigInt(index), false);
  return nonce;
}
const count = (size) => Math.max(1, Math.ceil(size / CHUNK));
const length = (m, i) => Math.min(CHUNK, Math.max(0, m.plaintext_size_bytes - i * CHUNK));
const aad = (m, i) =>
  utf8.encode(
    canonical({
      attachment_id: m.attachment_id,
      manifest_context_digest_hex: m.manifest_context_digest_hex,
      chunk_index: i,
      chunk_count: m.chunk_count,
      plaintext_length_bytes: length(m, i),
    }),
  );
function validate(m, parent) {
  need(
    m &&
      typeof m === 'object' &&
      !Array.isArray(m) &&
      Object.keys(m).sort().join(',') === [...fields].sort().join(','),
  );
  need(
    m.schema_version === '0.1' &&
      m.format_version === 'attachment-v1' &&
      m.profile_ref === ATTACHMENT_PROFILE &&
      m.content_aead_algorithm_id === 'ALG-AES-256-GCM' &&
      m.hash_algorithm_id === 'ALG-SHA256',
  );
  need(
    ['attachment_id', 'attachment_key_id', 'storage_object_id'].every(
      (k) => typeof m[k] === 'string' && /^[a-f0-9-]{36}$/.test(m[k]),
    ) &&
      m.parent_message_id === parent &&
      typeof parent === 'string' &&
      parent.length <= 100,
  );
  need(
    Number.isSafeInteger(m.plaintext_size_bytes) &&
      m.plaintext_size_bytes >= 0 &&
      m.plaintext_size_bytes <= MAX &&
      m.chunk_size_bytes === CHUNK &&
      m.chunk_count === count(m.plaintext_size_bytes),
  );
  need(
    /^[a-f0-9]{64}$/.test(m.attachment_master_key_hex) &&
      /^[a-f0-9]{8}$/.test(m.nonce_prefix_hex) &&
      /^[a-f0-9]{64}$/.test(m.whole_plaintext_hash_hex) &&
      /^[a-f0-9]{64}$/.test(m.manifest_context_digest_hex),
  );
  need(
    typeof m.filename === 'string' &&
      m.filename.length > 0 &&
      m.filename.length <= 120 &&
      !/[\x00-\x1f\\/]/.test(m.filename) &&
      m.media_type === 'application/octet-stream',
  );
}
export async function encryptProtectedAttachment({ bytes, name }, parent) {
  need(
    bytes instanceof Uint8Array &&
      bytes.length <= MAX &&
      typeof name === 'string' &&
      name.length > 0 &&
      name.length <= 120 &&
      !/[\x00-\x1f\\/]/.test(name) &&
      typeof parent === 'string' &&
      parent.length <= 100,
  );
  const raw = crypto.getRandomValues(new Uint8Array(32)),
    key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']),
    m = {
      schema_version: '0.1',
      format_version: 'attachment-v1',
      profile_ref: ATTACHMENT_PROFILE,
      attachment_id: crypto.randomUUID(),
      parent_message_id: parent,
      attachment_key_id: crypto.randomUUID(),
      attachment_master_key_hex: hex(raw),
      content_aead_algorithm_id: 'ALG-AES-256-GCM',
      hash_algorithm_id: 'ALG-SHA256',
      nonce_prefix_hex: hex(crypto.getRandomValues(new Uint8Array(4))),
      chunk_size_bytes: CHUNK,
      chunk_count: count(bytes.length),
      plaintext_size_bytes: bytes.length,
      filename: name,
      media_type: 'application/octet-stream',
      whole_plaintext_hash_hex: await sha(bytes),
      storage_object_id: crypto.randomUUID(),
    };
  raw.fill(0);
  m.manifest_context_digest_hex = await attachmentManifestDigest(m);
  validate(m, parent);
  const chunks = [];
  for (let i = 0; i < m.chunk_count; i++) {
    const plaintext = bytes.subarray(i * CHUNK, i * CHUNK + length(m, i)),
      encrypted = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: attachmentNonce(m.nonce_prefix_hex, i),
          additionalData: aad(m, i),
          tagLength: 128,
        },
        key,
        plaintext,
      );
    chunks.push(mlsBase64(new Uint8Array(encrypted)));
  }
  return { manifest: m, chunks };
}
export async function decryptProtectedAttachment(manifest, chunks, parent) {
  validate(manifest, parent);
  const m = manifest;
  need(
    (await attachmentManifestDigest(m)) === m.manifest_context_digest_hex &&
      Array.isArray(chunks) &&
      chunks.length === m.chunk_count,
  );
  const raw = unhex(m.attachment_master_key_hex),
    key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  raw.fill(0);
  const plaintext = [];
  try {
    for (let i = 0; i < m.chunk_count; i++) {
      const ciphertext = mlsBytes(chunks[i], 90000);
      need(ciphertext.length === length(m, i) + 16);
      plaintext.push(
        new Uint8Array(
          await crypto.subtle.decrypt(
            {
              name: 'AES-GCM',
              iv: attachmentNonce(m.nonce_prefix_hex, i),
              additionalData: aad(m, i),
              tagLength: 128,
            },
            key,
            ciphertext,
          ),
        ),
      );
    }
    const result = new Uint8Array(m.plaintext_size_bytes);
    let at = 0;
    for (const chunk of plaintext) {
      result.set(chunk, at);
      at += chunk.length;
    }
    if ((await sha(result)) !== m.whole_plaintext_hash_hex) {
      result.fill(0);
      need(false);
    }
    return { bytes: result, name: m.filename };
  } finally {
    for (const chunk of plaintext) chunk.fill(0);
  }
}
