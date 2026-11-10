// verify-account-root@0.1.0, ALG-SHA256. This is a comparison aid, never
// a password, identity proof or substitute for the signed device-state chain.
import { canonical } from './protected-crypto.mjs';
import { IDENTITY_PROFILE } from './protected-identity.mjs';
import { mlsBase64, mlsBytes } from './protected-mls.mjs';
export const VERIFICATION_PROFILE = 'verify-account-root@0.1.0';
const need = (x) => {
  if (!x)
    throw Error('Verify the exact current identity roots through an independent trusted channel.');
};
const utf8 = new TextEncoder(),
  decode = new TextDecoder('utf-8', { fatal: true }),
  hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export async function protectedSafetyValue(first, second) {
  const parties = [first, second]
    .map((state) => {
      need(
        state.profile === IDENTITY_PROFILE &&
          typeof state.identityId === 'string' &&
          /^[a-f0-9-]{36}$/.test(state.identityId) &&
          /^[a-f0-9]{64}$/.test(state.rootFingerprint),
      );
      return { identity_id: state.identityId, account_root_key_fingerprint: state.rootFingerprint };
    })
    .sort((a, b) => a.identity_id.localeCompare(b.identity_id));
  need(parties[0].identity_id !== parties[1].identity_id);
  const subject = {
      domain: 'E2EESA-KEY-VERIFICATION-v1',
      schema_version: '0.1',
      profile_ref: VERIFICATION_PROFILE,
      parties,
    },
    digest = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(canonical(subject)))),
    subjectDigest = hex(digest),
    groups = [];
  for (let i = 0; i < 24; i += 2)
    groups.push(String(digest[i] * 256 + digest[i + 1]).padStart(5, '0'));
  const qr = {
    v: 1,
    profile_ref: VERIFICATION_PROFILE,
    hash_algorithm_id: 'ALG-SHA256',
    party_identity_ids: parties.map((p) => p.identity_id),
    subject_digest_hex: subjectDigest,
  };
  return {
    profile: VERIFICATION_PROFILE,
    hash: 'ALG-SHA256',
    identities: qr.party_identity_ids,
    subjectDigest,
    numeric: groups.join(' '),
    qr:
      'e2eesa-kv1:' +
      mlsBase64(utf8.encode(canonical(qr)))
        .replaceAll('+', '-')
        .replaceAll('/', '_')
        .replace(/=+$/, ''),
  };
}
export function decodeProtectedSafetyQr(value) {
  need(typeof value === 'string' && value.startsWith('e2eesa-kv1:') && value.length <= 1500);
  const encoded = value.slice(11);
  need(/^[A-Za-z0-9_-]+$/.test(encoded));
  const standard = encoded.replaceAll('-', '+').replaceAll('_', '/'),
    padding = '='.repeat((4 - (standard.length % 4)) % 4),
    data = JSON.parse(decode.decode(mlsBytes(standard + padding, 2000)));
  need(
    data &&
      Object.keys(data).sort().join(',') ===
        'hash_algorithm_id,party_identity_ids,profile_ref,subject_digest_hex,v' &&
      data.v === 1 &&
      data.profile_ref === VERIFICATION_PROFILE &&
      data.hash_algorithm_id === 'ALG-SHA256' &&
      Array.isArray(data.party_identity_ids) &&
      data.party_identity_ids.length === 2 &&
      data.party_identity_ids.every((id) => typeof id === 'string' && /^[a-f0-9-]{36}$/.test(id)) &&
      data.party_identity_ids[0] < data.party_identity_ids[1] &&
      /^[a-f0-9]{64}$/.test(data.subject_digest_hex),
  );
  return data;
}
export function confirmProtectedSafety(value, { method, comparison, independent, confirmed }) {
  need(independent === true && confirmed === true && ['numeric', 'qr'].includes(method));
  if (method === 'numeric') need(comparison === value.numeric);
  else {
    const qr = decodeProtectedSafetyQr(comparison);
    need(
      qr.subject_digest_hex === value.subjectDigest &&
        canonical(qr.party_identity_ids) === canonical(value.identities),
    );
  }
  return {
    ...value,
    id: crypto.randomUUID(),
    method,
    independent: true,
    confirmed: true,
    status: 'verified',
  };
}
export function reconcileProtectedSafety(record, current) {
  if (!record) return { status: 'unverified' };
  if (
    record.status !== 'verified' ||
    record.profile !== current.profile ||
    record.hash !== current.hash ||
    record.subjectDigest !== current.subjectDigest ||
    canonical(record.identities) !== canonical(current.identities)
  )
    return { ...record, status: 'invalidated' };
  return record;
}
