import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  protectedSafetyValue,
  decodeProtectedSafetyQr,
  confirmProtectedSafety,
  reconcileProtectedSafety,
} from '../packages/core/protected-verification.mjs';
import { IDENTITY_PROFILE } from '../packages/core/protected-identity.mjs';
test('registered root verification is perspective-independent, uses twelve exact numeric groups and requires fresh independent confirmation after invalidation', async () => {
  const a = {
      profile: IDENTITY_PROFILE,
      identityId: randomUUID(),
      rootFingerprint: 'a'.repeat(64),
    },
    b = { ...a, identityId: randomUUID(), rootFingerprint: 'b'.repeat(64) },
    value = await protectedSafetyValue(a, b);
  assert.deepEqual(value, await protectedSafetyValue(b, a));
  assert.match(value.numeric, /^\d{5}( \d{5}){11}$/);
  assert.equal(decodeProtectedSafetyQr(value.qr).subject_digest_hex, value.subjectDigest);
  assert.throws(() =>
    confirmProtectedSafety(value, {
      method: 'numeric',
      comparison: value.numeric,
      independent: false,
      confirmed: true,
    }),
  );
  const record = confirmProtectedSafety(value, {
    method: 'qr',
    comparison: value.qr,
    independent: true,
    confirmed: true,
  });
  assert.equal(record.status, 'verified');
  const changed = await protectedSafetyValue(a, { ...b, rootFingerprint: 'c'.repeat(64) }),
    invalid = reconcileProtectedSafety(record, changed);
  assert.equal(invalid.status, 'invalidated');
  assert.equal(
    reconcileProtectedSafety(invalid, value).status,
    'invalidated',
    'old values cannot silently revive invalidated trust',
  );
  assert.throws(() =>
    confirmProtectedSafety(changed, {
      method: 'qr',
      comparison: value.qr,
      independent: true,
      confirmed: true,
    }),
  );
  assert.throws(() => decodeProtectedSafetyQr(value.qr + '='));
});
