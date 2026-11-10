import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  newProtectedKey,
  unlockProtectedKey,
  signProtected,
} from '../packages/core/protected-crypto.mjs';
import { newMlsSigningKeys } from '../packages/core/protected-mls.mjs';
import {
  initialProtectedIdentity,
  protectedIdentityEvent,
  applyProtectedIdentityEvent,
  identityStateHash,
} from '../packages/core/protected-identity.mjs';
test('account root signs exact predecessor and device proof; duplicate/revoked/retired keys and server-only enrollment fail', async () => {
  const accountId = randomUUID(),
    secret = 'synthetic identity key generation secret',
    root = await newProtectedKey(accountId, secret),
    rootKey = await unlockProtectedKey(root.privateKey, secret),
    first = await newProtectedKey(accountId, secret),
    firstKey = await unlockProtectedKey(first.privateKey, secret),
    firstMls = await newMlsSigningKeys();
  let state = await initialProtectedIdentity({
    accountId,
    identityId: randomUUID(),
    rootPublicKey: root.publicKey,
  });
  const subject = {
      id: randomUUID(),
      generation: 1,
      publicKey: first.publicKey,
      mlsSigningKey: firstMls.publicKey,
    },
    event = await protectedIdentityEvent(state, { id: randomUUID(), action: 'enroll', subject }),
    rootSig = await signProtected(event, rootKey),
    proof = await signProtected(event, firstKey);
  await assert.rejects(applyProtectedIdentityEvent(state, event, proof, proof));
  await assert.rejects(applyProtectedIdentityEvent(state, event, rootSig, rootSig));
  state = await applyProtectedIdentityEvent(state, event, rootSig, proof);
  assert.equal(state.devices.length, 1);
  await assert.rejects(applyProtectedIdentityEvent(state, event, rootSig, proof));
  const second = await newProtectedKey(accountId, secret),
    secondKey = await unlockProtectedKey(second.privateKey, secret),
    secondMls = await newMlsSigningKeys(),
    secondSubject = {
      id: randomUUID(),
      generation: 1,
      publicKey: second.publicKey,
      mlsSigningKey: secondMls.publicKey,
    };
  const enrollment = await protectedIdentityEvent(state, {
    id: randomUUID(),
    action: 'enroll',
    subject: secondSubject,
  });
  await assert.rejects(
    applyProtectedIdentityEvent(
      state,
      { ...enrollment, previousStateHash: '0'.repeat(64) },
      await signProtected({ ...enrollment, previousStateHash: '0'.repeat(64) }, rootKey),
      await signProtected(enrollment, secondKey),
    ),
  );
  state = await applyProtectedIdentityEvent(
    state,
    enrollment,
    await signProtected(enrollment, rootKey),
    await signProtected(enrollment, secondKey),
  );
  assert.equal(state.devices.length, 2);
  const revoked = await protectedIdentityEvent(state, {
    id: randomUUID(),
    action: 'revoke',
    subject: { id: subject.id, generation: 1 },
  });
  state = await applyProtectedIdentityEvent(state, revoked, await signProtected(revoked, rootKey));
  assert.equal(state.retiredKeys.length, 3);
  const reused = await protectedIdentityEvent(state, {
    id: randomUUID(),
    action: 'enroll',
    subject: { ...subject, id: randomUUID() },
  });
  await assert.rejects(
    applyProtectedIdentityEvent(
      state,
      reused,
      await signProtected(reused, rootKey),
      await signProtected(reused, firstKey),
    ),
  );
  const last = await protectedIdentityEvent(state, {
    id: randomUUID(),
    action: 'revoke',
    subject: { id: secondSubject.id, generation: 1 },
  });
  await assert.rejects(
    applyProtectedIdentityEvent(state, last, await signProtected(last, rootKey)),
  );
  assert.equal((await identityStateHash(state)).length, 64);
});
