import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  newMlsSigningKeys,
  newMlsKeyPackage,
  createProtectedMlsGroup,
  sealProtectedMls,
  protectedMlsKeyPackageMetadata,
  MLS_PROFILE,
} from '../packages/core/protected-mls.mjs';
import {
  protectedMlsEnvelope,
  encodeProtectedMlsBundle,
} from '../packages/core/protected-mls-envelope.mjs';
import {
  newProtectedKey,
  unlockProtectedKey,
  signProtected,
} from '../packages/core/protected-crypto.mjs';
test('shared wire parser binds actual MLS establishment and one-time references; legacy/plaintext/recipient changes fail closed', async () => {
  const a = randomUUID(),
    b = randomUUID(),
    groupId = randomUUID(),
    keys = await Promise.all([newMlsSigningKeys(), newMlsSigningKeys()]),
    [pa, pb] = await Promise.all([newMlsKeyPackage(a, keys[0]), newMlsKeyPackage(b, keys[1])]),
    members = [
      { device: a, signatureKey: keys[0].publicKey },
      { device: b, signatureKey: keys[1].publicKey },
    ].sort((a, b) => a.device.localeCompare(b.device));
  const created = await createProtectedMlsGroup({
      groupId,
      own: { device: a, package: pa },
      others: [{ device: b, wire: pb.wire }],
      members,
    }),
    context = {
      profile: MLS_PROFILE,
      recordId: groupId,
      sequence: 1,
      kind: 'incident',
      sender: a,
      recipients: members.map((m) => m.device),
      generation: 1,
      epoch: 2,
      identityHeads: [
        { id: randomUUID(), sequence: 1, hash: 'a'.repeat(64) },
        { id: randomUUID(), sequence: 1, hash: 'b'.repeat(64) },
      ].sort((a, b) => a.id.localeCompare(b.id)),
    },
    sent = await sealProtectedMls({
      state: created.state,
      context,
      payload: { text: 'MLS_API_PRIVATE_CANARY' },
      members,
    }),
    metadata = await protectedMlsKeyPackageMetadata(pb.wire, {
      device: b,
      signatureKey: keys[1].publicKey,
    }),
    bundle = {
      format: 'g28-mls-record-v1',
      members,
      setup: {
        claimId: groupId,
        creatorPackage: pa.wire,
        membershipCommit: created.membershipCommit,
        welcome: created.welcome,
        packages: [{ device: b, id: randomUUID(), hash: metadata.packageSha256 }],
      },
      commit: sent.commit,
      message: sent.message,
      chunks: [],
    };
  const pair = await newProtectedKey(randomUUID(), 'synthetic outer identity passphrase'),
    key = await unlockProtectedKey(pair.privateKey, 'synthetic outer identity passphrase'),
    unsigned = { context, ciphertext: encodeProtectedMlsBundle(bundle) },
    envelope = { ...unsigned, signature: await signProtected(unsigned, key) },
    parsed = protectedMlsEnvelope(envelope);
  assert.equal(parsed.senderLeaf, 0);
  assert.deepEqual(parsed.welcomeRefs, [metadata.keyPackageRef]);
  assert(!JSON.stringify(bundle).includes('MLS_API_PRIVATE_CANARY'));
  assert.throws(() => protectedMlsEnvelope({ ...envelope, narrative: 'never accept this field' }));
  assert.throws(() =>
    protectedMlsEnvelope({ ...envelope, ciphertext: '-----BEGIN PGP MESSAGE-----' }),
  );
  assert.throws(() =>
    protectedMlsEnvelope({
      ...envelope,
      context: { ...context, recipients: [b, a, randomUUID()].sort() },
    }),
  );
});
