import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  newMlsSigningKeys,
  newMlsKeyPackage,
  createProtectedMlsGroup,
  joinProtectedMlsGroup,
  sealProtectedMls,
  openProtectedMls,
  storeMlsState,
  restoreMlsState,
  mlsBytes,
  mlsBase64,
  MLS_PROFILE,
} from '../packages/core/protected-mls.mjs';
test('registered MLS suite establishes exact authenticated devices and erases old epoch state; replay and wrong membership fail', async () => {
  const ids = [randomUUID(), randomUUID(), randomUUID()],
    keys = await Promise.all(ids.map(() => newMlsSigningKeys())),
    packages = await Promise.all(ids.map((id, i) => newMlsKeyPackage(id, keys[i]))),
    members = ids.slice(0, 2).map((device, i) => ({ device, signatureKey: keys[i].publicKey })),
    groupId = randomUUID();
  const a = { device: ids[0], package: packages[0] },
    b = { device: ids[1], package: packages[1] },
    created = await createProtectedMlsGroup({
      groupId,
      own: a,
      others: [{ device: b.device, wire: b.package.wire }],
      members,
    });
  let alice = created.state,
    bob = await joinProtectedMlsGroup({ groupId, welcome: created.welcome, own: b, members });
  const context = {
      profile: MLS_PROFILE,
      recordId: groupId,
      epoch: 2,
      sequence: 1,
      sender: a.device,
      recipients: members.map((m) => m.device).sort(),
      generation: 1,
      kind: 'incident',
    },
    payload = { text: 'MLS_PRIVATE_CANARY_982' };
  const sent = await sealProtectedMls({ state: alice, context, payload, members });
  alice = sent.state;
  assert(!sent.message.includes(payload.text));
  const before = storeMlsState(bob),
    tampered = mlsBytes(sent.message);
  tampered[tampered.length - 20] ^= 1;
  await assert.rejects(
    openProtectedMls({
      state: bob,
      context,
      commit: sent.commit,
      message: mlsBase64(tampered),
      members,
    }),
  );
  assert.equal(
    storeMlsState(bob),
    before,
    'failed application authentication must preserve prior valid state',
  );
  await assert.rejects(
    openProtectedMls({
      state: bob,
      context: { ...context, sender: b.device },
      commit: sent.commit,
      message: sent.message,
      members,
    }),
  );
  assert.equal(storeMlsState(bob), before);
  const retired = Object.values(bob.keySchedule);
  const opened = await openProtectedMls({
    state: bob,
    context,
    commit: sent.commit,
    message: sent.message,
    members,
  });
  bob = opened.state;
  assert.deepEqual(opened.payload, payload);
  for (const key of retired)
    assert(
      key.every((x) => x === 0),
      'retired epoch secrets must be erased',
    );
  assert.equal(alice.historicalReceiverData.size, 0);
  assert.equal(bob.historicalReceiverData.size, 0);
  await assert.rejects(
    openProtectedMls({ state: bob, context, commit: sent.commit, message: sent.message, members }),
  );
  const restored = restoreMlsState(storeMlsState(bob), members, groupId);
  assert.equal(restored.groupContext.epoch, bob.groupContext.epoch);
  assert.throws(() =>
    restoreMlsState(
      storeMlsState(bob),
      [{ ...members[0], signatureKey: keys[2].publicKey }, members[1]],
      groupId,
    ),
  );
  const replyContext = { ...context, epoch: 3, sequence: 2, sender: b.device },
    reply = await sealProtectedMls({
      state: bob,
      context: replyContext,
      payload: { text: 'reply' },
      members,
    });
  bob = reply.state;
  const received = await openProtectedMls({
    state: alice,
    context: replyContext,
    commit: reply.commit,
    message: reply.message,
    members,
  });
  assert.equal(received.payload.text, 'reply');
  await assert.rejects(
    joinProtectedMlsGroup({
      groupId,
      welcome: created.welcome,
      own: { device: ids[2], package: packages[2] },
      members,
    }),
  );
  await assert.rejects(
    openProtectedMls({
      state: received.state,
      context: { ...replyContext, recordId: randomUUID() },
      commit: reply.commit,
      message: reply.message,
      members,
    }),
  );
});
