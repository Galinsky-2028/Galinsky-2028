import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  createProtectedDeviceVault,
  unlockProtectedDeviceVault,
  updateProtectedDeviceVault,
  sealProtectedThreadVault,
  openProtectedThreadVault,
  lockProtectedVault,
} from '../packages/core/protected-vault.mjs';
test('client vault uses fixed Argon2id/HKDF, fresh per-generation data keys and bound identity/record authority without escrow', async () => {
  const account = randomUUID(),
    device = randomUUID(),
    password = 'synthetic local browser vault passphrase',
    payload = { privateKey: 'SYNTHETIC_PRIVATE_KEY_CANARY' },
    created = await createProtectedDeviceVault({ account, device, password, payload }),
    expected = { account, device, minGeneration: 1 };
  assert(!JSON.stringify(created.envelope).includes(payload.privateKey));
  const session = await unlockProtectedDeviceVault(created.envelope, password, expected);
  assert.deepEqual(session.payload, payload);
  const updated = await updateProtectedDeviceVault(created.envelope, session, payload);
  assert.equal(updated.generation, 2);
  assert.notEqual(updated.envelope.wrap.ciphertext, created.envelope.wrap.ciphertext);
  await assert.rejects(
    unlockProtectedDeviceVault(created.envelope, password, { ...expected, minGeneration: 2 }),
  );
  await assert.rejects(
    unlockProtectedDeviceVault(created.envelope, 'incorrect synthetic vault password', expected),
  );
  const kdfAttack = structuredClone(created.envelope);
  kdfAttack.header.kdf.memoryKiB = 8;
  await assert.rejects(unlockProtectedDeviceVault(kdfAttack, password, expected));
  const record = randomUUID(),
    thread = await sealProtectedThreadVault(session, {
      record,
      generation: 1,
      payload: { state: 'SYNTHETIC_CURRENT_MLS_STATE' },
    });
  assert(!JSON.stringify(thread).includes('SYNTHETIC_CURRENT_MLS_STATE'));
  assert.deepEqual(await openProtectedThreadVault(session, thread, { record, minGeneration: 1 }), {
    state: 'SYNTHETIC_CURRENT_MLS_STATE',
  });
  await assert.rejects(
    openProtectedThreadVault(session, thread, { record: randomUUID(), minGeneration: 1 }),
  );
  await assert.rejects(openProtectedThreadVault(session, thread, { record, minGeneration: 2 }));
  const tampered = structuredClone(thread);
  tampered.header.generation = 2;
  await assert.rejects(openProtectedThreadVault(session, tampered, { record, minGeneration: 1 }));
  const copied = { ...session };
  await assert.rejects(
    sealProtectedThreadVault(copied, { record, generation: 2, payload: {} }),
    'copied session objects must not bypass the opaque active-session guard',
  );
  lockProtectedVault(session);
  assert(session.master.every((x) => x === 0));
  await assert.rejects(openProtectedThreadVault(session, thread, { record, minGeneration: 1 }));
  await assert.rejects(sealProtectedThreadVault(session, { record, generation: 2, payload: {} }));
  await assert.rejects(updateProtectedDeviceVault(created.envelope, session, {}));
  const race = sealProtectedThreadVault(created.session, { record, generation: 2, payload: {} });
  lockProtectedVault(created.session);
  await assert.rejects(race, 'locking must cancel an in-flight encryption before it can return');
});
