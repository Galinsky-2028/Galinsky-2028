import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { PostgresStore, databasePool } from '../../apps/api/src/postgres-store.mjs';
import {
  newProtectedKey,
  unlockProtectedKey,
  signProtected,
} from '../../packages/core/protected-crypto.mjs';
import {
  initialProtectedIdentity,
  protectedIdentityEvent,
  applyProtectedIdentityEvent,
  identityStateHash,
} from '../../packages/core/protected-identity.mjs';
import { newMlsSigningKeys } from '../../packages/core/protected-mls.mjs';
const base = process.env.TEST_DATABASE_URL;
test(
  'PostgreSQL persists only signed public authority; global retired keys, root replacement and closure cannot silently restore cryptographic trust',
  { skip: !base },
  async () => {
    assert(['localhost', '127.0.0.1'].includes(new URL(base).hostname));
    const name = 'g28_mls_directory_' + randomBytes(5).toString('hex'),
      admin = databasePool(base),
      url = new URL(base);
    url.pathname = '/' + name;
    await admin.query('CREATE DATABASE ' + name);
    const pool = databasePool(url.href),
      store = new PostgresStore(pool),
      accountId = randomUUID(),
      secret = 'synthetic separate client identity secret';
    try {
      for (const file of (await readdir('db/migrations')).filter((x) => x.endsWith('.sql')).sort())
        await pool.query(await readFile('db/migrations/' + file, 'utf8'));
      await pool.query(
        "INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'passkey-only',now(),'synthetic')",
        [accountId, randomBytes(32).toString('hex')],
      );
      async function keys() {
        const pair = await newProtectedKey(accountId, secret);
        return { ...pair, key: await unlockProtectedKey(pair.privateKey, secret) };
      }
      const root = await keys(),
        first = await keys(),
        mls = await newMlsSigningKeys(),
        identityId = randomUUID(),
        deviceId = randomUUID();
      let state = await initialProtectedIdentity({
        accountId,
        identityId,
        rootPublicKey: root.publicKey,
      });
      async function eventFor(current, action, subject, deviceKey) {
        const event = await protectedIdentityEvent(current, { id: randomUUID(), action, subject });
        return {
          event,
          rootSignature: await signProtected(event, root.key),
          deviceSignature: deviceKey ? await signProtected(event, deviceKey) : null,
        };
      }
      const initial = await eventFor(
        state,
        'enroll',
        { id: deviceId, generation: 1, publicKey: first.publicKey, mlsSigningKey: mls.publicKey },
        first.key,
      );
      const input = {
        accountId,
        identityId,
        rootPublicKey: root.publicKey,
        ...initial,
        label: 'Synthetic root-authorized device',
        replace: false,
      };
      const saved = await store.withProtectedMls((tx) => tx.commitIdentity(input));
      state = saved.state;
      assert.equal(saved.device.identityId, identityId);
      assert.equal(saved.device.state, 'enrolled');
      assert.equal(
        (await pool.query('SELECT count(*)::integer AS n FROM g28.protected_identity_keys')).rows[0]
          .n,
        5,
      );
      assert.equal(
        (await store.withProtectedMls((tx) => tx.commitIdentity(input))).duplicate,
        true,
        'an identical signed transition acknowledges a lost response without reapplying',
      );
      await assert.rejects(
        store.withProtectedMls((tx) =>
          tx.commitIdentity({
            ...input,
            event: { ...input.event, previousStateHash: '0'.repeat(64) },
          }),
        ),
      );
      const history = await store.withProtectedMls((tx) => tx.history(identityId));
      let replay = history.initialState;
      for (const row of history.events)
        replay = await applyProtectedIdentityEvent(
          replay,
          row.document,
          row.rootSignature,
          row.deviceSignature,
        );
      assert.equal(
        await identityStateHash(replay),
        saved.stateHash,
        'JSONB must not invalidate root signatures',
      );
      const second = await keys(),
        secondMls = await newMlsSigningKeys(),
        secondId = randomUUID(),
        enroll = await eventFor(
          state,
          'enroll',
          {
            id: secondId,
            generation: 1,
            publicKey: second.publicKey,
            mlsSigningKey: secondMls.publicKey,
          },
          second.key,
        );
      state = (
        await store.withProtectedMls((tx) =>
          tx.commitIdentity({ ...input, ...enroll, label: 'Second synthetic device' }),
        )
      ).state;
      const revoke = await eventFor(state, 'revoke', { id: deviceId, generation: 1 });
      state = (await store.withProtectedMls((tx) => tx.commitIdentity({ ...input, ...revoke })))
        .state;
      assert.equal(
        (
          await pool.query(
            'SELECT state,generation,quarantined FROM g28.protected_devices WHERE id=$1',
            [deviceId],
          )
        ).rows[0].state,
        'revoked',
      );
      const newRoot = await keys(),
        newRootKey = newRoot.key,
        newIdentity = randomUUID(),
        newInitial = await initialProtectedIdentity({
          accountId,
          identityId: newIdentity,
          rootPublicKey: newRoot.publicKey,
        });
      const reuse = await protectedIdentityEvent(newInitial, {
          id: randomUUID(),
          action: 'enroll',
          subject: {
            id: randomUUID(),
            generation: 1,
            publicKey: first.publicKey,
            mlsSigningKey: (await newMlsSigningKeys()).publicKey,
          },
        }),
        reuseInput = {
          accountId,
          identityId: newIdentity,
          rootPublicKey: newRoot.publicKey,
          event: reuse,
          rootSignature: await signProtected(reuse, newRootKey),
          deviceSignature: await signProtected(reuse, first.key),
          label: 'Rejected reused raw key',
          replace: true,
        };
      await assert.rejects(
        store.withProtectedMls((tx) => tx.commitIdentity(reuseInput)),
        (e) => e.code === 'retired_identity_key',
      );
      const fresh = await keys(),
        freshMls = await newMlsSigningKeys(),
        freshId = randomUUID(),
        replacement = await protectedIdentityEvent(newInitial, {
          id: randomUUID(),
          action: 'enroll',
          subject: {
            id: freshId,
            generation: 1,
            publicKey: fresh.publicKey,
            mlsSigningKey: freshMls.publicKey,
          },
        }),
        replacementInput = {
          ...reuseInput,
          event: replacement,
          rootSignature: await signProtected(replacement, newRootKey),
          deviceSignature: await signProtected(replacement, fresh.key),
          label: 'New unverified identity',
        };
      await assert.rejects(
        store.withProtectedMls((tx) => tx.commitIdentity({ ...replacementInput, replace: false })),
        (e) => e.code === 'identity_replacement_confirmation',
      );
      const replaced = await store.withProtectedMls((tx) => tx.commitIdentity(replacementInput));
      assert.equal(replaced.device.state, 'enrolled');
      assert.equal(replaced.device.scope, null);
      assert.equal(
        (await pool.query('SELECT current FROM g28.protected_identities WHERE id=$1', [identityId]))
          .rows[0].current,
        false,
      );
      assert(
        (
          await pool.query('SELECT quarantined FROM g28.protected_devices WHERE identity_id=$1', [
            identityId,
          ])
        ).rows.every((r) => r.quarantined),
      );
      const serialized = JSON.stringify(
        (await pool.query('SELECT state FROM g28.protected_identities')).rows,
      );
      assert(!serialized.includes('PRIVATE KEY'));
      assert(!serialized.includes(secret));
      const sequence = replaced.state.sequence;
      await pool.query('DELETE FROM g28.accounts WHERE id=$1', [accountId]);
      const closed = (
        await pool.query(
          'SELECT account_id,current,sequence FROM g28.protected_identities WHERE id=$1',
          [newIdentity],
        )
      ).rows[0];
      assert.equal(closed.account_id, null);
      assert.equal(closed.current, false);
      assert.equal(
        closed.sequence,
        sequence,
        'closure may quarantine routing but cannot forge a root-signed transition',
      );
      const d = (
        await pool.query(
          'SELECT account_id,generation,quarantined FROM g28.protected_devices WHERE id=$1',
          [freshId],
        )
      ).rows[0];
      assert.equal(d.account_id, null);
      assert.equal(d.generation, 1);
      assert(d.quarantined);
    } finally {
      await pool.end();
      await admin.query('DROP DATABASE ' + name);
      await admin.end();
    }
  },
);
