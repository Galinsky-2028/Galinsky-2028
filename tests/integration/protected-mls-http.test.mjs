import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { createApp } from '../../apps/api/src/app.mjs';
import { PostgresStore, databasePool } from '../../apps/api/src/postgres-store.mjs';
import { randomToken, tokenHash } from '../../packages/core/auth.mjs';
import {
  newProtectedKey,
  unlockProtectedKey,
  signProtected,
  canonical,
} from '../../packages/core/protected-crypto.mjs';
import {
  initialProtectedIdentity,
  protectedIdentityEvent,
} from '../../packages/core/protected-identity.mjs';
import {
  newMlsSigningKeys,
  newMlsKeyPackage,
  createProtectedMlsGroup,
  joinProtectedMlsGroup,
  sealProtectedMls,
  openProtectedMls,
  MLS_PROFILE,
} from '../../packages/core/protected-mls.mjs';
import {
  encodeProtectedMlsBundle,
  protectedMlsEnvelope,
} from '../../packages/core/protected-mls-envelope.mjs';
const base = process.env.TEST_DATABASE_URL,
  prefix = '/api/protected/v2';
test(
  'real HTTP MLS intake binds root authority, burned one-time packages and private ciphertext to current MFA/role/recipient/export/retention controls',
  { skip: !base },
  async () => {
    assert(['localhost', '127.0.0.1'].includes(new URL(base).hostname));
    const name = 'g28_mls_http_' + randomBytes(5).toString('hex'),
      admin = databasePool(base),
      url = new URL(base);
    url.pathname = '/' + name;
    await admin.query('CREATE DATABASE ' + name);
    const pool = databasePool(url.href),
      store = new PostgresStore(pool),
      now = Date.now(),
      origin = 'http://localhost:4322',
      ownerKey = tokenHash(randomUUID()),
      config = {
        protectedMls: true,
        protectedSetup: true,
        protectedContent: false,
        staffIdentity: true,
        adminLoginReady: true,
        adminOwnerEmailKey: ownerKey,
        portalOrigin: origin,
        publicOrigin: 'http://localhost:4321',
      },
      app = createApp({ store, config, clock: () => now });
    const send = (who, path, payload, extra = {}) =>
      app.inject({
        method: 'POST',
        url: prefix + path,
        headers: { ...who.headers, ...extra },
        payload,
      });
    const get = (who, path) =>
      app.inject({ method: 'GET', url: prefix + path, headers: who.headers });
    try {
      for (const file of (await readdir('db/migrations')).filter((x) => x.endsWith('.sql')).sort())
        await pool.query(await readFile('db/migrations/' + file, 'utf8'));
      async function actor(owner = false) {
        const id = randomUUID(),
          token = randomToken(),
          hash = tokenHash(token),
          csrf = randomToken();
        await pool.query(
          "INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'passkey-only',now(),'synthetic')",
          [id, owner ? ownerKey : tokenHash(id)],
        );
        await pool.query(
          'INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',
          [hash, id, csrf, new Date(now + 86400000)],
        );
        if (owner)
          await store.withStaffSecurity(id, (s) => {
            s.credentials = [{ id: 'synthetic-passkey' }];
            s.sessions = { [hash]: { credentialId: 'synthetic-passkey', expires: now + 900000 } };
          });
        return {
          id,
          hash,
          headers: {
            origin,
            cookie: 'g28-local=' + token,
            'x-csrf-token': csrf,
            'content-type': 'application/json',
          },
        };
      }
      const owner = await actor(true),
        author = await actor(),
        outsider = await actor();
      const blocked = await app.inject({
        method: 'POST',
        url: prefix + '/records',
        headers: author.headers,
        payload: '{malformed PRIVATE_CANARY',
      });
      assert.equal(blocked.statusCode, 503, 'closed intake must reject before body parsing');
      async function enroll(who) {
        const secret = 'synthetic client-only identity secret',
          root = await newProtectedKey(who.id, secret),
          device = await newProtectedKey(who.id, secret),
          rootKey = await unlockProtectedKey(root.privateKey, secret),
          deviceKey = await unlockProtectedKey(device.privateKey, secret),
          mls = await newMlsSigningKeys(),
          identityId = randomUUID(),
          deviceId = randomUUID(),
          initial = await initialProtectedIdentity({
            accountId: who.id,
            identityId,
            rootPublicKey: root.publicKey,
          }),
          event = await protectedIdentityEvent(initial, {
            id: randomUUID(),
            action: 'enroll',
            subject: {
              id: deviceId,
              generation: 1,
              publicKey: device.publicKey,
              mlsSigningKey: mls.publicKey,
            },
          }),
          body = {
            identityId,
            rootPublicKey: root.publicKey,
            event,
            rootSignature: await signProtected(event, rootKey),
            deviceSignature: await signProtected(event, deviceKey),
            label: 'Synthetic local device',
            replace: false,
            confirm: 'authorize this signed device transition',
          },
          response = await send(who, '/identity', body);
        assert.equal(response.statusCode, 200, response.body);
        const retry = await send(who, '/identity', body);
        assert.equal(retry.statusCode, 200, retry.body);
        assert.equal(retry.json().duplicate, true);
        assert.equal(
          (await send(who, '/identity', { ...body, event: { ...event, action: 'rotate' } }))
            .statusCode,
          409,
        );
        return Object.assign(who, {
          identityId,
          deviceId,
          root,
          rootKey,
          device,
          deviceKey,
          mls,
          ...response.json(),
          privatePackages: new Map(),
        });
      }
      await enroll(owner);
      await enroll(author);
      await enroll(outsider);
      const noCsrf = await send(
        owner,
        '/devices/' + owner.deviceId + '/approve',
        {
          fingerprint: owner.device.fingerprint,
          identityHash: owner.stateHash,
          scope: 'incident',
          confirm: 'verified recipient identity independently',
        },
        { 'x-csrf-token': 'invalid' },
      );
      assert.equal(noCsrf.statusCode, 403);
      const approved = await send(owner, '/devices/' + owner.deviceId + '/approve', {
        fingerprint: owner.device.fingerprint,
        identityHash: owner.stateHash,
        scope: 'incident',
        confirm: 'verified recipient identity independently',
      });
      assert.equal(approved.statusCode, 200, approved.body);
      const disallowed = await send(owner, '/devices/' + outsider.deviceId + '/approve', {
        fingerprint: outsider.device.fingerprint,
        identityHash: outsider.stateHash,
        scope: 'incident',
        confirm: 'verified recipient identity independently',
      });
      assert.equal(
        disallowed.statusCode,
        403,
        'a volunteer key must not become a staff recipient through cryptographic enrollment alone',
      );
      const published = [];
      for (let i = 0; i < 2; i++) {
        const id = randomUUID(),
          pair = await newMlsKeyPackage(owner.deviceId, owner.mls, now);
        owner.privatePackages.set(id, pair);
        published.push({ id, wire: pair.wire });
      }
      const publication = await send(owner, '/key-packages', {
        deviceId: owner.deviceId,
        packages: published,
      });
      assert.equal(publication.statusCode, 200, publication.body);
      config.protectedContent = true;
      assert.equal(
        (
          await app.inject({
            method: 'GET',
            url: '/api/protected/directory',
            headers: author.headers,
          })
        ).statusCode,
        404,
        'the static prototype API is not registered for MLS intake',
      );
      const recordId = randomUUID(),
        recipients = [owner.deviceId, author.deviceId].sort(),
        claimProof = {
          action: 'claim',
          profile: MLS_PROFILE,
          recordId,
          deviceId: author.deviceId,
          recipients,
          kind: 'incident',
          generation: 1,
        },
        claimBody = {
          recordId,
          deviceId: author.deviceId,
          recipients,
          kind: 'incident',
          generation: 1,
          signature: await signProtected(claimProof, author.deviceKey),
        },
        claim = await send(author, '/claims', claimBody);
      assert.equal(claim.statusCode, 200, claim.body);
      const reservation = claim.json();
      assert.equal(
        (await send(owner, '/key-packages', { deviceId: owner.deviceId, packages: published }))
          .statusCode,
        200,
        'publication retry must not reset or reject an exactly matching reserved package',
      );
      assert.equal(
        (
          await pool.query('SELECT state FROM g28.protected_key_packages WHERE id=$1', [
            reservation.packages[0].id,
          ])
        ).rows[0].state,
        'reserved',
      );
      const own = await newMlsKeyPackage(author.deviceId, author.mls, now),
        created = await createProtectedMlsGroup({
          groupId: recordId,
          own: { device: author.deviceId, package: own },
          others: reservation.packages.map((p) => ({ device: p.device, wire: p.wire })),
          members: reservation.members,
          now,
        }),
        context = {
          profile: MLS_PROFILE,
          recordId,
          sequence: 1,
          kind: 'incident',
          sender: author.deviceId,
          recipients,
          generation: 1,
          epoch: 2,
          identityHeads: reservation.identityHeads,
        },
        payload = { text: 'ACTUAL_MLS_NARRATIVE_CANARY_6109' },
        sent = await sealProtectedMls({
          state: created.state,
          context,
          payload,
          members: reservation.members,
        }),
        bundle = {
          format: 'g28-mls-record-v1',
          members: reservation.members,
          setup: {
            claimId: recordId,
            creatorPackage: own.wire,
            membershipCommit: created.membershipCommit,
            welcome: created.welcome,
            packages: reservation.packages.map(({ device, id, hash }) => ({ device, id, hash })),
          },
          commit: sent.commit,
          message: sent.message,
          chunks: [],
        },
        unsigned = { context, ciphertext: encodeProtectedMlsBundle(bundle) },
        message = { ...unsigned, signature: await signProtected(unsigned, author.deviceKey) };
      assert.equal(
        (await send(author, '/records', { ...message, narrative: 'MUST_NOT_STORE_PLAINTEXT' }))
          .statusCode,
        400,
      );
      const receipt = await send(author, '/records', message);
      assert.equal(receipt.statusCode, 200, receipt.body);
      assert.equal(receipt.json().version, 1);
      assert.equal(
        (await send(author, '/records', message)).json().duplicate,
        true,
        'lost acknowledgements retry the exact immutable frame',
      );
      const sql = JSON.stringify(
        (await pool.query('SELECT document FROM g28.protected_records WHERE id=$1', [recordId]))
          .rows,
      );
      assert(!sql.includes(payload.text));
      assert(!sql.includes('MUST_NOT_STORE_PLAINTEXT'));
      assert(!sql.includes('PRIVATE KEY'));
      assert.equal(
        (await get(outsider, '/records/' + recordId + '?deviceId=' + outsider.deviceId)).statusCode,
        404,
      );
      const fetched = await get(owner, '/records/' + recordId + '?deviceId=' + owner.deviceId);
      assert.equal(fetched.statusCode, 200, fetched.body);
      assert.equal(fetched.json().identities.length, 2);
      const recipientPair = owner.privatePackages.get(reservation.packages[0].id),
        joined = await joinProtectedMlsGroup({
          groupId: recordId,
          welcome: created.welcome,
          own: { device: owner.deviceId, package: recipientPair },
          members: reservation.members,
        }),
        opened = await openProtectedMls({
          state: joined,
          context,
          commit: bundle.commit,
          message: bundle.message,
          members: reservation.members,
        });
      assert.deepEqual(opened.payload, payload);
      const replyContext = { ...context, sequence: 2, epoch: 3, sender: owner.deviceId },
        reply = await sealProtectedMls({
          state: opened.state,
          context: replyContext,
          payload: { text: 'PRIVATE_MLS_REPLY' },
          members: reservation.members,
        }),
        replyBundle = {
          format: 'g28-mls-record-v1',
          members: reservation.members,
          setup: null,
          commit: reply.commit,
          message: reply.message,
          chunks: [],
        },
        replyUnsigned = {
          context: replyContext,
          ciphertext: encodeProtectedMlsBundle(replyBundle),
        },
        replyMessage = {
          ...replyUnsigned,
          signature: await signProtected(replyUnsigned, owner.deviceKey),
        },
        replyReceipt = await send(owner, '/records', replyMessage);
      assert.equal(replyReceipt.statusCode, 200, replyReceipt.body);
      const parsed = protectedMlsEnvelope(replyMessage),
        authorRead = await openProtectedMls({
          state: sent.state,
          context: replyContext,
          commit: parsed.bundle.commit,
          message: parsed.bundle.message,
          members: reservation.members,
        });
      assert.equal(authorRead.payload.text, 'PRIVATE_MLS_REPLY');
      const proof = {
          action: 'export',
          profile: MLS_PROFILE,
          recordId,
          version: 2,
          deviceId: author.deviceId,
          generation: 1,
        },
        exported = await send(author, '/records/' + recordId + '/export', {
          deviceId: author.deviceId,
          version: 2,
          signature: await signProtected(proof, author.deviceKey),
          confirm: 'export exact encrypted record',
        });
      assert.equal(exported.statusCode, 200, exported.body);
      assert.equal(exported.json().record.messages.length, 2);
      assert(!exported.body.includes(payload.text));
      // The same recipient must also work as a granted non-owner reviewer;
      // withdrawing that grant must stop ciphertext/export access immediately.
      await pool.query(
        "INSERT INTO g28.admin_grants(email_key,role,display_label,granted_by) VALUES($1,'safety-reviewer','Synthetic safety reviewer',$2)",
        [ownerKey, owner.id],
      );
      const originalOwner = config.adminOwnerEmailKey;
      config.adminOwnerEmailKey = tokenHash(randomUUID());
      assert.equal(
        (await get(owner, '/records/' + recordId + '?deviceId=' + owner.deviceId)).statusCode,
        200,
      );
      await pool.query('UPDATE g28.admin_grants SET revoked_at=now() WHERE email_key=$1', [
        ownerKey,
      ]);
      assert.equal(
        (await get(owner, '/records/' + recordId + '?deviceId=' + owner.deviceId)).statusCode,
        403,
      );
      const revokedProof = { ...proof, deviceId: owner.deviceId };
      assert.equal(
        (
          await send(owner, '/records/' + recordId + '/export', {
            deviceId: owner.deviceId,
            version: 2,
            signature: await signProtected(revokedProof, owner.deviceKey),
            confirm: 'export exact encrypted record',
          })
        ).statusCode,
        403,
      );
      assert.equal(
        (await get(author, '/records/' + recordId + '?deviceId=' + author.deviceId)).statusCode,
        200,
      );
      await pool.query('UPDATE g28.admin_grants SET revoked_at=NULL WHERE email_key=$1', [
        ownerKey,
      ]);
      assert.equal(
        (await get(owner, '/records/' + recordId + '?deviceId=' + owner.deviceId)).statusCode,
        200,
      );
      await store.withStaffSecurity(owner.id, (s) => {
        s.sessions[owner.hash].expires = now - 1;
      });
      assert.equal(
        (await get(owner, '/records/' + recordId + '?deviceId=' + owner.deviceId)).statusCode,
        403,
      );
      await store.withStaffSecurity(owner.id, (s) => {
        s.sessions[owner.hash].expires = now + 900000;
      });
      config.adminOwnerEmailKey = originalOwner;
      const concurrency = await Promise.all(
        Array.from({ length: 6 }, () => get(owner, '/directory?kind=incident')),
      );
      assert(
        concurrency.every((r) => r.statusCode === 200),
        'directory authorization must not deadlock a saturated pool',
      );
      const secondRecord = randomUUID(),
        secondProof = { ...claimProof, recordId: secondRecord },
        secondClaim = await send(author, '/claims', {
          ...claimBody,
          recordId: secondRecord,
          signature: await signProtected(secondProof, author.deviceKey),
        });
      assert.equal(secondClaim.statusCode, 200, secondClaim.body);
      const burned = secondClaim.json().packages[0].id;
      await pool.query('UPDATE g28.protected_key_packages SET lease_until=$2 WHERE id=$1', [
        burned,
        new Date(now - 1),
      ]);
      await pool.query('UPDATE g28.protected_package_claims SET expires_at=$2 WHERE record_id=$1', [
        secondRecord,
        new Date(now - 1),
      ]);
      assert.equal((await send(owner, '/lifecycle/purge', {})).statusCode, 200);
      assert.equal(
        (await pool.query('SELECT state FROM g28.protected_key_packages WHERE id=$1', [burned]))
          .rows[0].state,
        'expired',
      );
      const republish = await send(owner, '/key-packages', {
        deviceId: owner.deviceId,
        packages: [published.find((p) => p.id === burned)],
      });
      assert.equal(republish.statusCode, 200, republish.body);
      assert.equal(
        (await pool.query('SELECT state FROM g28.protected_key_packages WHERE id=$1', [burned]))
          .rows[0].state,
        'expired',
        'an exact retry must never recycle a burned reservation',
      );
      assert.equal(
        (
          await send(owner, '/devices/' + owner.deviceId + '/quarantine', {
            confirm: 'withdraw device routing access',
          })
        ).statusCode,
        200,
      );
      assert.equal(
        (await get(owner, '/records/' + recordId + '?deviceId=' + owner.deviceId)).statusCode,
        409,
      );
      assert.equal(
        (
          await pool.query('SELECT sequence FROM g28.protected_identities WHERE id=$1', [
            owner.identityId,
          ])
        ).rows[0].sequence,
        1,
        'routing quarantine must never forge a root-signed revocation',
      );
      const hold = await send(owner, '/records/' + recordId + '/hold', {
        held: true,
        evidenceDigest: 'a'.repeat(64),
      });
      assert.equal(hold.statusCode, 200);
      await pool.query('UPDATE g28.protected_records SET retain_until=$2 WHERE id=$1', [
        recordId,
        new Date(now - 1),
      ]);
      assert.equal((await send(owner, '/lifecycle/purge', {})).json().deleted, 0);
      assert.equal(
        (
          await send(owner, '/records/' + recordId + '/hold', {
            held: false,
            evidenceDigest: 'b'.repeat(64),
          })
        ).statusCode,
        200,
      );
      assert.equal((await send(owner, '/lifecycle/purge', {})).json().deleted, 1);
      const evidence = (
        await pool.query('SELECT action FROM g28.protected_lifecycle_events WHERE record_id=$1', [
          recordId,
        ])
      ).rows.map((r) => r.action);
      assert(evidence.includes('mls_ciphertext_export'));
      assert(evidence.includes('mls_expired_ciphertext_deleted'));
    } finally {
      await app.close();
      await pool.end();
      await admin.query('DROP DATABASE ' + name);
      await admin.end();
    }
  },
);
