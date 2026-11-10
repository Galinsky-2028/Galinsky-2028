import { randomUUID, createHash } from 'node:crypto';
import { assert, exactKeys } from '../../../packages/core/validation.mjs';
import { staffCan } from '../../../packages/core/staff-permissions.mjs';
import {
  publicProtectedKey,
  verifyProtected,
  canonical,
} from '../../../packages/core/protected-crypto.mjs';
import { protectedId } from '../../../packages/core/protected-records.mjs';
import { identityStateHash } from '../../../packages/core/protected-identity.mjs';
import {
  MLS_PROFILE,
  protectedMlsKeyPackageMetadata,
} from '../../../packages/core/protected-mls.mjs';
import { protectedMlsEnvelope } from '../../../packages/core/protected-mls-envelope.mjs';
const prefix = '/api/protected/v2',
  digest = (value) => createHash('sha256').update(canonical(value)).digest('hex');
const kinds = ['incident', 'help', 'correction', 'profile', 'operational_note'];
const label = (value) => {
  assert(
    typeof value === 'string' &&
      value.trim().length >= 2 &&
      value.length <= 60 &&
      !/[\x00-\x1f]/.test(value),
    'invalid_device_label',
    'Choose a short device label.',
  );
  return value.trim();
};
export function registerProtectedMls(app, { store, config, account, writeSession, clock }) {
  const setup = () =>
    assert(
      (config.protectedSetup === true || config.protectedContent === true) &&
        config.protectedMls === true &&
        config.staffIdentity === true &&
        typeof store.withProtectedMls === 'function',
      'protected_unavailable',
      'The reviewed protected client is not configured. Nothing has been stored.',
      503,
    );
  const intake = () => {
    setup();
    assert(
      config.protectedContent === true,
      'protected_unavailable',
      'Confidential intake is not open. Nothing has been stored.',
      503,
    );
  };
  async function staff(s, permission, tx) {
    const role = await tx.store.adminRole(s.account, config.adminOwnerEmailKey);
    assert(
      staffCan(role, permission),
      'staff_forbidden',
      'Your current role cannot perform this action.',
      403,
    );
    assert(
      await tx.store.staffMfaValid(s.account.id, s.hash, clock()),
      'mfa_required',
      'Verify your staff passkey first.',
      403,
    );
    return role;
  }
  async function currentDevice(tx, id) {
    const d = await tx.device(protectedId(id)),
      i = d?.identityId ? await tx.identity(d.identityId) : null,
      v = i?.state?.devices?.find((v) => v.id === d.id);
    assert(
      d &&
        i?.current &&
        i.accountId === d.accountId &&
        d.accountId &&
        v?.state === 'active' &&
        v.generation === d.generation &&
        v.publicKey === d.publicKey &&
        v.mlsSigningKey === d.mlsSigningKey &&
        !d.quarantined &&
        d.state !== 'revoked' &&
        (await identityStateHash(i.state)) === i.stateHash,
      'protected_device_unavailable',
      'A device was changed, retired or quarantined. Recheck current recipient authority.',
      409,
    );
    return { ...d, identity: i };
  }
  async function recipient(d, kind, tx) {
    return (
      d.state === 'approved' &&
      d.scope === kind &&
      !d.quarantined &&
      (await tx.store.protectedRecipientAuthorized(d.accountId, kind, config.adminOwnerEmailKey))
    );
  }
  async function ownDevice(tx, s, id) {
    const d = await currentDevice(tx, id);
    assert(
      d.accountId === s.account.id,
      'protected_device_forbidden',
      'Use your own authorized device.',
      403,
    );
    return d;
  }
  async function readable(tx, id, s, deviceId) {
    const doc = await tx.record(protectedId(id));
    assert(
      doc?.protocol === MLS_PROFILE &&
        doc.participants.includes(s.account.id) &&
        (Date.parse(doc.retainUntil) > clock() || doc.legalHold),
      'not_found',
      'Protected record not found.',
      404,
    );
    const d = await ownDevice(tx, s, deviceId),
      original = doc.memberKeys.find((m) => m.device === d.id);
    assert(
      original &&
        original.generation === d.generation &&
        original.publicKey === d.publicKey &&
        original.signatureKey === d.mlsSigningKey,
      'protected_history_unavailable',
      'This browser device has no original authority for that record. Account recovery cannot restore old decryption keys.',
      403,
    );
    if (doc.authorId !== s.account.id) {
      assert(
        await recipient(d, doc.kind, tx),
        'recipient_scope',
        'Current recipient approval was withdrawn.',
        403,
      );
      assert(
        await tx.store.staffMfaValid(s.account.id, s.hash, clock()),
        'mfa_required',
        'Verify your staff passkey before accessing protected records.',
        403,
      );
    }
    return { doc, device: d };
  }
  async function histories(tx, doc) {
    const ids = new Map();
    for (const m of doc.messages)
      for (const h of m.context.identityHeads)
        ids.set(h.id, Math.max(ids.get(h.id) || 0, h.sequence));
    const result = [];
    for (const [id, sequence] of ids) result.push({ id, ...(await tx.history(id, sequence)) });
    return result;
  }
  app.get(prefix + '/identity', async (req) => {
    setup();
    const s = await account(req);
    return store.withProtectedMls(async (tx) => {
      const identity = await tx.currentIdentity(s.account.id);
      return identity
        ? {
            identity: identity.state,
            stateHash: identity.stateHash,
            history: await tx.history(identity.id),
          }
        : { identity: null };
    });
  });
  app.post(prefix + '/identity', { bodyLimit: 40000 }, async (req) => {
    setup();
    const s = await writeSession(req),
      b = exactKeys(req.body, [
        'identityId',
        'rootPublicKey',
        'event',
        'rootSignature',
        'deviceSignature',
        'label',
        'replace',
        'confirm',
      ]);
    protectedId(b.identityId);
    assert(
      typeof b.replace === 'boolean' &&
        b.confirm ===
          (b.replace
            ? 'start a new unverified identity'
            : 'authorize this signed device transition'),
      'identity_confirmation',
      'Confirm the exact device transition or irreversible unverified replacement.',
    );
    assert(
      await store.rate('protected-identity:' + s.account.id, 20, clock() + 3600000),
      'rate_limited',
      'Wait before changing more device authority.',
      429,
    );
    try {
      return await store.withProtectedMls((tx) =>
        tx.commitIdentity({
          accountId: s.account.id,
          identityId: b.identityId,
          rootPublicKey: b.rootPublicKey,
          event: b.event,
          rootSignature: b.rootSignature,
          deviceSignature: b.deviceSignature,
          label: label(b.label),
          replace: b.replace,
        }),
      );
    } catch (error) {
      if (error.code && error.status) throw error;
      assert(
        false,
        'invalid_identity_proof',
        'The signed device authority failed validation. No transition was stored.',
        400,
      );
    }
  });
  app.get(prefix + '/directory', async (req) => {
    setup();
    const s = await account(req),
      q = exactKeys(req.query, ['kind', 'after']);
    assert(kinds.includes(q.kind), 'invalid_kind', 'Choose a protected record type.');
    if (q.after) protectedId(q.after);
    return store.withProtectedMls(async (tx) => {
      const role = await tx.store.adminRole(s.account, config.adminOwnerEmailKey),
        review =
          staffCan(role, 'security:manage') &&
          (await tx.store.staffMfaValid(s.account.id, s.hash, clock())),
        page = await tx.directory(s.account.id, q.kind, q.after, review),
        devices = [];
      for (const row of page.devices) {
        try {
          const d = await currentDevice(tx, row.id);
          if (review || d.accountId === s.account.id || (await recipient(d, q.kind, tx)))
            devices.push({ ...row });
        } catch {
          /* Unavailable keys are never offered. */
        }
      }
      return {
        ...page,
        devices,
        notice:
          'Verify signed identity history and compare the numeric/QR root value independently. Directory rows and staff approval do not by themselves establish cryptographic trust.',
      };
    });
  });
  app.get(prefix + '/identities/:id', async (req) => {
    setup();
    const s = await account(req),
      q = exactKeys(req.query, ['fingerprint']);
    assert(
      await store.rate('protected-public-identity:' + s.account.id, 60, clock() + 60000),
      'rate_limited',
      'Wait before reading more public identity packets.',
      429,
    );
    return store.withProtectedMls(async (tx) => {
      const i = await tx.identity(protectedId(req.params.id));
      assert(
        i?.current &&
          (i.accountId === s.account.id ||
            (typeof q.fingerprint === 'string' &&
              /^[a-f0-9]{64}$/.test(q.fingerprint) &&
              q.fingerprint === i.rootFingerprint)),
        'not_found',
        'Public identity not found.',
        404,
      );
      return {
        identity: i.state,
        stateHash: i.stateHash,
        history: await tx.history(i.id),
        notice:
          'Public cryptographic identity only. This does not approve a staff recipient, disclose private reports or replace independent verification.',
      };
    });
  });

  app.post(prefix + '/devices/:id/approve', async (req) => {
    setup();
    const s = await writeSession(req),
      b = exactKeys(req.body, ['fingerprint', 'identityHash', 'scope', 'confirm']);
    assert(
      kinds.includes(b.scope) && b.confirm === 'verified recipient identity independently',
      'recipient_confirmation',
      'Verify the exact recipient identity through an independent trusted channel.',
    );
    return store.withProtectedMls(async (tx) => {
      await staff(s, 'security:manage', tx);
      const d = await currentDevice(tx, req.params.id);
      assert(
        d.fingerprint === b.fingerprint && d.identity.stateHash === b.identityHash,
        'recipient_mismatch',
        'The signed device or identity changed.',
        409,
      );
      assert(
        await tx.store.protectedRecipientAuthorized(
          d.accountId,
          b.scope,
          config.adminOwnerEmailKey,
        ),
        'recipient_scope',
        'The recipient lacks the required current staff role.',
        403,
      );
      await tx.query(
        "UPDATE g28.protected_devices SET state='approved',scope=$2,approved_by=$3,quarantined=false WHERE id=$1",
        [d.id, b.scope, s.account.id],
      );
      await tx.audit(s.account.id, d.id, 'mls_recipient_approved', d.identity.stateHash);
      return { approved: true };
    });
  });
  app.post(prefix + '/devices/:id/quarantine', async (req) => {
    setup();
    const s = await writeSession(req),
      b = exactKeys(req.body, ['confirm']);
    assert(
      b.confirm === 'withdraw device routing access',
      'quarantine_confirmation',
      'Confirm withdrawal of future routing access.',
    );
    return store.withProtectedMls(async (tx) => {
      await staff(s, 'security:manage', tx);
      const d = await tx.device(protectedId(req.params.id));
      assert(d?.identityId, 'not_found', 'Device not found.', 404);
      await tx.query('UPDATE g28.protected_devices SET quarantined=true WHERE id=$1', [d.id]);
      await tx.query(
        "UPDATE g28.protected_key_packages SET state='expired',wire=NULL,lease_until=NULL WHERE device_id=$1 AND state<>'used'",
        [d.id],
      );
      await tx.audit(s.account.id, d.id, 'routing_quarantined');
      return {
        quarantined: true,
        notice:
          'Routing is withdrawn. This is not a forged root-signed identity revocation and cannot erase retained plaintext or keys. The account root must authorize any identity transition.',
      };
    });
  });
  app.post(prefix + '/key-packages', { bodyLimit: 200000 }, async (req) => {
    setup();
    const s = await writeSession(req),
      b = exactKeys(req.body, ['deviceId', 'packages']);
    assert(
      Array.isArray(b.packages) && b.packages.length >= 1 && b.packages.length <= 16,
      'package_batch',
      'Publish one to sixteen fresh public packages.',
    );
    return store.withProtectedMls(async (tx) => {
      const d = await ownDevice(tx, s, b.deviceId);
      const n = (
        await tx.query(
          "SELECT count(*)::integer AS n FROM g28.protected_key_packages WHERE device_id=$1 AND state='available' AND expires_at>$2",
          [d.id, new Date(clock())],
        )
      ).rows[0].n;
      let available = n;
      const saved = [];
      for (const item of b.packages) {
        exactKeys(item, ['id', 'wire']);
        protectedId(item.id);
        let meta;
        try {
          meta = await protectedMlsKeyPackageMetadata(
            item.wire,
            { device: d.id, signatureKey: d.mlsSigningKey },
            clock(),
          );
        } catch {
          assert(
            false,
            'invalid_key_package',
            'A public key package failed signature, identity or lifetime validation.',
            400,
          );
        }
        const previous = (
          await tx.query(
            'SELECT id,device_id,state,package_sha256 FROM g28.protected_key_packages WHERE id=$1 OR package_sha256=$2 OR init_sha256=$3',
            [item.id, meta.packageSha256, meta.initSha256],
          )
        ).rows[0];
        if (previous) {
          assert(
            previous.id === item.id &&
              previous.device_id === d.id &&
              previous.package_sha256 === meta.packageSha256,
            'key_package_reused',
            'A reserved, used or retired initialization key cannot be reused.',
            409,
          );
          saved.push(item.id);
          continue;
        }
        assert(
          available < 32,
          'package_pool_full',
          'The device already has enough available one-time packages.',
          409,
        );
        available++;
        await tx.query(
          "INSERT INTO g28.protected_key_packages(id,device_id,identity_id,generation,package_sha256,init_sha256,package_ref,wire,expires_at,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'available')",
          [
            item.id,
            d.id,
            d.identityId,
            d.generation,
            meta.packageSha256,
            meta.initSha256,
            meta.keyPackageRef,
            item.wire,
            meta.expiresAt,
          ],
        );
        saved.push(item.id);
      }
      await tx.audit(s.account.id, d.id, 'public_key_packages_published');
      return { published: saved };
    });
  });
  app.get(prefix + '/key-packages', async (req) => {
    setup();
    const s = await account(req),
      q = exactKeys(req.query, ['deviceId']);
    return store.withProtectedMls(async (tx) => {
      const d = await ownDevice(tx, s, q.deviceId);
      return {
        packages: (
          await tx.query(
            'SELECT id,state,record_id AS "recordId",expires_at AS "expiresAt" FROM g28.protected_key_packages WHERE device_id=$1 ORDER BY created_at DESC LIMIT 128',
            [d.id],
          )
        ).rows,
      };
    });
  });
  app.post(prefix + '/claims', async (req) => {
    intake();
    const s = await writeSession(req),
      b = exactKeys(req.body, [
        'recordId',
        'deviceId',
        'recipients',
        'kind',
        'generation',
        'signature',
      ]);
    protectedId(b.recordId);
    assert(
      kinds.includes(b.kind) &&
        Array.isArray(b.recipients) &&
        b.recipients.length >= 2 &&
        b.recipients.length <= 12 &&
        canonical(b.recipients) === canonical([...new Set(b.recipients)].sort()) &&
        b.recipients.includes(b.deviceId),
      'invalid_recipients',
      'Choose the exact sorted device recipients.',
    );
    b.recipients.forEach(protectedId);
    assert(
      await store.rate('protected-claim:' + s.account.id, 10, clock() + 3600000),
      'rate_limited',
      'Wait before reserving more recipient packages.',
      429,
    );
    return store.withProtectedMls(async (tx) => {
      const sender = await ownDevice(tx, s, b.deviceId);
      assert(
        sender.generation === b.generation &&
          (await verifyProtected(
            {
              action: 'claim',
              profile: MLS_PROFILE,
              recordId: b.recordId,
              deviceId: b.deviceId,
              recipients: b.recipients,
              kind: b.kind,
              generation: b.generation,
            },
            b.signature,
            (await publicProtectedKey(sender.publicKey)).key,
          )),
        'claim_proof',
        'Unlock the current device before reserving packages.',
        403,
      );
      let outside = false;
      const devices = [];
      for (const id of b.recipients) {
        const d = await currentDevice(tx, id);
        if (d.accountId !== s.account.id) {
          outside = true;
          assert(
            await recipient(d, b.kind, tx),
            'recipient_scope',
            'The current recipient is not approved for this record type.',
            403,
          );
        }
        devices.push(d);
      }
      assert(outside, 'protected_recipients', 'Select a named authorized staff recipient.', 403);
      const existing = (
        await tx.query('SELECT * FROM g28.protected_package_claims WHERE record_id=$1', [
          b.recordId,
        ])
      ).rows[0];
      if (existing)
        assert(
          tx.sameClaim(existing, s.account.id, b.deviceId, b.recipients, b.kind) &&
            existing.expires_at.getTime() > clock(),
          'claim_unavailable',
          'This claim expired or its ownership/recipient set changed. Start a fresh record.',
          409,
        );
      else {
        assert(
          !(await tx.record(b.recordId)) &&
            !(
              await tx.query(
                'SELECT 1 FROM g28.protected_lifecycle_events WHERE record_id=$1 LIMIT 1',
                [b.recordId],
              )
            ).rowCount,
          'retired_protected_record',
          'This reference was already used. Start a fresh record.',
          409,
        );
        await tx.query(
          'INSERT INTO g28.protected_package_claims(record_id,account_id,sender_device_id,recipient_devices,kind,expires_at) VALUES($1,$2,$3,$4,$5,$6)',
          [b.recordId, s.account.id, b.deviceId, b.recipients, b.kind, new Date(clock() + 300000)],
        );
      }
      const packages = [];
      for (const d of devices.filter((d) => d.id !== b.deviceId)) {
        let row = (
          await tx.query(
            "SELECT id,wire,package_sha256 AS hash,generation FROM g28.protected_key_packages WHERE record_id=$1 AND device_id=$2 AND state='reserved' AND lease_until>$3",
            [b.recordId, d.id, new Date(clock())],
          )
        ).rows[0];
        if (!row) {
          assert(
            !existing,
            'claim_unavailable',
            'A one-time package is no longer available. Start a fresh record.',
            409,
          );
          row = (
            await tx.query(
              "SELECT id,wire,package_sha256 AS hash,generation FROM g28.protected_key_packages WHERE device_id=$1 AND identity_id=$2 AND generation=$3 AND state='available' AND expires_at>$4 ORDER BY created_at,id LIMIT 1 FOR UPDATE",
              [d.id, d.identityId, d.generation, new Date(clock() + 600000)],
            )
          ).rows[0];
          assert(
            row,
            'recipient_offline',
            'A recipient needs to open their protected inbox to publish fresh one-time packages. No report was sent.',
            409,
          );
          await tx.query(
            "UPDATE g28.protected_key_packages SET state='reserved',record_id=$2,lease_until=$3 WHERE id=$1",
            [row.id, b.recordId, new Date(clock() + 300000)],
          );
        }
        assert(
          row.generation === d.generation && row.wire,
          'claim_unavailable',
          'Recipient keys changed. Start a fresh record.',
          409,
        );
        packages.push({ device: d.id, id: row.id, wire: row.wire, hash: row.hash });
      }
      const heads = new Map(
        devices.map((d) => [
          d.identityId,
          { id: d.identityId, sequence: d.identity.sequence, hash: d.identity.stateHash },
        ]),
      );
      return {
        recordId: b.recordId,
        expiresAt: existing?.expires_at.toISOString() || new Date(clock() + 300000).toISOString(),
        packages: packages.sort((a, b) => a.device.localeCompare(b.device)),
        members: devices
          .map((d) => ({ device: d.id, signatureKey: d.mlsSigningKey }))
          .sort((a, b) => a.device.localeCompare(b.device)),
        identityHeads: [...heads.values()].sort((a, b) => a.id.localeCompare(b.id)),
      };
    });
  });
  app.get(prefix + '/records', async (req) => {
    intake();
    const s = await account(req);
    return store.withProtectedMls(async (tx) => ({
      records: (
        await tx.query(
          "SELECT id,version,updated_at AS \"updatedAt\",document->>'kind' AS kind,document->>'status' AS status FROM g28.protected_records WHERE $1=ANY(participants) AND document->>'protocol'=$2 AND (retain_until>$3 OR legal_hold) ORDER BY updated_at DESC LIMIT 100",
          [s.account.id, MLS_PROFILE, new Date(clock())],
        )
      ).rows,
    }));
  });
  app.get(prefix + '/records/:id', async (req) => {
    intake();
    const s = await account(req),
      q = exactKeys(req.query, ['deviceId']);
    return store.withProtectedMls(async (tx) => {
      const { doc } = await readable(tx, req.params.id, s, q.deviceId);
      await tx.audit(s.account.id, doc.id, 'mls_ciphertext_read');
      return { record: doc, identities: await histories(tx, doc) };
    });
  });
  app.post(prefix + '/records', { bodyLimit: 410000 }, async (req) => {
    intake();
    const s = await writeSession(req);
    let parsed;
    try {
      parsed = protectedMlsEnvelope(req.body);
    } catch (error) {
      if (error.code && error.status) throw error;
      assert(false, 'invalid_protected_proof', 'The encrypted wire format failed validation.', 400);
    }
    const { envelope: message, bundle, senderLeaf, welcomeRefs } = parsed,
      ctx = message.context;
    assert(
      await store.rate('protected-submit:' + s.account.id, 30, clock() + 3600000),
      'rate_limited',
      'Wait before sending more protected messages.',
      429,
    );
    return store.withProtectedMls(async (tx) => {
      const sender = await ownDevice(tx, s, ctx.sender);
      assert(
        sender.generation === ctx.generation,
        'stale_key_generation',
        'Device keys changed. Start a new verified thread.',
        409,
      );
      const old = await tx.record(ctx.recordId);
      if (old) {
        await readable(tx, ctx.recordId, s, ctx.sender);
        const previous = old.messages[ctx.sequence - 1];
        if (previous) {
          assert(
            canonical(previous) === canonical(message),
            'protected_version_conflict',
            'A different message won this sequence. Synchronize before explicitly sending a new draft.',
            409,
          );
          return { id: old.id, version: old.messages.length, status: old.status, duplicate: true };
        }
      }
      assert(
        !old || old.status !== 'closed',
        'protected_record_closed',
        'This thread is closed. Start a new verified record.',
        409,
      );
      assert(
        !old ||
          (ctx.sequence === old.messages.length + 1 &&
            ctx.kind === old.kind &&
            canonical(ctx.recipients) === canonical(old.memberKeys.map((m) => m.device).sort())),
        'protected_version_conflict',
        'Synchronize the original thread before sending.',
        409,
      );
      const devices = [];
      for (const id of ctx.recipients) {
        const d = await currentDevice(tx, id);
        if (d.accountId !== (old?.authorId || s.account.id))
          assert(
            await recipient(d, ctx.kind, tx),
            'recipient_scope',
            'A recipient lost current approval. This thread cannot receive new content.',
            403,
          );
        devices.push(d);
      }
      if (!old)
        assert(
          ctx.sequence === 1 && devices.some((d) => d.accountId !== s.account.id),
          'protected_recipients',
          'Select an authorized staff recipient.',
          403,
        );
      const expectedMembers = devices
        .map((d) => ({ device: d.id, signatureKey: d.mlsSigningKey }))
        .sort((a, b) => a.device.localeCompare(b.device));
      assert(
        canonical(bundle.members) === canonical(expectedMembers),
        'recipient_keys_changed',
        'Recipient keys changed. Start a new verified group.',
        409,
      );
      if (old)
        assert(
          devices.every((d) =>
            old.memberKeys.some(
              (m) =>
                m.device === d.id &&
                m.generation === d.generation &&
                m.publicKey === d.publicKey &&
                m.signatureKey === d.mlsSigningKey &&
                m.identityId === d.identityId,
            ),
          ),
          'recipient_keys_changed',
          'Original device generations changed. This group is frozen.',
          409,
        );
      const heads = new Map(
        devices.map((d) => [
          d.identityId,
          { id: d.identityId, sequence: d.identity.sequence, hash: d.identity.stateHash },
        ]),
      );
      assert(
        canonical(ctx.identityHeads) ===
          canonical([...heads.values()].sort((a, b) => a.id.localeCompare(b.id))),
        'identity_head_changed',
        'Signed identity state changed. Synchronize and recheck trust.',
        409,
      );
      const leafOrder = old?.leafOrder || [
        ctx.sender,
        ...ctx.recipients.filter((id) => id !== ctx.sender),
      ];
      assert(
        leafOrder[senderLeaf] === ctx.sender,
        'mls_sender_mismatch',
        'The MLS sender does not match the outer identity.',
        400,
      );
      assert(
        await verifyProtected(
          { context: ctx, ciphertext: message.ciphertext },
          message.signature,
          (await publicProtectedKey(sender.publicKey)).key,
        ),
        'invalid_protected_proof',
        'Sender signature failed. No content was stored.',
        400,
      );
      if (!old) {
        assert(
          !(
            await tx.query(
              'SELECT 1 FROM g28.protected_lifecycle_events WHERE record_id=$1 LIMIT 1',
              [ctx.recordId],
            )
          ).rowCount,
          'retired_protected_record',
          'This record reference is retired.',
          409,
        );
        const claim = (
          await tx.query('SELECT * FROM g28.protected_package_claims WHERE record_id=$1', [
            ctx.recordId,
          ])
        ).rows[0];
        assert(
          tx.sameClaim(claim, s.account.id, ctx.sender, ctx.recipients, ctx.kind) &&
            claim.expires_at.getTime() > clock(),
          'claim_unavailable',
          'The one-time package claim expired or changed. Start a fresh record.',
          409,
        );
        const refs = [];
        for (const item of bundle.setup.packages) {
          const row = (
            await tx.query('SELECT * FROM g28.protected_key_packages WHERE id=$1', [item.id])
          ).rows[0];
          assert(
            row &&
              row.record_id === ctx.recordId &&
              row.device_id === item.device &&
              row.state === 'reserved' &&
              row.lease_until.getTime() > clock() &&
              row.package_sha256 === item.hash,
            'claim_unavailable',
            'A one-time key package no longer matches.',
            409,
          );
          refs.push(row.package_ref);
        }
        assert(
          canonical([...welcomeRefs].sort()) === canonical(refs.sort()),
          'welcome_recipients',
          'The Welcome includes a different recipient set.',
          400,
        );
        let own;
        try {
          own = await protectedMlsKeyPackageMetadata(
            bundle.setup.creatorPackage,
            { device: sender.id, signatureKey: sender.mlsSigningKey },
            clock(),
          );
        } catch {
          assert(
            false,
            'invalid_creator_package',
            'The creator key package failed validation.',
            400,
          );
        }
        assert(
          !(
            await tx.query(
              'SELECT 1 FROM g28.protected_key_packages WHERE init_sha256=$1 OR package_sha256=$2',
              [own.initSha256, own.packageSha256],
            )
          ).rowCount,
          'key_package_reused',
          'The creator initialization key was already used.',
          409,
        );
        await tx.query(
          "INSERT INTO g28.protected_key_packages(id,device_id,identity_id,generation,package_sha256,init_sha256,package_ref,wire,expires_at,state,record_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'used',$10)",
          [
            randomUUID(),
            sender.id,
            sender.identityId,
            sender.generation,
            own.packageSha256,
            own.initSha256,
            own.keyPackageRef,
            bundle.setup.creatorPackage,
            own.expiresAt,
            ctx.recordId,
          ],
        );
        await tx.query(
          "UPDATE g28.protected_key_packages SET state='used',lease_until=NULL WHERE record_id=$1 AND state='reserved'",
          [ctx.recordId],
        );
      }
      assert(
        !old ||
          old.messages.reduce((n, m) => n + m.ciphertext.length, 0) + message.ciphertext.length <=
            2000000,
        'protected_record_full',
        'This encrypted thread is full. Start a fresh verified group.',
        409,
      );
      const doc = old || {
        id: ctx.recordId,
        protocol: MLS_PROFILE,
        authorId: s.account.id,
        kind: ctx.kind,
        participants: [...new Set(devices.map((d) => d.accountId))],
        status: 'received',
        messages: [],
        memberKeys: devices
          .map((d) => ({
            device: d.id,
            accountId: d.accountId,
            identityId: d.identityId,
            generation: d.generation,
            publicKey: d.publicKey,
            fingerprint: d.fingerprint,
            signatureKey: d.mlsSigningKey,
          }))
          .sort((a, b) => a.device.localeCompare(b.device)),
        leafOrder,
        retainUntil: new Date(clock() + 90 * 86400000).toISOString(),
      };
      doc.messages.push(message);
      await tx.storeRecord(doc);
      await tx.audit(s.account.id, doc.id, 'mls_ciphertext_committed', digest(message));
      return { id: doc.id, version: doc.messages.length, status: doc.status };
    });
  });
  app.post(prefix + '/records/:id/export', async (req) => {
    intake();
    const s = await writeSession(req),
      b = exactKeys(req.body, ['deviceId', 'version', 'signature', 'confirm']);
    assert(
      b.confirm === 'export exact encrypted record',
      'export_confirmation',
      'Confirm this exact encrypted export.',
    );
    return store.withProtectedMls(async (tx) => {
      const { doc, device } = await readable(tx, req.params.id, s, b.deviceId);
      assert(
        doc.messages.length === b.version,
        'protected_version_conflict',
        'Reload the exact current record.',
        409,
      );
      const proof = {
        action: 'export',
        profile: MLS_PROFILE,
        recordId: doc.id,
        version: b.version,
        deviceId: b.deviceId,
        generation: device.generation,
      };
      assert(
        await verifyProtected(proof, b.signature, (await publicProtectedKey(device.publicKey)).key),
        'export_proof',
        'Unlock the original authorized device before exporting.',
        403,
      );
      await tx.audit(s.account.id, doc.id, 'mls_ciphertext_export', digest(proof));
      return { record: doc, identities: await histories(tx, doc) };
    });
  });
  app.post(prefix + '/records/:id/status', async (req) => {
    intake();
    const s = await writeSession(req),
      b = exactKeys(req.body, ['deviceId', 'status', 'version']);
    assert(
      ['acknowledged', 'escalated', 'closed'].includes(b.status),
      'invalid_status',
      'Choose a supported status.',
    );
    return store.withProtectedMls(async (tx) => {
      const { doc } = await readable(tx, req.params.id, s, b.deviceId);
      await staff(s, doc.kind === 'correction' ? 'content:edit' : 'safety:review', tx);
      assert(
        doc.messages.length === b.version,
        'protected_version_conflict',
        'Reload the current record.',
        409,
      );
      doc.status = b.status;
      await tx.storeRecord(doc);
      await tx.audit(s.account.id, doc.id, 'mls_status_' + b.status);
      return { status: doc.status };
    });
  });
  app.post(prefix + '/records/:id/hold', async (req) => {
    setup();
    const s = await writeSession(req),
      b = exactKeys(req.body, ['held', 'evidenceDigest']);
    assert(
      typeof b.held === 'boolean' && /^[a-f0-9]{64}$/.test(b.evidenceDigest),
      'hold_evidence',
      'Record the actual hold decision evidence.',
    );
    return store.withProtectedMls(async (tx) => {
      await staff(s, 'security:manage', tx);
      assert(
        (
          await tx.query(
            'UPDATE g28.protected_records SET legal_hold=$2 WHERE id=$1 RETURNING id',
            [protectedId(req.params.id), b.held],
          )
        ).rowCount,
        'not_found',
        'Record not found.',
        404,
      );
      await tx.audit(
        s.account.id,
        req.params.id,
        b.held ? 'mls_hold_set' : 'mls_hold_released',
        b.evidenceDigest,
      );
      return { held: b.held };
    });
  });
  async function purge(tx, actor) {
    await tx.query(
      "UPDATE g28.protected_key_packages SET state='expired',wire=NULL,lease_until=NULL WHERE state IN ('available','reserved') AND (expires_at<=$1 OR (state='reserved' AND lease_until<=$1))",
      [new Date(clock())],
    );
    const rows = (
      await tx.query(
        'DELETE FROM g28.protected_records WHERE retain_until<=$1 AND NOT legal_hold RETURNING id',
        [new Date(clock())],
      )
    ).rows;
    for (const row of rows) await tx.audit(actor, row.id, 'mls_expired_ciphertext_deleted');
    return rows.length;
  }
  app.post(prefix + '/lifecycle/purge', async (req) => {
    setup();
    const s = await writeSession(req);
    exactKeys(req.body, []);
    return store.withProtectedMls(async (tx) => {
      await staff(s, 'security:manage', tx);
      return { deleted: await purge(tx, s.account.id) };
    });
  });
  let timer,
    running = Promise.resolve();
  app.addHook('onReady', async () => {
    if (config.protectedMls && (config.protectedContent || config.protectedSetup)) {
      await store.withProtectedMls((tx) => purge(tx, 'retention-worker'));
      timer = setInterval(() => {
        running = running
          .then(() => store.withProtectedMls((tx) => purge(tx, 'retention-worker')))
          .catch(() => console.error(JSON.stringify({ event: 'protected_retention_failed' })));
      }, 3600000);
      timer.unref();
    }
  });
  app.addHook('onClose', async () => {
    clearInterval(timer);
    await running;
  });
}
