import { randomUUID } from 'node:crypto';
import { assert } from '../../../packages/core/validation.mjs';
import { canonical } from '../../../packages/core/protected-crypto.mjs';
import {
  initialProtectedIdentity,
  applyProtectedIdentityEvent,
  identityStateHash,
  protectedIdentityKeyClaims,
} from '../../../packages/core/protected-identity.mjs';
const identityColumns =
  'id,account_id AS "accountId",current,root_fingerprint AS "rootFingerprint",initial_state AS "initialState",state,state_hash AS "stateHash",sequence';
const deviceColumns =
  'd.id,d.account_id AS "accountId",d.identity_id AS "identityId",d.fingerprint,d.public_key AS "publicKey",d.mls_signing_key AS "mlsSigningKey",d.label,d.state,d.scope,d.approved_by AS "approvedBy",d.generation,d.quarantined';
const identity = async (c, id) =>
  (await c.query('SELECT ' + identityColumns + ' FROM g28.protected_identities WHERE id=$1', [id]))
    .rows[0] || null;
const current = async (c, account) =>
  (
    await c.query(
      'SELECT ' +
        identityColumns +
        ' FROM g28.protected_identities WHERE account_id=$1 AND current',
      [account],
    )
  ).rows[0] || null;
const device = async (c, id) =>
  (await c.query('SELECT ' + deviceColumns + ' FROM g28.protected_devices d WHERE d.id=$1', [id]))
    .rows[0] || null;
const audit = (c, actor, id, action, digest = null) =>
  c.query(
    'INSERT INTO g28.protected_lifecycle_events(id,actor_id,record_id,action,evidence_digest) VALUES($1,$2,$3,$4,$5)',
    [randomUUID(), actor, id, action, digest],
  );
export const postgresProtectedMls = {
  async withProtectedMls(fn) {
    const c = await this.pool.connect();
    try {
      await c.query('BEGIN');
      await c.query("SELECT pg_advisory_xact_lock(hashtext('g28-protected-directory'))");
      await c.query('LOCK TABLE g28.admin_grants IN SHARE MODE');
      // Authorization reads reuse this client: waiting directory transactions
      // must not exhaust the pool while its lock holder requests another client.
      const scoped = Object.create(this);
      scoped.pool = c;
      const tx = {
        store: scoped,
        query: (sql, values) => c.query(sql, values),
        identity: (id) => identity(c, id),
        currentIdentity: (account) => current(c, account),
        device: (id) => device(c, id),
        audit: (actor, id, action, digest) => audit(c, actor, id, action, digest),
        history: async (id, through) => {
          const row = await identity(c, id);
          if (!row) return null;
          const events = (
            await c.query(
              'SELECT document,root_signature AS "rootSignature",device_signature AS "deviceSignature",state_hash AS "stateHash" FROM g28.protected_identity_events WHERE identity_id=$1 AND sequence<=$2 ORDER BY sequence',
              [id, through ?? row.sequence],
            )
          ).rows;
          return { initialState: row.initialState, events };
        },
        record: async (id) => {
          const row = (
            await c.query(
              'SELECT document,retain_until,legal_hold FROM g28.protected_records WHERE id=$1',
              [id],
            )
          ).rows[0];
          return row
            ? {
                ...row.document,
                retainUntil: row.retain_until.toISOString(),
                legalHold: row.legal_hold,
              }
            : null;
        },
        storeRecord: (doc) =>
          c.query(
            'INSERT INTO g28.protected_records(id,author_id,participants,document,version,retain_until) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET document=EXCLUDED.document,version=EXCLUDED.version,updated_at=now()',
            [doc.id, doc.authorId, doc.participants, doc, doc.messages.length, doc.retainUntil],
          ),
        commitIdentity: async ({
          accountId,
          identityId,
          rootPublicKey,
          event,
          rootSignature,
          deviceSignature,
          label,
          replace,
        }) => {
          // A lost HTTP acknowledgement must not apply a signed transition twice.
          // A matching event ID is sufficient only with identical authenticated bytes
          // and the same still-current identity; retired roots never reactivate.
          const replay = (
            await c.query(
              'SELECT identity_id,document,root_signature,device_signature FROM g28.protected_identity_events WHERE id=$1',
              [event.id],
            )
          ).rows[0];
          const old = await current(c, accountId);
          let initial, state;
          if (replay) {
            assert(
              old?.id === identityId &&
                old.accountId === accountId &&
                replay.identity_id === identityId &&
                canonical(replay.document) === canonical(event) &&
                replay.root_signature === rootSignature &&
                replay.device_signature === (deviceSignature || null),
              'identity_replay_conflict',
              'This transition reference is already used or its identity is archived.',
              409,
            );
            assert(
              (await identityStateHash(old.state)) === old.stateHash,
              'identity_state_corrupt',
              'Identity state could not be authenticated.',
              409,
            );
            return {
              state: old.state,
              stateHash: old.stateHash,
              device: await device(c, event.subject.id),
              duplicate: true,
            };
          }
          if (old?.id === identityId) {
            initial = old.initialState;
            state = old.state;
            assert(
              (await identityStateHash(state)) === old.stateHash,
              'identity_state_corrupt',
              'Identity state could not be authenticated.',
              409,
            );
          } else {
            assert(
              !(await identity(c, identityId)),
              'identity_retired',
              'An archived identity cannot be reactivated. Start a fresh unverified identity.',
              409,
            );
            assert(
              !old || replace === true,
              'identity_replacement_confirmation',
              'Use the existing root device or explicitly start a new unverified identity.',
              409,
            );
            initial = await initialProtectedIdentity({ accountId, identityId, rootPublicKey });
            state = initial;
          }
          assert(
            event.accountId === accountId && event.identityId === identityId,
            'identity_account',
            'The identity proof does not belong to this account.',
            403,
          );
          const next = await applyProtectedIdentityEvent(
              state,
              event,
              rootSignature,
              deviceSignature,
            ),
            stateHash = await identityStateHash(next),
            claims = await protectedIdentityKeyClaims(next);
          for (const claim of claims) {
            const previous = (
              await c.query(
                'SELECT identity_id,subject_id,generation,kind FROM g28.protected_identity_keys WHERE key_id=$1',
                [claim.keyId],
              )
            ).rows[0];
            assert(
              !previous ||
                (previous.identity_id === identityId &&
                  previous.subject_id === claim.subjectId &&
                  previous.generation === claim.generation &&
                  previous.kind === claim.kind),
              'retired_identity_key',
              'A current or retired key cannot be reused.',
              409,
            );
          }
          if (old && old.id !== identityId) {
            await c.query('UPDATE g28.protected_identities SET current=false WHERE id=$1', [
              old.id,
            ]);
            await c.query(
              'UPDATE g28.protected_devices SET quarantined=true WHERE identity_id=$1',
              [old.id],
            );
            await c.query(
              "UPDATE g28.protected_key_packages SET state='expired',wire=NULL,lease_until=NULL WHERE identity_id=$1 AND state<>'used'",
              [old.id],
            );
            await audit(c, accountId, old.id, 'unverified_identity_replacement_started');
          }
          await c.query(
            'INSERT INTO g28.protected_identities(id,account_id,current,root_fingerprint,initial_state,state,state_hash,sequence) VALUES($1,$2,true,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET state=EXCLUDED.state,state_hash=EXCLUDED.state_hash,sequence=EXCLUDED.sequence,updated_at=now()',
            [identityId, accountId, next.rootFingerprint, initial, next, stateHash, next.sequence],
          );
          for (const claim of claims)
            await c.query(
              'INSERT INTO g28.protected_identity_keys(key_id,identity_id,subject_id,generation,kind) VALUES($1,$2,$3,$4,$5) ON CONFLICT(key_id) DO NOTHING',
              [claim.keyId, identityId, claim.subjectId, claim.generation, claim.kind],
            );
          await c.query(
            'INSERT INTO g28.protected_identity_events(id,identity_id,sequence,previous_state_hash,document,root_signature,device_signature,state_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
            [
              event.id,
              identityId,
              event.sequence,
              event.previousStateHash,
              event,
              rootSignature,
              deviceSignature || null,
              stateHash,
            ],
          );
          const subject = next.devices.find((d) => d.id === event.subject.id),
            existing = await device(c, subject.id);
          assert(
            !existing || existing.identityId === identityId,
            'device_identity_conflict',
            'This device reference belongs to another identity.',
            409,
          );
          if (event.action === 'revoke') {
            await c.query(
              "UPDATE g28.protected_devices SET state='revoked',scope=NULL,approved_by=NULL,quarantined=true WHERE id=$1 AND identity_id=$2",
              [subject.id, identityId],
            );
          } else {
            await c.query(
              "INSERT INTO g28.protected_devices(id,account_id,identity_id,fingerprint,public_key,mls_signing_key,label,state,scope,approved_by,generation,quarantined) VALUES($1,$2,$3,$4,$5,$6,$7,'enrolled',NULL,NULL,$8,false) ON CONFLICT(id) DO UPDATE SET fingerprint=EXCLUDED.fingerprint,public_key=EXCLUDED.public_key,mls_signing_key=EXCLUDED.mls_signing_key,label=EXCLUDED.label,state='enrolled',scope=NULL,approved_by=NULL,generation=EXCLUDED.generation,quarantined=false",
              [
                subject.id,
                accountId,
                identityId,
                subject.fingerprint,
                subject.publicKey,
                subject.mlsSigningKey,
                label,
                subject.generation,
              ],
            );
          }
          if (event.action !== 'enroll')
            await c.query(
              "UPDATE g28.protected_key_packages SET state='expired',wire=NULL,lease_until=NULL WHERE device_id=$1 AND state<>'used'",
              [subject.id],
            );
          await audit(c, accountId, identityId, 'signed_identity_' + event.action, stateHash);
          return { state: next, stateHash, device: await device(c, subject.id) };
        },
        directory: async (accountId, kind, after, review = false) => {
          const rows = (
            await c.query(
              'SELECT ' +
                deviceColumns +
                ',i.root_fingerprint AS "rootFingerprint",i.state_hash AS "identityHash",i.sequence AS "identitySequence" FROM g28.protected_devices d JOIN g28.protected_identities i ON i.id=d.identity_id AND i.current WHERE d.id>$3::uuid AND (d.account_id=$1 OR (d.state=\'approved\' AND d.scope=$2 AND NOT d.quarantined) OR $4::boolean) ORDER BY d.id LIMIT 101',
              [accountId, kind, after || '00000000-0000-0000-0000-000000000000', review],
            )
          ).rows;
          return { devices: rows.slice(0, 100), next: rows.length > 100 ? rows[99].id : null };
        },
        sameClaim: (row, actor, sender, recipients, kind) =>
          row &&
          row.account_id === actor &&
          row.sender_device_id === sender &&
          row.kind === kind &&
          canonical([...row.recipient_devices].sort()) === canonical([...recipients].sort()),
      };
      const result = await fn(tx);
      await c.query('COMMIT');
      return result;
    } catch (error) {
      await c.query('ROLLBACK');
      throw error;
    } finally {
      c.release();
    }
  },
};
