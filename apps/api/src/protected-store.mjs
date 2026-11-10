import {randomUUID} from 'node:crypto';
import {staffCan} from '../../../packages/core/staff-permissions.mjs';
// A directory lock serializes trust changes and message commits. Ciphertext,
// attachments and key-generation metadata share one transactional backup unit.
export const postgresProtected={
 async protectedRecipientAuthorized(accountId,scope,ownerKey){
  const account=(await this.pool.query('SELECT id,email_key AS "emailKey" FROM g28.accounts WHERE id=$1',[accountId])).rows[0];
  return Boolean(account&&staffCan(await this.adminRole(account,ownerKey),scope==='correction'?'content:edit':'safety:review'));
 },
 async withProtected(fn){
  const c=await this.pool.connect();try{await c.query('BEGIN');await c.query("SELECT pg_advisory_xact_lock(hashtext('g28-protected-directory'))");await c.query('LOCK TABLE g28.admin_grants IN SHARE MODE');
   const devices=(await c.query('SELECT id,account_id AS "accountId",fingerprint,public_key AS "publicKey",label,state,scope,approved_by AS "approvedBy",generation FROM g28.protected_devices ORDER BY id LIMIT 2001')).rows;
   const result=await fn({devices,
    saveDevice:async d=>{await c.query('INSERT INTO g28.protected_devices(id,account_id,fingerprint,public_key,label,state,scope,approved_by,generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO UPDATE SET state=EXCLUDED.state,scope=EXCLUDED.scope,approved_by=EXCLUDED.approved_by,generation=EXCLUDED.generation',[d.id,d.accountId,d.fingerprint,d.publicKey,d.label,d.state,d.scope,d.approvedBy,d.generation]);},
    get:async id=>{const r=(await c.query('SELECT document,retain_until,legal_hold FROM g28.protected_records WHERE id=$1',[id])).rows[0];return r?{...r.document,retainUntil:r.retain_until.toISOString(),legalHold:r.legal_hold}:null;},
    used:async id=>(await c.query('SELECT 1 FROM g28.protected_lifecycle_events WHERE record_id=$1 LIMIT 1',[id])).rowCount>0,
    list:async accountId=>(await c.query('SELECT id,version,updated_at AS "updatedAt" FROM g28.protected_records WHERE $1=ANY(participants) AND (retain_until>now() OR legal_hold) ORDER BY updated_at DESC LIMIT 100',[accountId])).rows,
    save:async doc=>{await c.query('INSERT INTO g28.protected_records(id,author_id,participants,document,version,retain_until) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET document=EXCLUDED.document,version=EXCLUDED.version,updated_at=now()',[doc.id,doc.authorId,doc.participants,doc,doc.messages.length,doc.retainUntil]);},
    audit:async(actor,id,action,digest=null)=>{await c.query('INSERT INTO g28.protected_lifecycle_events(id,actor_id,record_id,action,evidence_digest) VALUES($1,$2,$3,$4,$5)',[randomUUID(),actor,id,action,digest]);},
    hold:async(id,held)=>{return (await c.query('UPDATE g28.protected_records SET legal_hold=$2 WHERE id=$1 RETURNING id',[id,held])).rowCount===1;},
    purge:async now=>{const q=await c.query('DELETE FROM g28.protected_records WHERE retain_until<=$1 AND legal_hold=false RETURNING id',[new Date(now)]);return q.rows.map(r=>r.id);}
   });await c.query('COMMIT');return result;
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
};
