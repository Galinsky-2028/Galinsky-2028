import {postgresProtected} from './protected-store.mjs';
import {postgresTreasuryExport} from './treasury-export.mjs';
import {postgresOperations} from './operations-store.mjs';
import {prepareAccountNotice} from './mail-notices.mjs';
import {queueNoticeSQL,postgresMail} from './mail-store.mjs';
import {postgresStaffSecurity} from './staff-security.mjs';
import {postgresCoordination,removeAccountCoordination,ownCoordination} from './coordination-store.mjs';
import {postgresActivityReview} from './activity-review-store.mjs';
import {postgresHelp} from './help-store.mjs';
import pg from 'pg';
import {randomUUID} from 'node:crypto';
import {assessOperations} from '../../../packages/core/ops-health.mjs';
export function databasePool(connectionString){
 const u=new URL(connectionString);const local=['localhost','127.0.0.1','[::1]'].includes(u.hostname);
 // Keep TLS verification explicit; connection-string sslmode must not silently weaken it.
 for(const p of ['sslmode','sslcert','sslkey','sslrootcert'])u.searchParams.delete(p);
 return new pg.Pool({connectionString:u.toString(),ssl:local?false:{rejectUnauthorized:true},max:5,connectionTimeoutMillis:8000,idleTimeoutMillis:10000,statement_timeout:10000,application_name:'galinsky-2028'});
}
export class PostgresStore{
 constructor(pool){this.pool=pool;}
 async healthy(){await this.pool.query('SELECT 1 FROM g28.schema_migrations LIMIT 1');return true;}
 async operationalStatus(){
  // Only grouped counts and schema versions leave PostgreSQL. Never select
  // addresses, tokens, mail bodies, source IPs or payment events.
  const [versions,accounts,materials,jobs]=await Promise.all([
   this.pool.query('SELECT version FROM g28.schema_migrations ORDER BY version'),
   this.pool.query('SELECT count(*)::integer AS value FROM g28.accounts'),
   this.pool.query("SELECT count(*)::integer AS value FROM g28.materials WHERE status='published' AND audience='volunteer'"),
   this.pool.query(`SELECT count(*) FILTER (WHERE status='queued')::integer AS queued,
     count(*) FILTER (WHERE status='leased')::integer AS leased,
     count(*) FILTER (WHERE status='dead')::integer AS dead,
     COALESCE(GREATEST(0,EXTRACT(EPOCH FROM now()-min(created_at) FILTER (WHERE status='queued'))),0)::integer AS oldest_queued
     FROM g28.outbox`)
  ]);
  const row=jobs.rows[0];
  return {...assessOperations({versions:versions.rows.map(r=>r.version),
   accounts:accounts.rows[0].value,materials:materials.rows[0].value,
   queued:row.queued,leased:row.leased,dead:row.dead,
   oldestQueuedSeconds:row.oldest_queued}),source:'live_database_aggregate'};
 }

 async rate(key,limit,until){const q=await this.pool.query(`INSERT INTO g28.rate_buckets(key,count,expires_at) VALUES($1,1,$2) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN g28.rate_buckets.expires_at<now() THEN 1 ELSE g28.rate_buckets.count+1 END, expires_at=CASE WHEN g28.rate_buckets.expires_at<now() THEN EXCLUDED.expires_at ELSE g28.rate_buckets.expires_at END RETURNING count`,[key,new Date(until)]);return q.rows[0].count<=limit;}
 async requestLogin(r,job){const c=await this.pool.connect();try{await c.query('BEGIN');await c.query(`INSERT INTO g28.login_requests(token_hash,binding_hash,email_key,delivery_envelope,marketing_consent,terms_version,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,[r.hash,r.binding,r.emailKey,r.deliveryEnvelope,r.marketing,r.termsVersion,new Date(r.expires)]);await c.query('INSERT INTO g28.outbox(id,kind,subject_key,payload_envelope) VALUES($1,$2,$3,$4)',[job.id,job.kind,r.emailKey,job.envelope]);await c.query('COMMIT');}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
 async consumeLogin(hash,binding,s,now=Date.now(),noticeConfig=null){
  const c=await this.pool.connect();try{await c.query('BEGIN');const found=await c.query('DELETE FROM g28.login_requests WHERE token_hash=$1 AND binding_hash=$2 AND expires_at>$3 RETURNING *',[hash,binding,new Date(now)]);if(!found.rowCount){await c.query('ROLLBACK');return null;}
  const r=found.rows[0];const accounts=await c.query(`INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,marketing_consent,terms_version) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(email_key) DO UPDATE SET verified_at=g28.accounts.verified_at RETURNING *`,[randomUUID(),r.email_key,r.delivery_envelope,new Date(now),r.marketing_consent,r.terms_version]);const a=accounts.rows[0];await c.query('INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',[s.hash,a.id,s.csrf,new Date(s.expires)]);if(noticeConfig)await queueNoticeSQL(c,a.id,'welcome-v1',prepareAccountNotice(a,noticeConfig,'account_welcome',now));await c.query('COMMIT');return {id:a.id,verified:true,marketing:a.marketing_consent,emailKey:a.email_key};
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 async session(hash,now=Date.now()){const q=await this.pool.query('SELECT s.token_hash,s.csrf_token,s.expires_at,a.id,a.marketing_consent,a.email_key FROM g28.sessions s JOIN g28.accounts a ON a.id=s.account_id WHERE s.token_hash=$1 AND s.expires_at>$2',[hash,new Date(now)]);const r=q.rows[0];return r?{hash:r.token_hash,csrf:r.csrf_token,expires:+r.expires_at,account:{id:r.id,verified:true,marketing:r.marketing_consent,emailKey:r.email_key}}:null;}
 async invitedAdminRole(key){
  const q=await this.pool.query('SELECT role FROM g28.admin_grants WHERE email_key=$1 AND revoked_at IS NULL',[key]);
  return q.rows[0]?.role||null;
 }
 async adminRole(account,ownerEmailKey){
  if(ownerEmailKey&&account.emailKey===ownerEmailKey)return 'owner';
  return this.invitedAdminRole(account.emailKey);
 }
 async adminGrants(){
  const q=await this.pool.query('SELECT email_key,role,display_label,created_at FROM g28.admin_grants WHERE revoked_at IS NULL ORDER BY created_at');
  return q.rows.map(r=>({reference:r.email_key.slice(0,12),role:r.role,label:r.display_label,createdAt:r.created_at.toISOString()}));
 }
 async setAdminGrant(actorId,key,role,label){
  const c=await this.pool.connect();
  try{
   await c.query('BEGIN');
   await c.query('INSERT INTO g28.admin_grants(email_key,role,display_label,granted_by,revoked_at) VALUES($1,$2,$3,$4,NULL) ON CONFLICT(email_key) DO UPDATE SET role=EXCLUDED.role,display_label=EXCLUDED.display_label,granted_by=EXCLUDED.granted_by,revoked_at=NULL',[key,role,label,actorId]);
   await c.query('INSERT INTO g28.treasury_audit(id,actor_id,action,subject) VALUES($1,$2,$3,$4)',[randomUUID(),actorId,'grant_set',key.slice(0,12)]);
   await c.query('COMMIT');
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 async revokeAdminGrant(actorId,reference){
  const c=await this.pool.connect();
  try{
   await c.query('BEGIN');
   const r=await c.query('UPDATE g28.admin_grants SET revoked_at=now() WHERE left(email_key,12)=$1 AND revoked_at IS NULL RETURNING email_key',[reference]);
   if(r.rowCount!==1){await c.query('ROLLBACK');return false;}
   // Existing sessions are immediately read-only/unauthorized because role is rechecked on each request.
   await c.query('INSERT INTO g28.treasury_audit(id,actor_id,action,subject) VALUES($1,$2,$3,$4)',[randomUUID(),actorId,'grant_revoke',reference]);
   await c.query('COMMIT');return true;
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 async treasuryMetadata(){
  const q=await this.pool.query('SELECT slot,masked_label,updated_at FROM g28.treasury_secrets ORDER BY slot');
  return q.rows.map(r=>({slot:r.slot,maskedLabel:r.masked_label,updatedAt:r.updated_at.toISOString()}));
 }
 async saveTreasurySecret(actorId,slot,envelope,maskedLabel){
  const c=await this.pool.connect();
  try{
   await c.query('BEGIN');
   await c.query('INSERT INTO g28.treasury_secrets(slot,encrypted_envelope,masked_label,last_updated_by) VALUES($1,$2,$3,$4) ON CONFLICT(slot) DO UPDATE SET encrypted_envelope=EXCLUDED.encrypted_envelope,masked_label=EXCLUDED.masked_label,last_updated_by=EXCLUDED.last_updated_by,updated_at=now()',[slot,envelope,maskedLabel,actorId]);
   await c.query('INSERT INTO g28.treasury_audit(id,actor_id,action,subject) VALUES($1,$2,$3,$4)',[randomUUID(),actorId,'vault_set',slot]);
   await c.query('COMMIT');
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 async logout(hash){await this.pool.query('DELETE FROM g28.sessions WHERE token_hash=$1',[hash]);}
 async consent(id,marketing){await this.pool.query('UPDATE g28.accounts SET marketing_consent=$1 WHERE id=$2',[marketing,id]);}
 async closeAccount(id){const c=await this.pool.connect();try{await c.query('BEGIN');const a=(await c.query('SELECT email_key FROM g28.accounts WHERE id=$1 FOR UPDATE',[id])).rows[0];if(a){const teams=await c.query('SELECT id,record FROM g28.coordination_teams ORDER BY id FOR UPDATE');for(const row of teams.rows){removeAccountCoordination(row.record,id,a.email_key);await c.query('UPDATE g28.coordination_teams SET record=$2,updated_at=now() WHERE id=$1',[row.id,row.record]);}}await c.query('DELETE FROM g28.login_requests WHERE email_key=(SELECT email_key FROM g28.accounts WHERE id=$1)',[id]);await c.query('DELETE FROM g28.outbox WHERE subject_key=(SELECT email_key FROM g28.accounts WHERE id=$1)',[id]);await c.query('DELETE FROM g28.accounts WHERE id=$1',[id]);await c.query('COMMIT');}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}}
 async accountActivityExport(id){
  const c=await this.pool.connect();
  try{
   await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
   const account=await c.query(
    'SELECT id,verified_at,created_at,marketing_consent,terms_version FROM g28.accounts WHERE id=$1',[id]);
   if(account.rowCount===0){await c.query('COMMIT');return null;}
   const prefs=await c.query('SELECT role_id,available_minutes,willing_to_train FROM g28.volunteer_role_preferences WHERE account_id=$1',[id]);
   const tasks=await c.query('SELECT task_id FROM g28.task_progress WHERE account_id=$1 ORDER BY task_id',[id]);
   const reads=await c.query('SELECT material_id,revision,content_sha256 FROM g28.material_reading WHERE account_id=$1 ORDER BY material_id',[id]);
   const bookmarked=await c.query('SELECT material_id FROM g28.account_bookmarks WHERE account_id=$1 ORDER BY material_id',[id]);
   const coordination=await c.query('SELECT record FROM g28.coordination_teams');
   await c.query('COMMIT');
   const a=account.rows[0],p=prefs.rows[0];
   return {
    coordination:ownCoordination(coordination.rows.map(r=>r.record),id),
    account:{id:a.id,verifiedAt:a.verified_at.toISOString(),createdAt:a.created_at.toISOString(),
     marketingConsent:a.marketing_consent,termsVersion:a.terms_version},
    rolePreferences:p?{roleId:p.role_id,minutes:p.available_minutes,willingToTrain:p.willing_to_train}:null,
    completedTasks:tasks.rows.map(x=>x.task_id),
    bookmarkedMaterials:bookmarked.rows.map(x=>x.material_id),
    materialAcknowledgments:reads.rows.map(x=>({materialId:x.material_id,revision:x.revision,contentSha256:x.content_sha256}))
   };
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
 async revokeAllSessions(id){
  await this.pool.query('DELETE FROM g28.sessions WHERE account_id=$1',[id]);
 }
 async listTaskCompletion(accountId){
  const q=await this.pool.query('SELECT task_id FROM g28.task_progress WHERE account_id=$1 ORDER BY task_id',[accountId]);
  return q.rows.map(r=>r.task_id);
 }
 async setTaskCompletion(accountId,taskId,completed){
  if(completed)await this.pool.query(`INSERT INTO g28.task_progress(account_id,task_id) VALUES($1,$2) ON CONFLICT(account_id,task_id) DO UPDATE SET completed_at=now()`,[accountId,taskId]);
  else await this.pool.query('DELETE FROM g28.task_progress WHERE account_id=$1 AND task_id=$2',[accountId,taskId]);
 }
 async listBookmarks(accountId){
  const r=await this.pool.query('SELECT material_id FROM g28.account_bookmarks WHERE account_id=$1 ORDER BY material_id',[accountId]);
  return r.rows.map(x=>x.material_id);
 }
 async setBookmark(accountId,materialId,saved){
  if(saved)await this.pool.query(
   'INSERT INTO g28.account_bookmarks(account_id,material_id) VALUES($1,$2) ON CONFLICT(account_id,material_id) DO NOTHING',
   [accountId,materialId]);
  else await this.pool.query(
   'DELETE FROM g28.account_bookmarks WHERE account_id=$1 AND material_id=$2',[accountId,materialId]);
 }
 async getRolePreferences(accountId){
  const q=await this.pool.query('SELECT role_id,available_minutes,willing_to_train FROM g28.volunteer_role_preferences WHERE account_id=$1',[accountId]);
  const r=q.rows[0];
  return r?{roleId:r.role_id,minutes:r.available_minutes,willingToTrain:r.willing_to_train}:null;
 }
 async setRolePreferences(accountId,preferences){
  await this.pool.query(`INSERT INTO g28.volunteer_role_preferences(account_id,role_id,available_minutes,willing_to_train)
   VALUES($1,$2,$3,$4)
   ON CONFLICT(account_id) DO UPDATE SET role_id=EXCLUDED.role_id,available_minutes=EXCLUDED.available_minutes,
   willing_to_train=EXCLUDED.willing_to_train,updated_at=now()`,
   [accountId,preferences.roleId,preferences.minutes,preferences.willingToTrain]);
 }
 async readMaterialAck(accountId,materialId){
  const q=await this.pool.query('SELECT material_id,revision,content_sha256 FROM g28.material_reading WHERE account_id=$1 AND material_id=$2',[accountId,materialId]);
  return q.rows[0]?{materialId:q.rows[0].material_id,revision:q.rows[0].revision,contentSha256:q.rows[0].content_sha256}:null;
 }
 async setMaterialAck(accountId,materialId,record){
  if(record)await this.pool.query(`INSERT INTO g28.material_reading(account_id,material_id,revision,content_sha256) VALUES($1,$2,$3,$4) ON CONFLICT(account_id,material_id) DO UPDATE SET revision=EXCLUDED.revision,content_sha256=EXCLUDED.content_sha256,acknowledged_at=now()`,[accountId,materialId,record.revision,record.contentSha256]);
  else await this.pool.query('DELETE FROM g28.material_reading WHERE account_id=$1 AND material_id=$2',[accountId,materialId]);
 }
 async listMaterials(){const q=await this.pool.query("SELECT record FROM g28.materials WHERE status='published' AND audience='volunteer'");return q.rows.map(r=>r.record);}
 async listPublishedActivityModules(){
  // A newer draft, expired/revoked publication or missing approval must not
  // resurrect an older published version as current fieldwork guidance.
  const q=await this.pool.query(`SELECT id,revision,record FROM (
   SELECT DISTINCT ON (id) id,revision,record FROM g28.activity_modules
   ORDER BY id,revision DESC
  ) latest WHERE record->>'status'='published' ORDER BY id LIMIT 50`);
  return q.rows.map(r=>({...r.record,id:r.id,revision:r.revision}));
 }
 async claimJob(){const lease=randomUUID();const q=await this.pool.query(`WITH next AS (SELECT id FROM g28.outbox WHERE (status='queued' AND available_at<=now()) OR (status='leased' AND lease_until<now()) ORDER BY available_at FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE g28.outbox o SET status='leased',attempts=attempts+1,lease_until=now()+interval '2 minutes',lease_token=$1 FROM next WHERE o.id=next.id RETURNING o.*`,[lease]);return q.rows[0]||null;}
 async finishJob(job,error=null){if(!error){await this.pool.query("UPDATE g28.outbox SET status='sent',payload_envelope='',lease_until=NULL,lease_token=NULL WHERE id=$1 AND lease_token=$2",[job.id,job.lease_token]);return;}const dead=job.attempts>=8||['expired','invalid_destination','provider_rejected','suppressed'].includes(error);await this.pool.query("UPDATE g28.outbox SET status=$1,last_error_code=$2,payload_envelope=CASE WHEN $1='dead' THEN '' ELSE payload_envelope END,available_at=now()+($3 * interval '1 second'),lease_until=NULL,lease_token=NULL WHERE id=$4 AND lease_token=$5",[dead?'dead':'queued',error,Math.min(3600,2**job.attempts*15),job.id,job.lease_token]);}
 // Only terminal email jobs are eligible for retention cleanup. A delayed login
 // can expire, but its queued/leased job must still be claimed and marked dead
 // by the worker; age alone is never proof that delivery completed.
 async cleanup(){
  // Mixed-schema staging and isolated legacy tests may not have migration 021 yet.
  if((await this.pool.query("SELECT to_regclass('g28.volunteer_passkey_challenges') AS name")).rows[0].name)
   await this.pool.query('DELETE FROM g28.volunteer_passkey_challenges WHERE expires_at<now()');
  await this.pool.query('DELETE FROM g28.login_requests WHERE expires_at<now()');
  await this.pool.query('DELETE FROM g28.sessions WHERE expires_at<now()');
  await this.pool.query('DELETE FROM g28.rate_buckets WHERE expires_at<now()');
  await this.pool.query("DELETE FROM g28.mail_events WHERE received_at<now()-interval '90 days'");
  // A bounded, restart-safe purge avoids lengthy web-worker transactions and
  // never deletes queued or leased jobs during an outage or slow retry.
  await this.pool.query(`DELETE FROM g28.outbox WHERE id IN (
   SELECT id FROM g28.outbox
   WHERE status IN ('sent','dead') AND created_at<now()-interval '30 days'
   ORDER BY created_at,id LIMIT 250 FOR UPDATE SKIP LOCKED
  )`);
 }
 async close(){await this.pool.end();}
}

Object.assign(PostgresStore.prototype, postgresCoordination, postgresHelp, postgresActivityReview);

Object.assign(PostgresStore.prototype, postgresStaffSecurity);

Object.assign(PostgresStore.prototype, postgresMail);

Object.assign(PostgresStore.prototype,postgresOperations);

Object.assign(PostgresStore.prototype,postgresTreasuryExport);
Object.assign(PostgresStore.prototype,postgresProtected);
