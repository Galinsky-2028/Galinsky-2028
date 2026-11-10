import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {readFile,readdir} from 'node:fs/promises';
import pg from 'pg';
import {runtimeRoleStatements} from '../../scripts/runtime-role-permissions.mjs';
const url=process.env.TEST_DATABASE_URL;
test('SQL-created application identities allow scoped DML and deny account leakage, DDL, role administration and future-table grants',{skip:!url},async()=>{
 assert(['localhost','127.0.0.1'].includes(new URL(url).hostname));
 const pool=new pg.Pool({connectionString:url}),c=await pool.connect(),suffix=randomBytes(5).toString('hex');
 const profiles=['stripe','portal','portal_preview','volunteer'],roles=profiles.map(p=>'g28_'+(['portal_preview','volunteer'].includes(p)?'portal':p)+'_runtime_'+suffix+(p==='portal_preview'?'_preview':p==='volunteer'?'_volunteer':''));
 try{
  for(const name of (await readdir('db/migrations')).filter(f=>f.endsWith('.sql')).sort())await c.query(await readFile('db/migrations/'+name,'utf8'));
  await c.query('BEGIN');
  // The production profile pins neondb; this synthetic database may use another name.
  for(const [index,profile]of profiles.entries())for(const sql of runtimeRoleStatements({role:roles[index],password:randomBytes(36).toString('base64url'),profile}))await c.query(sql.replace('ON DATABASE neondb','ON DATABASE "'+new URL(url).pathname.slice(1)+'"'));
  for(const role of roles){
   const r=(await c.query('SELECT rolcreatedb,rolcreaterole,rolsuper,rolinherit,rolbypassrls FROM pg_roles WHERE rolname=$1',[role])).rows[0];assert(Object.values(r).every(v=>v===false));
   assert.equal((await c.query('SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=$1)',[role])).rowCount,0);
  }
  async function as(role,sql,denied=false){await c.query('SAVEPOINT permission_probe');await c.query('SET LOCAL ROLE "'+role+'"');try{await c.query(sql);assert(!denied,'Unexpected permission: '+sql);}catch(e){if(!denied)throw e;assert(['42501'].includes(e.code),e.message);}finally{await c.query('ROLLBACK TO SAVEPOINT permission_probe');}}
  await as(roles[0],'SELECT session_id FROM g28.stripe_checkout_intents LIMIT 0');
  await as(roles[0],"INSERT INTO g28.financial_provider_events(provider,event_id,payment_id,event_digest,event_kind,amount_cents,occurred_at) VALUES('synthetic-role','synthetic-event','synthetic-payment',repeat('a',64),'captured',1,now()) ON CONFLICT(provider,event_id) DO NOTHING");
  await as(roles[0],"INSERT INTO g28.stripe_checkout_intents(client_reference,session_id,election,amount_cents,livemode) VALUES('attempt_"+'a'.repeat(32)+"','cs_test_syntheticpermission','primary',1,false) ON CONFLICT(client_reference) DO NOTHING");
  await as(roles[1],"INSERT INTO g28.audit_events(id,actor_subject,action,object_id,result) VALUES(gen_random_uuid(),'synthetic','permission_probe','synthetic','success')");
  await as(roles[1],"DELETE FROM g28.audit_events WHERE false",true);
  await as(roles[1],"UPDATE g28.financial_provider_events SET amount_cents=1 WHERE false",true);
  for(const table of ['accounts','sessions','staff_security','treasury_secrets','financial_provider_events'])await as(roles[0],'SELECT * FROM g28.'+table+' LIMIT 0',true);
  await as(roles[1],'SELECT * FROM g28.accounts LIMIT 0');await as(roles[1],'SELECT * FROM g28.campaign_public_releases LIMIT 0');
  for(const role of roles){await as(role,'CREATE TABLE g28.synthetic_unauthorized(id int)',true);await as(role,'ALTER TABLE g28.accounts ADD COLUMN synthetic_unauthorized text',true);await as(role,'TRUNCATE g28.accounts CASCADE',true);await as(role,'CREATE ROLE g28_synthetic_unauthorized',true);}
  await as(roles[0],'SELECT * FROM g28.schema_migrations',true);
  await as(roles[1],'SELECT version FROM g28.schema_migrations LIMIT 1');
  await as(roles[2],'SELECT version FROM g28.schema_migrations LIMIT 1');
  await as(roles[2],'SELECT * FROM g28.campaign_public_releases LIMIT 0');
  for(const table of ['accounts','sessions','staff_security','treasury_secrets','financial_provider_events','content_revisions','outbox'])await as(roles[2],'SELECT * FROM g28.'+table+' LIMIT 0',true);
  await as(roles[2],"INSERT INTO g28.rate_buckets(key,count,expires_at) VALUES('synthetic',1,now())",true);
  await as(roles[3],'SELECT * FROM g28.accounts LIMIT 0');
  await as(roles[3],'SELECT * FROM g28.volunteer_passkeys LIMIT 0');
  await as(roles[3],"UPDATE g28.volunteer_passkeys SET counter=counter WHERE false");
  for(const table of ['admin_grants','staff_security','treasury_secrets','financial_provider_events','content_revisions'])await as(roles[3],'SELECT * FROM g28.'+table+' LIMIT 0',true);
  await as(roles[3],"INSERT INTO g28.admin_grants(email_key,role,display_label,granted_by) VALUES('synthetic','owner','synthetic',gen_random_uuid())",true);
  await as(roles[3],"UPDATE g28.materials SET revision=revision WHERE false",true);
  await as(roles[1],"DELETE FROM g28.schema_migrations WHERE false",true);
  await c.query('CREATE TABLE g28.synthetic_future_permission(id int)');
  for(const role of roles)await as(role,'SELECT * FROM g28.synthetic_future_permission',true);
  await c.query('ROLLBACK');
 }finally{await c.query('ROLLBACK');c.release();await pool.end();}
});
