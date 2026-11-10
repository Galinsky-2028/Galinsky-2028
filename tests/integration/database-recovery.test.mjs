import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {mkdtemp,readFile,writeFile,readdir,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import pg from 'pg';
import {backupDatabase,restoreDatabase} from '../../scripts/database-recovery.mjs';
import {newProtectedKey,unlockProtectedKey,encryptProtected,decryptProtected,publicProtectedKey,PROTECTED_PROFILE} from '../../packages/core/protected-crypto.mjs';
import {sealFinanceIdentity,openFinanceIdentity,sealFinanceEvidence,openFinanceEvidence} from '../../packages/core/treasury-private.mjs';
const base=process.env.TEST_DATABASE_URL;
test('complete encrypted PostgreSQL recovery is authenticated, isolated, atomic and preserves durable application records',{skip:!base},async()=>{
 assert(['localhost','127.0.0.1'].includes(new URL(base).hostname),'Synthetic drill uses local Postgres only.');
 const suffix=randomBytes(5).toString('hex'),sourceName='g28_backup_'+suffix,targetName='g28_restore_'+suffix;
 const admin=new pg.Pool({connectionString:base}),sourceURL=new URL(base),targetURL=new URL(base);
 sourceURL.pathname='/'+sourceName;targetURL.pathname='/'+targetName;
 const dir=await mkdtemp(join(tmpdir(),'g28-synthetic-drill-')),file=join(dir,'backup.g28'),bad=join(dir,'tampered.g28'),key=randomBytes(32).toString('base64');
 let source,target;
 try{
  await admin.query('CREATE DATABASE '+sourceName);await admin.query('CREATE DATABASE '+targetName);
  source=new pg.Pool({connectionString:sourceURL.href});target=new pg.Pool({connectionString:targetURL.href});
  for(const name of (await readdir('db/migrations')).filter(x=>x.endsWith('.sql')).sort())await source.query(await readFile('db/migrations/'+name,'utf8'));
  await source.query("INSERT INTO g28.content_revisions(id,content_key,revision,state,record,author_subject) VALUES($2,'synthetic.recovery',1,'draft',$1,'synthetic-operator')",[{fixture:'synthetic-recovery-only'},randomUUID()]);
  const jobId=randomUUID();await source.query("INSERT INTO g28.outbox(id,kind,subject_key,payload_envelope,status,lease_until,lease_token,attempts) VALUES($1,'account_login','synthetic','synthetic-envelope','leased',now()-interval '1 minute',$2,1)",[jobId,randomUUID()]);
  const before=await source.query('SELECT version FROM g28.schema_migrations ORDER BY version');
  const recipient=randomUUID(),device=randomUUID(),protectedId=randomUUID(),pair=await newProtectedKey(recipient,'synthetic separate recovery passphrase'),privateKey=await unlockProtectedKey(pair.privateKey,'synthetic separate recovery passphrase'),info=await publicProtectedKey(pair.publicKey);
  await source.query("INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'synthetic',now(),'synthetic')",[recipient,'f'.repeat(64)]);
  await source.query("INSERT INTO g28.protected_devices(id,account_id,fingerprint,public_key,label,state,generation) VALUES($1,$2,$3,$4,'Synthetic recovery device','enrolled',1)",[device,recipient,info.fingerprint,pair.publicKey]);
  const secondDevice=randomUUID(),secondPair=await newProtectedKey(recipient,'synthetic separate recovery passphrase'),secondInfo=await publicProtectedKey(secondPair.publicKey);await source.query("INSERT INTO g28.protected_devices(id,account_id,fingerprint,public_key,label,state,generation) VALUES($1,$2,$3,$4,'Synthetic second recovery device','enrolled',1)",[secondDevice,recipient,secondInfo.fingerprint,secondPair.publicKey]);
  const protectedMessage=await encryptProtected({profile:PROTECTED_PROFILE,recordId:protectedId,sequence:1,kind:'incident',sender:device,recipients:[device,secondDevice].sort(),generation:1},{text:'PROTECTED_RECOVERY_CANARY'},[pair,secondPair],privateKey);
  await source.query("INSERT INTO g28.protected_records(id,author_id,participants,document,version,retain_until,legal_hold) VALUES($1,$2,$3,$4,1,now()+interval '90 days',true)",[protectedId,recipient,[recipient],{messages:[protectedMessage]}]);
  const financeKey=randomBytes(32).toString('base64'),donorId=randomUUID(),evidenceId=randomUUID(),identity={name:'FINANCE_RECOVERY_CANARY'},document={text:'PRIVATE_EVIDENCE_RECOVERY_CANARY'};
  await source.query("INSERT INTO g28.treasury_donors(id,encrypted_envelope,evidence_digest,version) VALUES($1,$2,$3,1)",[donorId,sealFinanceIdentity(donorId,1,identity,financeKey),'a'.repeat(64)]);
  await source.query("INSERT INTO g28.treasury_evidence(id,digest,byte_count,encrypted_envelope,created_by) VALUES($1,$2,42,$3,'synthetic')",[evidenceId,'a'.repeat(64),sealFinanceEvidence(evidenceId,document,financeKey)]);
  const result=await backupDatabase({url:sourceURL.href,key,file});assert(result.bytes>1000);assert(result.durationMs>=0);
  assert.equal((await stat(file)).mode&0o777,0o600);
  const bytes=await readFile(file);assert(!bytes.includes('synthetic-recovery-only'));assert(!bytes.includes(sourceName));assert(!bytes.includes(Buffer.from(key)));
  await assert.rejects(backupDatabase({url:sourceURL.href,key,file}),e=>e.code==='EEXIST');
  await assert.rejects(restoreDatabase({url:sourceURL.href,key,file,confirmation:sourceName}));
  await assert.rejects(restoreDatabase({url:targetURL.href,key,file,confirmation:'wrong'}));
  await assert.rejects(restoreDatabase({url:targetURL.href,key:randomBytes(32).toString('base64'),file,confirmation:targetName}));
  const corrupt=Buffer.from(bytes);corrupt[corrupt.length-32]^=1;await writeFile(bad,corrupt);
  await assert.rejects(restoreDatabase({url:targetURL.href,key,file:bad,confirmation:targetName}));
  assert.equal((await target.query("SELECT to_regclass('g28.accounts') AS found")).rows[0].found,null);
  const restored=await restoreDatabase({url:targetURL.href,key,file,confirmation:targetName});
  assert(restored.durationMs>=0);assert.equal(restored.productionRecoveryProven,false);
  assert.deepEqual((await target.query('SELECT version FROM g28.schema_migrations ORDER BY version')).rows,before.rows);
  assert.equal((await target.query("SELECT record FROM g28.content_revisions WHERE content_key='synthetic.recovery'")).rows[0].record.fixture,'synthetic-recovery-only');
  const recoveredProtected=(await target.query('SELECT document,legal_hold FROM g28.protected_records WHERE id=$1',[protectedId])).rows[0];
  assert(recoveredProtected.legal_hold);assert(!JSON.stringify(recoveredProtected).includes('PROTECTED_RECOVERY_CANARY'));
  assert.equal((await decryptProtected(recoveredProtected.document.messages[0],privateKey,pair)).text,'PROTECTED_RECOVERY_CANARY');
  assert.equal((await target.query('SELECT generation,fingerprint FROM g28.protected_devices WHERE id=$1',[device])).rows[0].fingerprint,info.fingerprint);
  const donorEnvelope=(await target.query('SELECT encrypted_envelope FROM g28.treasury_donors WHERE id=$1',[donorId])).rows[0].encrypted_envelope;
  assert(!donorEnvelope.includes(identity.name));assert.deepEqual(openFinanceIdentity(donorId,1,donorEnvelope,financeKey),identity);
  assert.throws(()=>openFinanceIdentity(donorId,1,donorEnvelope,key));
  const evidenceEnvelope=(await target.query('SELECT encrypted_envelope FROM g28.treasury_evidence WHERE id=$1',[evidenceId])).rows[0].encrypted_envelope;
  assert(!evidenceEnvelope.includes(document.text));assert.deepEqual(openFinanceEvidence(evidenceId,evidenceEnvelope,financeKey),document);
  for(const name of ['accounts','outbox','activity_modules','financial_provider_events','staff_security','encrypted_records']){
   assert((await target.query('SELECT to_regclass($1) AS found',['g28.'+name])).rows[0].found,name+' survives complete restore');
  }
  const {PostgresStore}=await import('../../apps/api/src/postgres-store.mjs');const recoveredStore=new PostgresStore(target);
  const job=await recoveredStore.claimJob();assert.equal(job.id,jobId);assert.equal(job.attempts,2);await recoveredStore.finishJob(job);
  assert.equal((await target.query('SELECT status,payload_envelope FROM g28.outbox WHERE id=$1',[jobId])).rows[0].status,'sent');
  assert.equal(await recoveredStore.claimJob(),null);
  const acl=await target.query("SELECT EXISTS (SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='g28.ingest_page_events(uuid,text,jsonb)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE') AS permitted");assert.equal(acl.rows[0].permitted,false,'Restoration preserves function revocations');
  await assert.rejects(restoreDatabase({url:targetURL.href,key,file,confirmation:targetName}));
  // Emit aggregate, synthetic-only measured evidence into the retained CI log.
  console.log(JSON.stringify({event:'synthetic_recovery_drill',backupMs:result.durationMs,restoreMs:restored.durationMs,bytes:result.bytes,schemaVersions:before.rowCount,productionRecoveryProven:false}));
 }finally{
  await source?.end();await target?.end();
  await admin.query('DROP DATABASE IF EXISTS '+sourceName);await admin.query('DROP DATABASE IF EXISTS '+targetName);await admin.end();await rm(dir,{recursive:true,force:true});
 }
});
