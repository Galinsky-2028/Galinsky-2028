import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';import {randomUUID} from 'node:crypto';
import {databasePool,PostgresStore} from '../../apps/api/src/postgres-store.mjs';
const url=process.env.TEST_DATABASE_URL;
test('Postgres persistence, atomic verification, leasing and deletion',{skip:!url},async t=>{
 assert(['127.0.0.1','localhost'].includes(new URL(url).hostname),'Tests must use an isolated local database, never the assigned Neon production database.');
 const pool=databasePool(url),store=new PostgresStore(pool);await pool.query(await readFile('db/migrations/001_foundation.sql','utf8'));await pool.query(await readFile('db/migrations/002_self_reported_task_progress.sql','utf8'));await pool.query(await readFile('db/migrations/003_material_reading.sql','utf8'));await pool.query(await readFile('db/migrations/004_fundraising_reconciliation.sql','utf8'));await pool.query(await readFile('db/migrations/005_volunteer_role_preferences.sql','utf8'));await pool.query(await readFile('db/migrations/006_account_bookmarks.sql','utf8'));await pool.query(await readFile('db/migrations/014_volunteer_coordination.sql','utf8'));await pool.query(await readFile('db/migrations/018_mail_delivery.sql','utf8'));await pool.query('TRUNCATE g28.accounts,g28.login_requests,g28.outbox,g28.rate_buckets,g28.materials CASCADE');
 try{
  await t.test('database readiness',async()=>assert(await store.healthy()));
  await t.test('durable login request and encrypted outbox',async()=>{await store.requestLogin({hash:'test-token',binding:'binding',emailKey:'fixture-email-key',deliveryEnvelope:'fixture-encrypted-envelope',marketing:false,termsVersion:'test',expires:Date.now()+100000},{id:randomUUID(),kind:'account_login',envelope:'fixture-outbox-envelope'});const row=await pool.query('SELECT count(*) FROM g28.outbox');assert.equal(Number(row.rows[0].count),1);});
  let account;
  await t.test('concurrent consume has exactly one winner',async()=>{const consume=i=>store.consumeLogin('test-token','binding',{hash:'session-'+i,csrf:'csrf',expires:Date.now()+100000});const results=await Promise.all([consume(1),consume(2)]);assert.equal(results.filter(Boolean).length,1);account=results.find(Boolean);});
  await t.test('concurrent job leases cannot duplicate delivery',async()=>{const results=await Promise.all([store.claimJob(),store.claimJob()]);assert.equal(results.filter(Boolean).length,1);const job=results.find(Boolean);await store.finishJob(job);const row=await pool.query('SELECT status,payload_envelope FROM g28.outbox WHERE id=$1',[job.id]);assert.equal(row.rows[0].status,'sent');assert.equal(row.rows[0].payload_envelope,'');});
  await t.test('outbox retention never deletes an undelivered or leased job even after a month',async()=>{
   const ids=Array.from({length:5},()=>randomUUID());
   const values=[
    {state:'queued',days:35},
    {state:'leased',days:35},
    {state:'sent',days:35},
    {state:'dead',days:35},
    {state:'sent',days:2}
   ];
   for(let i=0;i<values.length;i++){
    const v=values[i];
    await pool.query(`INSERT INTO g28.outbox(id,kind,subject_key,payload_envelope,status,created_at)
     VALUES($1,'account_login','retention-fixture','fixture-envelope',$2,$3)`,
     [ids[i],v.state,new Date(Date.now()-v.days*86400000)]);
   }
   await store.cleanup();
   const actual=await pool.query('SELECT id,status FROM g28.outbox WHERE id=ANY($1::uuid[])',[ids]);
   const remaining=new Map(actual.rows.map(r=>[r.id,r.status]));
   assert.equal(remaining.get(ids[0]),'queued');
   assert.equal(remaining.get(ids[1]),'leased');
   assert.equal(remaining.has(ids[2]),false);
   assert.equal(remaining.has(ids[3]),false);
   assert.equal(remaining.get(ids[4]),'sent');
   // Repeating the operation is safe and must not drain pending work.
   await store.cleanup();
   const again=await pool.query('SELECT id FROM g28.outbox WHERE id=ANY($1::uuid[])',[ids]);
   assert.equal(again.rowCount,3);
   await pool.query('DELETE FROM g28.outbox WHERE id=ANY($1::uuid[])',[ids]);
  });
  await t.test('newest activity revision controls read-only publication status',async()=>{
   const id='readiness-fixture';
   const published={id,revision:1,status:'published',activity:'Fixture training',jurisdiction:'CT',election:'2028 General'};
   await pool.query('INSERT INTO g28.activity_modules(id,revision,record) VALUES($1,$2,$3) ON CONFLICT(id,revision) DO UPDATE SET record=EXCLUDED.record',[id,1,published]);
   let records=await store.listPublishedActivityModules();
   assert(records.some(r=>r.id===id&&r.revision===1));
   const unpublished={...published,revision:2,status:'draft'};
   await pool.query('INSERT INTO g28.activity_modules(id,revision,record) VALUES($1,$2,$3) ON CONFLICT(id,revision) DO UPDATE SET record=EXCLUDED.record',[id,2,unpublished]);
   records=await store.listPublishedActivityModules();
   assert(!records.some(r=>r.id===id));
   await pool.query('DELETE FROM g28.activity_modules WHERE id=$1',[id]);
  });
  await t.test('rate buckets are shared and atomic',async()=>{const r=await Promise.all(Array.from({length:8},()=>store.rate('fixture-rate',4,Date.now()+10000)));assert.equal(r.filter(Boolean).length,4);});
  await t.test('task checklist is idempotent, per-account and cascades on closure',async()=>{
   await store.setTaskCompletion(account.id,'choose-role',true);
   await store.setTaskCompletion(account.id,'choose-role',true);
   assert.deepEqual(await store.listTaskCompletion(account.id),['choose-role']);
   await store.setTaskCompletion(account.id,'read-principle',true);
   assert.deepEqual(await store.listTaskCompletion(account.id),['choose-role','read-principle']);
   await store.setTaskCompletion(account.id,'read-principle',false);
   assert.deepEqual(await store.listTaskCompletion(account.id),['choose-role']);
  });
  await t.test('role preferences are truly persisted, updated and never grant activity authorization',async()=>{
   assert.equal(await store.getRolePreferences(account.id),null);
   await store.setRolePreferences(account.id,{roleId:'ballot',minutes:120,willingToTrain:true});
   assert.deepEqual(await store.getRolePreferences(account.id),{roleId:'ballot',minutes:120,willingToTrain:true});
   await store.setRolePreferences(account.id,{roleId:'skills',minutes:30,willingToTrain:false});
   assert.deepEqual(await store.getRolePreferences(account.id),{roleId:'skills',minutes:30,willingToTrain:false});
   const forbidden=await pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema='g28' AND table_name='activity_permissions'");assert.equal(forbidden.rowCount,0);
  });
  await t.test('account bookmarks persist and can be removed without another account',async()=>{
    assert.deepEqual(await store.listBookmarks(account.id),[]);
    await store.setBookmark(account.id,'test-guide',true);
    await store.setBookmark(account.id,'test-guide',true);
    assert.deepEqual(await store.listBookmarks(account.id),['test-guide']);
    assert.deepEqual(await store.listBookmarks(randomUUID()),[]);
    await store.setBookmark(account.id,'another-guide',true);
    assert.deepEqual(await store.listBookmarks(account.id),['another-guide','test-guide']);
    await store.setBookmark(account.id,'another-guide',false);
    assert.deepEqual(await store.listBookmarks(account.id),['test-guide']);
   });
  await t.test('reading acknowledgments persist and bind exact publication revisions',async()=>{
   const ack={revision:1,contentSha256:'a'.repeat(64)};
   await store.setMaterialAck(account.id,'test-guide',ack);
   assert.deepEqual(await store.readMaterialAck(account.id,'test-guide'),{materialId:'test-guide',...ack});
   const revised={revision:2,contentSha256:'b'.repeat(64)};
   await store.setMaterialAck(account.id,'test-guide',revised);
   assert.deepEqual(await store.readMaterialAck(account.id,'test-guide'),{materialId:'test-guide',...revised});
   await store.setMaterialAck(account.id,'test-guide',null);
   assert.equal(await store.readMaterialAck(account.id,'test-guide'),null);
   await store.setMaterialAck(account.id,'test-guide',ack);
  });
  await t.test('financial provider events have safe fixed-key uniqueness and no donor card fields',async()=>{
   const reference='synthetic-'+randomUUID();
   await pool.query("INSERT INTO g28.financial_provider_events(provider,event_id,payment_id,event_digest,event_kind,amount_cents,occurred_at) VALUES($1,$2,$3,$4,$5,$6,now())",['synthetic',reference,'pay-a','a'.repeat(64),'captured',2500]);
   await assert.rejects(()=>pool.query("INSERT INTO g28.financial_provider_events(provider,event_id,payment_id,event_digest,event_kind,amount_cents,occurred_at) VALUES($1,$2,$3,$4,$5,$6,now())",['synthetic',reference,'pay-a','a'.repeat(64),'captured',2500]));
   const cols=await pool.query("SELECT column_name FROM information_schema.columns WHERE table_schema='g28' AND table_name='financial_provider_events'");
   const names=cols.rows.map(r=>r.column_name);
   for(const prohibited of ['card_number','email','donor_name','billing_address','cvv'])assert(!names.includes(prohibited));
   const result=await pool.query("SELECT amount_cents FROM g28.financial_provider_events WHERE provider='synthetic' AND event_id=$1",[reference]);
   assert.equal(Number(result.rows[0].amount_cents),2500);
  });
  await t.test('account activity snapshot excludes identity secrets and role preferences persist',async()=>{
    const data=await store.accountActivityExport(account.id);
    assert.equal(data.account.id,account.id);
    assert.deepEqual(data.rolePreferences,{roleId:'skills',minutes:30,willingToTrain:false});
    assert.deepEqual(data.completedTasks,['choose-role']);
    assert.deepEqual(data.bookmarkedMaterials,['test-guide']);
    assert.equal(data.materialAcknowledgments.length,1);
    assert.equal(data.materialAcknowledgments[0].materialId,'test-guide');
    assert(!JSON.stringify(data).includes('fixture-encrypted-envelope'));
    assert(!JSON.stringify(data).includes('fixture-email-key'));
    assert.equal(await store.accountActivityExport(randomUUID()),null);
  });
  await t.test('revoke all sessions does not close the account',async()=>{
    await store.revokeAllSessions(account.id);
    assert.equal(await store.session('session-1'),null);
    assert.equal(await store.session('session-2'),null);
    assert(await store.accountActivityExport(account.id));
  });
  await t.test('account closure cascades to all sessions, checklist and reading history',async()=>{await store.closeAccount(account.id);assert.equal(await store.session('session-1'),null);assert.equal(await store.session('session-2'),null);assert.deepEqual(await store.listTaskCompletion(account.id),[]);assert.equal(await store.readMaterialAck(account.id,'test-guide'),null);assert.equal(await store.getRolePreferences(account.id),null);assert.deepEqual(await store.listBookmarks(account.id),[]);});
 }finally{await store.close();}
});
