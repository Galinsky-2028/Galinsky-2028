import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {PostgresStore,databasePool} from '../../apps/api/src/postgres-store.mjs';
import {createApp} from '../../apps/api/src/app.mjs';
import {randomToken,tokenHash} from '../../packages/core/auth.mjs';
const url=process.env.TEST_DATABASE_URL;
test('real task HTTP/SQL enforces capacity, current training, tool opt-out, publication revocation, provenance and scoped review',{skip:!url},async()=>{
 assert(['localhost','127.0.0.1'].includes(new URL(url).hostname));
 const pool=databasePool(url),store=new PostgresStore(pool),now=Date.now(),origin='http://localhost:4322',prefix='fixture-'+randomUUID().slice(0,8),accounts=[],keys=[];
 const config={staffIdentity:true,adminLoginReady:true,adminOwnerEmailKey:tokenHash(prefix+'-owner'),portalOrigin:origin,publicOrigin:'http://localhost:4321'};
 const app=createApp({store,config,clock:()=>now});
 async function actor(role='volunteer'){
  const id=randomUUID(),key=role==='owner'?config.adminOwnerEmailKey:tokenHash(prefix+'-'+id),token=randomToken(),hash=tokenHash(token),csrf=randomToken();accounts.push(id);keys.push(key);
  await pool.query("INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'synthetic',now(),'synthetic')",[id,key]);
  await pool.query('INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',[hash,id,csrf,new Date(now+86400000)]);
  if(!['owner','volunteer'].includes(role))await store.setAdminGrant(id,key,role,'Synthetic staff');
  if(role!=='volunteer')await store.withStaffSecurity(id,s=>{s.credentials=[{id:'fixture'}];s.sessions={[hash]:{credentialId:'fixture',expires:now+900000}};});
  return {id,hash,headers:{origin,cookie:'g28-local='+token,'content-type':'application/json','x-csrf-token':csrf}};
 }
 const post=(path,who,payload)=>app.inject({method:'POST',url:path,headers:who.headers,payload});
 const taskId=prefix+'-task',guideId=prefix+'-guide',trainingId=prefix+'-training',toolId=prefix+'-tool',moduleId=prefix+'-module';
 const end=new Date(now+3600000).toISOString();
 try{
  for(const name of ['001_foundation','009_treasurer_vault_admin_rbac','016_staff_passkeys','017_staff_roles','019_operations'])await pool.query(await readFile('db/migrations/'+name+'.sql','utf8'));
  const owner=await actor('owner'),first=await actor(),second=await actor(),captain=await actor('captain'),finance=await actor('treasurer');
  const material={id:guideId,title:'Synthetic guide',body:'Synthetic safe practice only',revision:1,status:'published',audience:'volunteer'};
  await pool.query("INSERT INTO g28.materials(id,revision,status,audience,record) VALUES($1,1,'published','volunteer',$2)",[guideId,material]);
  let task={id:taskId,title:'Synthetic practice task',active:true,roleId:'network',description:'Read the synthetic guide.',stopConditions:'Stop if guidance is paused.',estimatedMinutes:15,capacity:1,startsAt:new Date(now-1000).toISOString(),endsAt:end,materialId:guideId,materialRevision:1,training:[],restricted:false,moduleId:null,moduleRevision:null,toolId:null,reviewers:[]};
  assert.equal((await post('/api/staff/operations/task',finance,{definition:task,expected:null})).statusCode,403);
  const save=await post('/api/staff/operations/task',owner,{definition:task,expected:null});assert.equal(save.statusCode,200,save.body);task=save.json().definition;
  const results=await Promise.all([first,second].map(w=>post('/api/operations/tasks/'+taskId+'/claim',w,{revision:1})));
  assert.equal(results.filter(r=>r.statusCode===200).length,1);assert.equal(results.filter(r=>r.statusCode===409).length,1);
  const participant=results[0].statusCode===200?first:second;
  const bad=await post('/api/operations/tasks/'+taskId+'/report',participant,{revision:1,report:{count:1,minutes:2,feedback:'completed',supporterName:'Must not store'}});assert.equal(bad.statusCode,400);
  const report=await post('/api/operations/tasks/'+taskId+'/report',participant,{revision:1,report:{count:2,minutes:15,feedback:'completed'}});assert.equal(report.statusCode,200,report.body);assert.equal(report.json().claim.report.provenance,'self_reported');
  assert.equal((await post('/api/staff/operations/tasks/'+taskId+'/review',captain,{accountId:participant.id,revision:1,decision:'verified'})).statusCode,403);
  const reviewed=await post('/api/staff/operations/tasks/'+taskId+'/review',owner,{accountId:participant.id,revision:1,decision:'verified'});assert.equal(reviewed.statusCode,200,reviewed.body);
  assert.equal((await post('/api/staff/operations/task',owner,{definition:task,expected:null})).statusCode,400,'Returned metadata cannot be submitted as editable fields');
  const training={id:trainingId,title:'Synthetic training',active:true,materialId:guideId,materialRevision:1};
  assert.equal((await post('/api/staff/operations/training',owner,{definition:training,expected:null})).statusCode,200);
  const evidence={accountId:first.id,revision:1,expiresAt:end,evidenceDigest:'a'.repeat(64),revoked:false};
  assert.equal((await post('/api/staff/operations/training/'+trainingId+'/attest',owner,{...evidence,accountId:owner.id})).statusCode,403);
  const tool={id:toolId,title:'Synthetic practice tool',active:true,url:'https://example.org/practice',purpose:'Synthetic controlled practice only',reviewDigest:'b'.repeat(64),reviewUntil:end,capabilityMode:'manual-link',suppressionMode:'provider-managed',health:{state:'available',checkedAt:new Date(now).toISOString(),validUntil:end,evidenceDigest:'c'.repeat(64)}};
  assert.equal((await post('/api/staff/operations/tool',owner,{definition:tool,expected:null})).statusCode,200);
  const module={id:moduleId,revision:1,status:'published',jurisdiction:'CT',election:'2028',activity:'Synthetic practice',validFrom:new Date(now-1000).toISOString(),validUntil:end,training:[trainingId],approvedTools:[toolId],sources:[{url:'https://example.org/official',checkedAt:new Date(now).toISOString()}],verifiers:[{id:randomUUID(),revision:1,evidence:'review-one'},{id:randomUUID(),revision:1,evidence:'review-two'}],approval:{by:randomUUID(),revision:1}};
  await pool.query('INSERT INTO g28.activity_modules(id,revision,record) VALUES($1,1,$2)',[moduleId,module]);
  const {revision,...fields}=task;const restricted={...fields,id:prefix+'-restricted',training:[trainingId],restricted:true,moduleId,moduleRevision:1,toolId};
  assert.equal((await post('/api/staff/operations/task',owner,{definition:restricted,expected:null})).statusCode,200);
  const action=(name,payload={})=>post('/api/operations/tasks/'+restricted.id+'/'+name,first,{revision:1,...payload});
  assert.equal((await action('claim')).statusCode,403,'Self assertion cannot substitute for verified training');
  assert.equal((await post('/api/staff/operations/training/'+trainingId+'/attest',owner,evidence)).statusCode,200);
  const claim=await action('claim');assert.equal(claim.statusCode,200,claim.body);
  assert.equal((await action('handoff')).statusCode,403);
  assert.equal((await post('/api/operations/tools/'+toolId+'/consent',first,{revision:1,allowed:true})).statusCode,200);
  assert.equal((await action('handoff')).json().url,'https://example.org/practice');
  await pool.query("UPDATE g28.operation_definitions SET record=jsonb_set(record,'{health,state}','\"suppression_failed\"'::jsonb) WHERE kind='tool' AND id=$1",[toolId]);assert.equal((await action('handoff')).statusCode,403,'Known failed suppression pauses existing claims');await pool.query("UPDATE g28.operation_definitions SET record=jsonb_set(record,'{health,state}','\"available\"'::jsonb) WHERE kind='tool' AND id=$1",[toolId]);
  await post('/api/operations/tools/'+toolId+'/consent',first,{revision:1,allowed:false});assert.equal((await action('handoff')).statusCode,403);
  await pool.query("INSERT INTO g28.activity_modules(id,revision,record) VALUES($1,2,$2)",[moduleId,{...module,revision:2,status:'revoked'}]);
  assert.equal((await action('report',{report:{count:1,minutes:2,feedback:'completed'}})).statusCode,403);
  assert.equal((await action('release')).statusCode,200,'Leaving remains available after revocation');
  await store.withStaffSecurity(owner.id,s=>{s.sessions={};});assert.equal((await post('/api/staff/operations/tool',owner,{definition:tool,expected:1})).statusCode,403);
  const records=await pool.query('SELECT record FROM g28.operation_claims WHERE task_id=$1',[taskId]);assert(!JSON.stringify(records.rows).includes('Must not store'));assert.equal(records.rowCount,1);
 }finally{
  await app.close();await pool.query('DELETE FROM g28.operation_definitions WHERE id LIKE $1',[prefix+'%']);await pool.query('DELETE FROM g28.operation_claims WHERE task_id LIKE $1',[prefix+'%']);await pool.query('DELETE FROM g28.activity_modules WHERE id=$1',[moduleId]);await pool.query('DELETE FROM g28.materials WHERE id=$1',[guideId]);await pool.query('DELETE FROM g28.admin_grants WHERE email_key=ANY($1::text[])',[keys]);await pool.query('DELETE FROM g28.treasury_audit WHERE actor_id=ANY($1::uuid[])',[accounts]);await pool.query('DELETE FROM g28.accounts WHERE id=ANY($1::uuid[])',[accounts]);await pool.query('DELETE FROM g28.audit_events WHERE actor_subject=ANY($1::text[])',[accounts]);await store.close();
 }
});
