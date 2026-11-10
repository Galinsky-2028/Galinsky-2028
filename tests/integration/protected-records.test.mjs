import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {PostgresStore,databasePool} from '../../apps/api/src/postgres-store.mjs';
import {createApp} from '../../apps/api/src/app.mjs';
import {randomToken,tokenHash} from '../../packages/core/auth.mjs';
import {newProtectedKey,publicProtectedKey,unlockProtectedKey,signProtected,encryptProtected,decryptProtected,PROTECTED_PROFILE} from '../../packages/core/protected-crypto.mjs';
const url=process.env.TEST_DATABASE_URL;
test('protected PostgreSQL/HTTP lifecycle binds current role, exact devices, revisions, legal holds, exports and irreversible revocation',{skip:!url},async()=>{
 assert(['localhost','127.0.0.1'].includes(new URL(url).hostname));
 const pool=databasePool(url),store=new PostgresStore(pool),now=Date.now(),origin='http://localhost:4322',accounts=[],keys=[],recordIds=[],deviceIds=[];
 const config={protectedContent:true,staffIdentity:true,adminLoginReady:true,adminOwnerEmailKey:tokenHash(randomUUID()),portalOrigin:origin,publicOrigin:'http://localhost:4321'},app=createApp({store,config,clock:()=>now});
 const send=(who,path,payload)=>app.inject({method:payload===undefined?'GET':'POST',url:'/api/protected/'+path,headers:who.headers,...(payload===undefined?{}:{payload})});
 async function actor(role){const id=randomUUID(),emailKey=role==='owner'?config.adminOwnerEmailKey:tokenHash(id),token=randomToken(),hash=tokenHash(token),csrf=randomToken();accounts.push(id);keys.push(emailKey);await pool.query("INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'synthetic',now(),'synthetic')",[id,emailKey]);await pool.query('INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',[hash,id,csrf,new Date(now+86400000)]);if(!['owner','volunteer'].includes(role))await pool.query("INSERT INTO g28.admin_grants(email_key,role,display_label,granted_by) VALUES($1,$2,'Synthetic staff',$3)",[emailKey,role,accounts[0]]);await store.withStaffSecurity(id,s=>{s.credentials=[{id:'fixture'}];s.sessions={[hash]:{credentialId:'fixture',expires:now+900000}};});return {id,emailKey,hash,headers:{origin,cookie:'g28-local='+token,'content-type':'application/json','x-csrf-token':csrf}};}
 async function device(who){const pair=await newProtectedKey(who.id,'synthetic key recovery passphrase'),key=await unlockProtectedKey(pair.privateKey,'synthetic key recovery passphrase'),info=await publicProtectedKey(pair.publicKey),id=randomUUID();deviceIds.push(id);const response=await send(who,'devices',{id,publicKey:pair.publicKey,label:'Synthetic device',signature:await signProtected({action:'enroll',accountId:who.id,id,fingerprint:info.fingerprint},key)});assert.equal(response.statusCode,200,response.body);return {...response.json().device,key,pair};}
 try{
  for(const name of ['001_foundation','009_treasurer_vault_admin_rbac','014_volunteer_coordination','016_staff_passkeys','017_staff_roles','022_protected_records'])await pool.query(await readFile('db/migrations/'+name+'.sql','utf8'));
  const owner=await actor('owner'),volunteer=await actor('volunteer'),safety=await actor('safety-reviewer'),outsider=await actor('editor');
  const a=await device(volunteer),b=await device(safety),c=await device(outsider);
  const approval=d=>({fingerprint:d.fingerprint,scope:'incident',confirm:'verified recipient fingerprint independently'});
  assert.equal((await send(volunteer,'devices/'+b.id+'/approve',approval(b))).statusCode,403);
  assert.equal((await send(owner,'devices/'+c.id+'/approve',approval(c))).statusCode,403);
  assert.equal((await send(owner,'devices/'+b.id+'/approve',approval(b))).statusCode,200);
  const id=randomUUID();recordIds.push(id);const context={profile:PROTECTED_PROFILE,recordId:id,sequence:1,kind:'incident',sender:a.id,recipients:[a.id,b.id].sort(),generation:1},payload={text:'PRIVATE_SQL_CANARY_9274',attachment:{name:'private.txt',bytes:Buffer.from('ATTACHMENT_SQL_CANARY').toString('base64')}};
  const message=await encryptProtected(context,payload,[a,b],a.key);
  assert.equal((await send({...volunteer,headers:{...volunteer.headers,'x-csrf-token':'wrong'}},'records',message)).statusCode,403);
  const posted=await send(volunteer,'records',message);assert.equal(posted.statusCode,200,posted.body);
  assert.equal((await send(volunteer,'records',message)).statusCode,409);
  assert.equal((await send(outsider,'records/'+id)).statusCode,404);
  const sql=JSON.stringify((await pool.query('SELECT * FROM g28.protected_records WHERE id=$1',[id])).rows);assert(!sql.includes(payload.text));assert(!sql.includes(payload.attachment.bytes));
  const received=await send(safety,'records/'+id);assert.equal(received.statusCode,200,received.body);assert.deepEqual(await decryptProtected(received.json().record.messages[0],b.key,a),payload);
  const substituted=await encryptProtected({...context,sequence:2},{text:'should fail'},[a,c],a.key);assert.equal((await send(volunteer,'records',substituted)).statusCode,400);
  const reply=await encryptProtected({...context,sequence:2,sender:b.id},{text:'protected staff reply'},[a,b],b.key);assert.equal((await send(safety,'records',reply)).statusCode,200);
  const proof={action:'export',recordId:id,version:2,deviceId:a.id};const exported=await send(volunteer,'records/'+id+'/export',{deviceId:a.id,version:2,signature:await signProtected(proof,a.key),confirm:'export exact encrypted record'});assert.equal(exported.statusCode,200,exported.body);assert(!exported.body.includes('protected staff reply'));
  await pool.query('UPDATE g28.admin_grants SET revoked_at=now() WHERE email_key=$1',[safety.emailKey]);assert.equal((await send(safety,'records/'+id)).statusCode,403);await pool.query('UPDATE g28.admin_grants SET revoked_at=NULL WHERE email_key=$1',[safety.emailKey]);
  await store.withStaffSecurity(safety.id,s=>{s.sessions={};});assert.equal((await send(safety,'records/'+id)).statusCode,403);
  const digest=createHash('sha256').update('synthetic legal hold').digest('hex');assert.equal((await send(owner,'records/'+id+'/hold',{held:true,evidenceDigest:digest})).statusCode,200);
  await pool.query("UPDATE g28.protected_records SET retain_until=now()-interval '1 day' WHERE id=$1",[id]);assert.equal((await send(owner,'lifecycle/purge',{})).json().deleted,0);
  assert.equal((await send(owner,'devices/'+b.id+'/revoke',{signature:null})).statusCode,200);assert.equal((await send(volunteer,'records',await encryptProtected({...context,sequence:3},{text:'revoked'},[a,b],a.key))).statusCode,409);
  assert.equal((await send(owner,'devices/'+b.id+'/approve',approval(b))).statusCode,409);
  await send(owner,'records/'+id+'/hold',{held:false,evidenceDigest:digest});assert.equal((await send(owner,'lifecycle/purge',{})).json().deleted,1);assert.equal((await send(volunteer,'records/'+id)).statusCode,404);
  assert.equal((await send(volunteer,'records',message)).statusCode,409,'An old signed first message cannot resurrect a purged record');
  assert((await pool.query("SELECT 1 FROM g28.protected_lifecycle_events WHERE record_id=$1 AND action='ciphertext_export'",[id])).rowCount===1);
  // The closure trigger does not need a general protected-table runtime grant.
  const heldId=randomUUID(),unheldId=randomUUID();recordIds.push(heldId,unheldId);
  for(const [closureId,held]of [[heldId,true],[unheldId,false]])await pool.query('INSERT INTO g28.protected_records(id,author_id,participants,document,version,retain_until,legal_hold) VALUES($1,$2,$3,$4,1,$5,$6)',[closureId,volunteer.id,[volunteer.id,safety.id],{id:closureId,authorId:volunteer.id,participants:[volunteer.id,safety.id],messages:[message]},new Date(now+86400000),held]);
  await store.closeAccount(volunteer.id);
  assert.equal((await pool.query('SELECT 1 FROM g28.protected_records WHERE id=$1',[unheldId])).rowCount,0);
  const heldRow=(await pool.query('SELECT author_id,legal_hold FROM g28.protected_records WHERE id=$1',[heldId])).rows[0];assert(heldRow.legal_hold);assert.equal(heldRow.author_id,null);
  assert.equal((await pool.query('SELECT state,account_id FROM g28.protected_devices WHERE id=$1',[a.id])).rows[0].state,'revoked');
  assert.equal((await pool.query('SELECT account_id FROM g28.protected_devices WHERE id=$1',[a.id])).rows[0].account_id,null);

 }finally{await app.close();await pool.query('DELETE FROM g28.protected_records WHERE id=ANY($1::uuid[])',[recordIds]);await pool.query('DELETE FROM g28.protected_lifecycle_events WHERE actor_id=ANY($1::text[])',[accounts]);await pool.query('DELETE FROM g28.protected_devices WHERE id=ANY($1::uuid[])',[deviceIds]);await pool.query('DELETE FROM g28.admin_grants WHERE email_key=ANY($1::text[])',[keys]);await pool.query('DELETE FROM g28.accounts WHERE id=ANY($1::uuid[])',[accounts]);await store.close();}
});
