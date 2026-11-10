// Real application + isolated PostgreSQL; synthetic sessions, no outbound mail.
import assert from 'node:assert/strict';
import {chromium,firefox,webkit} from 'playwright';
import {randomUUID} from 'node:crypto';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {createApp} from '../../apps/api/src/app.mjs';
import {PostgresStore,databasePool} from '../../apps/api/src/postgres-store.mjs';
import {registerPortal} from '../../apps/api/src/static.mjs';
import {randomToken,tokenHash} from '../../packages/core/auth.mjs';
const url=process.env.TEST_DATABASE_URL;
assert(url&&['localhost','127.0.0.1'].includes(new URL(url).hostname),'Operations browser verification requires isolated local PostgreSQL.');
const pool=databasePool(url),store=new PostgresStore(pool),origin='http://127.0.0.1:4452',now=Date.now(),prefix='browser-'+randomUUID().slice(0,8),accounts=[],results=[];
const config={staffIdentity:true,adminLoginReady:true,adminOwnerEmailKey:prefix+'-owner',portalOrigin:origin,publicOrigin:'http://127.0.0.1:4451'};
const app=createApp({store,config});registerPortal(app,origin);
await mkdir('test-results/browser/operations',{recursive:true});
async function identity(owner=false){const id=randomUUID(),token=randomToken(),hash=tokenHash(token),key=owner?config.adminOwnerEmailKey:prefix+'-'+id;accounts.push(id);await pool.query("INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'synthetic',now(),'synthetic')",[id,key]);await pool.query('INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',[hash,id,randomToken(),new Date(now+86400000)]);if(owner)await store.withStaffSecurity(id,s=>{s.credentials=[{id:'synthetic-session-fixture'}];s.sessions={[hash]:{credentialId:'synthetic-session-fixture',expires:now+900000}};});return {id,token};}
try{
 for(const name of ['001_foundation','004_fundraising_reconciliation','009_treasurer_vault_admin_rbac','016_staff_passkeys','017_staff_roles','019_operations','020_treasury_exports'])await pool.query(await readFile('db/migrations/'+name+'.sql','utf8'));
 const owner=await identity(true),member=await identity(),guideId=prefix+'-guide';
 await pool.query("INSERT INTO g28.materials(id,revision,status,audience,record) VALUES($1,1,'published','volunteer',$2)",[guideId,{id:guideId,title:'Synthetic operations guide',body:'Synthetic training only.',revision:1,status:'published',audience:'volunteer',author:'synthetic-operations-author',review:{approvedBy:'synthetic-review',revision:1,at:'2026-10-10T00:00:00Z'}}]);
 await pool.query("INSERT INTO g28.financial_provider_events(provider,event_id,payment_id,event_digest,event_kind,amount_cents,occurred_at) VALUES($1,$2,$3,$4,'captured',1700,'2021-01-18T12:00:00Z')",[prefix,randomUUID(),randomUUID(),'a'.repeat(64)]);
 await app.listen({host:'127.0.0.1',port:4452});
 for(const [name,engine]of Object.entries({chromium,firefox,webkit})){
  const browser=await engine.launch();let ownerContext,memberContext;
  try{
   ownerContext=await browser.newContext({viewport:{width:390,height:844}});memberContext=await browser.newContext({viewport:{width:390,height:844}});
   await ownerContext.addCookies([{name:'g28-local',value:owner.token,url:origin}]);await memberContext.addCookies([{name:'g28-local',value:member.token,url:origin}]);
   const page=await ownerContext.newPage(),volunteer=await memberContext.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));volunteer.on('pageerror',e=>errors.push(e.message));
   await page.goto(origin+'/assignments-admin');await page.getByRole('heading',{name:'Assignments, training and tools'}).waitFor();
   const taskId=prefix+'-'+name;await page.getByLabel('Stable reference',{exact:true}).fill(taskId);await page.getByLabel('Title',{exact:true}).fill('Synthetic '+name+' practice');await page.getByLabel('Active after the documented prerequisites pass').check();await page.getByLabel('Current approved material').selectOption(guideId);await page.getByLabel('Task instructions').fill('Read the synthetic guide.');await page.getByLabel('Stop conditions').fill('Stop if the guide changes.');await page.getByLabel('Available from').fill(new Date(now-60000).toISOString().slice(0,16));await page.getByLabel('Available until').fill(new Date(now+3600000).toISOString().slice(0,16));await page.getByRole('button',{name:'Save definition',exact:true}).click();await page.getByText('Definition saved. Changed requirements must be rechecked before further action.').waitFor();
   await volunteer.goto(origin+'/tasks');const card=volunteer.getByRole('article').filter({has:volunteer.getByRole('heading',{name:'Synthetic '+name+' practice',exact:true})});await card.getByRole('button',{name:'Claim assignment',exact:true}).click();await card.getByText('Your assignment: claimed.').waitFor();await card.getByLabel('Aggregate completed units').fill('2');await card.getByLabel('Minutes spent').fill('15');await card.getByRole('button',{name:'Submit self-reported result'}).click();await card.getByText('Your assignment: reported.').waitFor();
   const item=page.getByRole('listitem').filter({has:page.getByText('Synthetic '+name+' practice',{exact:true})});await item.getByRole('button',{name:'Review reports'}).click();await page.getByRole('button',{name:'Verify result',exact:true}).click();await page.getByText(/verified · 2 units · 15 minutes/).waitFor();
   await volunteer.reload();await card.getByText('Your assignment: verified.').waitFor();assert.equal(await volunteer.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.goto(origin+'/admin');await page.getByRole('heading',{name:'Controlled ledger export'}).waitFor();await page.getByLabel('Period begins (UTC, inclusive)',{exact:true}).fill('2021-01-01');await page.getByLabel('Period ends (UTC, exclusive)',{exact:true}).fill('2021-02-01');await page.getByLabel('Type “export treasury ledger” to confirm').fill('export treasury ledger');const download=page.waitForEvent('download');await page.getByRole('button',{name:'Download controlled export'}).click();const downloaded=await download;const csv=await readFile(await downloaded.path(),'utf8');assert(csv.includes(prefix));assert(csv.includes('1700'));await page.getByText(/Export downloaded. Audit reference:/).waitFor();
   assert.deepEqual(errors,[]);await volunteer.screenshot({path:`test-results/browser/operations/${name}-verified.png`,fullPage:true});results.push({browser:name,realPostgres:true,staffDefinition:true,volunteerClaimReport:true,independentReview:true,mobileReflow:true,auditedTreasuryDownload:true});
  }finally{await ownerContext?.close();await memberContext?.close();await browser.close();}
 }
}finally{
 await app.close();await pool.query('DELETE FROM g28.operation_definitions WHERE id LIKE $1',[prefix+'%']);await pool.query('DELETE FROM g28.materials WHERE id=$1',[prefix+'-guide']);await pool.query('DELETE FROM g28.treasury_exports WHERE actor_id=ANY($1::uuid[])',[accounts]);await pool.query('DELETE FROM g28.financial_provider_events WHERE provider=$1',[prefix]);await pool.query('DELETE FROM g28.accounts WHERE id=ANY($1::uuid[])',[accounts]);await pool.query('DELETE FROM g28.audit_events WHERE actor_subject=ANY($1::text[])',[accounts]);await store.close();await writeFile('test-results/browser/operations/results.json',JSON.stringify(results,null,2));
}
console.log(JSON.stringify(results));
