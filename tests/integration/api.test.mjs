import test from 'node:test';import assert from 'node:assert/strict';import {randomBytes} from 'node:crypto';
import {createApp} from '../../apps/api/src/app.mjs';import {MemoryStore} from '../../apps/api/src/memory-store.mjs';import {loadConfig} from '../../apps/api/src/config.mjs';import {openDelivery} from '../../packages/core/auth.mjs';
const config=loadConfig({MAIL_PROVIDER:'resend',RESEND_API_KEY:'ci-fixture-not-a-key',MAIL_FROM:'campaign@example.test',SIGNUP_ENABLED:'true',DELIVERY_KEY:randomBytes(32).toString('base64'),LOGIN_PEPPER:'ci-fixture-pepper-with-more-than-thirty-two-characters'});
const headers={origin:config.portalOrigin,'content-type':'application/json','sec-fetch-site':'same-origin'};
const material={id:'test-guide',title:'Synthetic test guide',description:'Fixture',body:'This is a synthetic guide.',category:'start',status:'published',audience:'volunteer',author:'fixture-author',revision:1,review:{approvedBy:'fixture-reviewer',revision:1,at:'2026-10-10T00:00:00Z'}};
async function setup(){const store=new MemoryStore({materials:[structuredClone(material),{...structuredClone(material),id:'archive',status:'unreviewed'}]});const app=createApp({store,config});return{app,store};}
async function login(app,store){const r=await app.inject({method:'POST',url:'/api/auth/request',headers,payload:{email:'volunteer@example.test',termsAccepted:true,marketing:false}});assert.equal(r.statusCode,202);const binding=r.headers['set-cookie'].split(';')[0];const job=store.outbox.at(-1);const token=new URL(openDelivery(job.envelope,config.deliveryKey).url).hash.slice(7);const v=await app.inject({method:'POST',url:'/api/auth/verify',headers:{...headers,cookie:binding},payload:{token}});assert.equal(v.statusCode,200);const cookie=v.headers['set-cookie'][0].split(';')[0];const s=await app.inject({url:'/api/session',headers:{cookie}});assert.equal(s.statusCode,200);return{cookie,csrf:s.json().csrf,binding,token};}
test('invalid approval metadata is excluded consistently from authenticated material surfaces',async()=>{
 const{app,store}=await setup();
 try{
  const user=await login(app,store);
  const mutations=[m=>{delete m.author;},m=>{m.review.approvedBy=m.author;},m=>{delete m.review.at;},m=>{m.review.at='invalid';},m=>{m.review.revision=2;}];
  for(const mutate of mutations){
   const broken=structuredClone(material);mutate(broken);store.materials=[broken];
   const list=await app.inject({url:'/api/materials',headers:{cookie:user.cookie}});
   assert.equal(list.statusCode,200);assert.deepEqual(list.json().materials,[]);
   for(const url of ['/api/materials/test-guide','/api/materials/test-guide/download']){
    const response=await app.inject({url,headers:{cookie:user.cookie}});
    assert.equal(response.statusCode,404);assert(!response.body.includes(material.body));
   }
   for(const [path,payload]of [['bookmark',{saved:true}],['reading',{revision:1,acknowledged:true}]]){
    const response=await app.inject({method:'POST',url:'/api/materials/test-guide/'+path,headers:{...headers,cookie:user.cookie,'x-csrf-token':user.csrf},payload});
    assert.equal(response.statusCode,404);
   }
  }
 }finally{await app.close();}
});
test('published activity readiness shows only non-sensitive current-version prerequisites',async()=>{
 const{app,store}=await setup();
 try{
  const user=await login(app,store);
  const at=Date.now();
  const module={id:'fixture-module',revision:1,status:'published',jurisdiction:'CT',election:'2028 General',
   activity:'Synthetic role orientation',validFrom:new Date(at-60000).toISOString(),
   validUntil:new Date(at+3600000).toISOString(),training:['private-training-id'],
   approvedTools:['approved-tool'],sources:[{url:'https://example.org/official',checkedAt:new Date(at).toISOString()}],
   verifiers:[{id:'staff-private-one',revision:1,evidence:'reviewed'},
    {id:'staff-private-two',revision:1,evidence:'reviewed'}],
   approval:{by:'approver-private',revision:1}};
  store.activityModules=[module,{...module,id:'draft-only',revision:1,status:'draft'}];
  const r=await app.inject({url:'/api/activity-status',headers:{cookie:user.cookie}});
  assert.equal(r.statusCode,200);
  assert.equal(r.json().modules.length,1);
  const status=r.json().modules[0];
  assert.equal(status.id,'fixture-module');
  assert.equal(status.publishedCurrent,true);
  assert.equal(status.activityAuthorized,false);
  assert(!r.body.includes('staff-private-one'));
  assert(!r.body.includes('approver-private'));
  assert(!r.body.includes('private-training-id'));
  assert(!r.body.includes('approved-tool'));
  assert(!r.body.includes('https://example.org'));
  // A newer draft suppresses an older published record rather than silently
  // falling back to an expired/possibly withdrawn field module.
  store.activityModules.push({...module,revision:2,status:'draft'});
  const later=await app.inject({url:'/api/activity-status',headers:{cookie:user.cookie}});
  assert.deepEqual(later.json().modules,[]);
 }finally{await app.close();}
});
test('first-hour orientation is private, revision-bound and never grants field authority',async()=>{
 const {app,store}=await setup();
 try{
  assert.equal((await app.inject({url:'/api/orientation'})).statusCode,401);
  const user=await login(app,store);
  const read=await app.inject({url:'/api/orientation',headers:{cookie:user.cookie}});
  assert.equal(read.statusCode,200);
  const lesson=read.json();
  assert.equal(lesson.completed,false);
  assert.equal(lesson.questions.length,3);
  assert(!read.body.includes('correct'));
  const payload={revision:lesson.revision,answers:{'current-guides':'no','personal-details':'own-notes','outdated-content':'verify'}};
  const h={...headers,cookie:user.cookie,'x-csrf-token':user.csrf};
  assert.equal((await app.inject({method:'POST',url:'/api/orientation/complete',headers:{...headers,cookie:user.cookie},payload})).statusCode,403);
  const wrong=await app.inject({method:'POST',url:'/api/orientation/complete',headers:h,
   payload:{...payload,answers:{...payload.answers,'current-guides':'yes'}}});
  assert.equal(wrong.statusCode,200);assert.equal(wrong.json().passed,false);
  const before=await app.inject({url:'/api/orientation',headers:{cookie:user.cookie}});
  assert.equal(before.json().completed,false);
  const stale=await app.inject({method:'POST',url:'/api/orientation/complete',headers:h,payload:{...payload,revision:'obsolete'}});
  assert.equal(stale.statusCode,409);
  const right=await app.inject({method:'POST',url:'/api/orientation/complete',headers:h,payload});
  assert.equal(right.statusCode,200);assert.equal(right.json().passed,true);
  assert.equal(right.json().verified,false);assert.equal(right.json().activityAuthorized,false);
  const saved=await app.inject({url:'/api/orientation',headers:{cookie:user.cookie}});
  assert.equal(saved.json().completed,true);
  const modules=await app.inject({url:'/api/activity-status',headers:{cookie:user.cookie}});
  assert.deepEqual(modules.json().modules,[]);
  assert.equal(store.accounts.size,1);
 }finally{await app.close();}
});
test('signup waits for verification and only encrypted delivery metadata is queued',async()=>{const{app,store}=await setup();const r=await app.inject({method:'POST',url:'/api/auth/request',headers,payload:{email:'volunteer@example.test',termsAccepted:true}});assert.equal(r.statusCode,202);assert.equal(store.accounts.size,0);assert.equal(store.outbox.length,1);assert(!JSON.stringify(store.outbox).includes('volunteer@example.test'));assert(!r.body.includes('token='));await app.close();});
test('email verification creates a real session and immediately unlocks reviewed materials',async()=>{const{app,store}=await setup();const{cookie}=await login(app,store);const r=await app.inject({url:'/api/materials',headers:{cookie}});assert.deepEqual(r.json().materials.map(m=>m.id),['test-guide']);const doc=await app.inject({url:'/api/materials/test-guide',headers:{cookie}});assert(doc.json().body.includes('synthetic'));const hidden=await app.inject({url:'/api/materials/archive',headers:{cookie}});assert.equal(hidden.statusCode,404);await app.close();});
test('verification links cannot replay or create sessions by GET',async()=>{const{app,store}=await setup();const{binding,token}=await login(app,store);const replay=await app.inject({method:'POST',url:'/api/auth/verify',headers:{...headers,cookie:binding},payload:{token}});assert.equal(replay.statusCode,400);const get=await app.inject({url:'/api/auth/verify?token='+token});assert.equal(get.statusCode,404);await app.close();});
test('unauthenticated library, downloads, tasks and forms return no private data',async()=>{const{app}=await setup();for(const path of ['/api/materials','/api/materials/test-guide','/api/materials/test-guide/download','/api/tasks','/api/forms']){const r=await app.inject({url:path});assert.equal(r.statusCode,401);assert(!r.body.includes('synthetic'));}await app.close();});
test('cross-origin and unsupported content type are rejected',async()=>{const{app}=await setup();const r=await app.inject({method:'POST',url:'/api/auth/request',headers:{...headers,origin:'https://other.test'},payload:{email:'volunteer@example.test',termsAccepted:true}});assert.equal(r.statusCode,403);const bad=await app.inject({method:'POST',url:'/api/auth/request',headers:{origin:config.portalOrigin,'content-type':'text/plain'},payload:'email=x'});assert.equal(bad.statusCode,415);await app.close();});
test('CSRF protected preferences and account closure revoke access',async()=>{const{app,store}=await setup();const{cookie,csrf}=await login(app,store);let r=await app.inject({method:'POST',url:'/api/account/consent',headers:{...headers,cookie},payload:{marketing:true}});assert.equal(r.statusCode,403);r=await app.inject({method:'POST',url:'/api/account/consent',headers:{...headers,cookie,'x-csrf-token':csrf},payload:{marketing:true}});assert.equal(r.statusCode,200);r=await app.inject({method:'POST',url:'/api/account/close',headers:{...headers,cookie,'x-csrf-token':csrf},payload:{confirm:'close my account'}});assert.equal(r.statusCode,200);assert.equal(store.accounts.size,0);assert.equal((await app.inject({url:'/api/session',headers:{cookie}})).statusCode,401);await app.close();});
test('rate limiting retains generic response and does not enqueue unlimited email',async()=>{const{app,store}=await setup();for(let n=0;n<8;n++){const r=await app.inject({method:'POST',url:'/api/auth/request',headers,payload:{email:'volunteer@example.test',termsAccepted:true}});assert.equal(r.statusCode,202);}assert.equal(store.outbox.length,4);await app.close();});
test('no volunteer session can access staff, payments or plaintext sensitive submissions',async()=>{const{app,store}=await setup();const{cookie,csrf}=await login(app,store);for(const path of ['/api/admin/publish','/api/protected/report','/api/payments/checkout']){const r=await app.inject({method:'POST',url:path,headers:{...headers,cookie,'x-csrf-token':csrf},payload:{body:'Must never be stored'}});assert.equal(r.statusCode,503);}assert(!JSON.stringify(store).includes('Must never be stored'));await app.close();});
test('unconfigured registration is a clear failure, not a fake success',async()=>{const store=new MemoryStore();const app=createApp({store,config:{...config,signup:false}});const r=await app.inject({method:'POST',url:'/api/auth/request',headers,payload:{email:'volunteer@example.test',termsAccepted:true}});assert.equal(r.statusCode,503);assert.equal(store.outbox.length,0);assert.equal(store.accounts.size,0);await app.close();});
test('security headers and body limits apply to API responses',async()=>{const{app}=await setup();const r=await app.inject({url:'/api/config'});assert.equal(r.headers['cache-control'],'no-store');assert.equal(r.headers['x-frame-options'],'DENY');assert(r.headers['content-security-policy'].includes("frame-ancestors 'none'"));const huge=await app.inject({method:'POST',url:'/api/auth/request',headers,payload:{email:'x'.repeat(40000)}});assert.equal(huge.statusCode,413);await app.close();});

// Progress is account-scoped and cannot certify regulated election activity.
test('personal task progress persists, toggles and requires CSRF',async()=>{
 const{app,store}=await setup();const{cookie,csrf}=await login(app,store);
 const auth={...headers,cookie,'x-csrf-token':csrf};
 let r=await app.inject({url:'/api/tasks',headers:{cookie}});
 assert.equal(r.json().completed,0);assert.equal(r.json().total,3);
 r=await app.inject({method:'POST',url:'/api/tasks/choose-role/completion',headers:{...headers,cookie},payload:{completed:true}});
 assert.equal(r.statusCode,403,'Missing CSRF must fail');
 r=await app.inject({method:'POST',url:'/api/tasks/choose-role/completion',headers:auth,payload:{completed:true}});
 assert.equal(r.statusCode,200);assert.deepEqual(r.json(),{id:'choose-role',completed:true,verified:false});
 r=await app.inject({url:'/api/tasks',headers:{cookie}});assert.equal(r.json().completed,1);
 assert.equal(r.json().tasks.find(t=>t.id==='choose-role').completed,true);
 r=await app.inject({method:'POST',url:'/api/tasks/choose-role/completion',headers:auth,payload:{completed:false}});
 assert.equal(r.statusCode,200);
 r=await app.inject({url:'/api/tasks',headers:{cookie}});assert.equal(r.json().completed,0);
 await app.close();
});
test('restricted tasks, arbitrary IDs and forged completion payloads are rejected',async()=>{
 const{app,store}=await setup();const{cookie,csrf}=await login(app,store);const auth={...headers,cookie,'x-csrf-token':csrf};
 for(const [task,payload,status] of [['petition-training',{completed:true},403],['arbitrary',{completed:true},404],['read-principle',{completed:'true'},400],['read-principle',{completed:true,notes:'leak'},400]]){
  const r=await app.inject({method:'POST',url:'/api/tasks/'+task+'/completion',headers:auth,payload});assert.equal(r.statusCode,status,task);
 }
 assert.equal(store.taskProgress.size,0);
 await app.close();
});
test('task progress is account-isolated and erased when the account closes',async()=>{
 const{app,store}=await setup();const{cookie,csrf}=await login(app,store);const auth={...headers,cookie,'x-csrf-token':csrf};
 let r=await app.inject({method:'POST',url:'/api/tasks/read-principle/completion',headers:auth,payload:{completed:true}});assert.equal(r.statusCode,200);
 assert.equal(store.taskProgress.size,1);
 r=await app.inject({method:'POST',url:'/api/account/close',headers:auth,payload:{confirm:'close my account'}});assert.equal(r.statusCode,200);
 assert.equal(store.taskProgress.size,0);
 assert.equal((await app.inject({url:'/api/tasks',headers:{cookie}})).statusCode,401);
 await app.close();
});

test('material reading acknowledgments track exact approved edition, undo and CSRF',async()=>{
 const{app,store}=await setup();const{cookie,csrf}=await login(app,store);
 const auth={...headers,cookie,'x-csrf-token':csrf};
 let r=await app.inject({url:'/api/materials/test-guide',headers:{cookie}});
 assert.equal(r.statusCode,200);assert.equal(r.json().acknowledged,false);
 r=await app.inject({method:'POST',url:'/api/materials/test-guide/reading',headers:auth,payload:{revision:1,acknowledged:true}});
 assert.equal(r.statusCode,200);assert.deepEqual(r.json(),{materialId:'test-guide',revision:1,acknowledged:true,trainingCertified:false,activityAuthorized:false});
 r=await app.inject({url:'/api/materials/test-guide',headers:{cookie}});assert.equal(r.json().acknowledged,true);
 r=await app.inject({method:'POST',url:'/api/materials/test-guide/reading',headers:auth,payload:{revision:1,acknowledged:false}});
 assert.equal(r.statusCode,200);
 r=await app.inject({url:'/api/materials/test-guide',headers:{cookie}});assert.equal(r.json().acknowledged,false);
 assert.equal(store.materialReading.size,0);await app.close();
});
test('stale, unreviewed and forged material acknowledgments fail closed',async()=>{
 const{app,store}=await setup();const{cookie,csrf}=await login(app,store);
 const auth={...headers,cookie,'x-csrf-token':csrf};
 const cases=[
 ['test-guide',{revision:2,acknowledged:true},409,auth],
 ['archive',{revision:1,acknowledged:true},404,auth],
 ['missing',{revision:1,acknowledged:true},404,auth],
 ['test-guide',{revision:1,acknowledged:'yes'},400,auth],
 ['test-guide',{revision:1,acknowledged:true,certified:true},400,auth],
 ['test-guide',{revision:1,acknowledged:true},403,{...headers,cookie}]
 ];
 for(const [id,body,status,h]of cases){
  const r=await app.inject({method:'POST',url:'/api/materials/'+id+'/reading',headers:h,payload:body});
  assert.equal(r.statusCode,status,id+' '+JSON.stringify(body));
 }
 assert.equal(store.materialReading.size,0);
 const r=await app.inject({method:'POST',url:'/api/materials/test-guide/reading',headers:auth,payload:{revision:1,acknowledged:true}});
 assert.equal(r.statusCode,200);
 store.materials[0].body='A newly reviewed edition';store.materials[0].revision=2;store.materials[0].review={approvedBy:'different-reviewer',revision:2,at:'2026-10-11T00:00:00Z'};
 const changed=await app.inject({url:'/api/materials/test-guide',headers:{cookie}});
 assert.equal(changed.json().acknowledged,false,'Previous revision acknowledgment must never silently carry over');
 await app.close();
});
test('closing an account erases its private material reading records',async()=>{
 const{app,store}=await setup();const{cookie,csrf}=await login(app,store);
 const auth={...headers,cookie,'x-csrf-token':csrf};
 let r=await app.inject({method:'POST',url:'/api/materials/test-guide/reading',headers:auth,payload:{revision:1,acknowledged:true}});assert.equal(r.statusCode,200);
 assert.equal(store.materialReading.size,1);
 r=await app.inject({method:'POST',url:'/api/account/close',headers:auth,payload:{confirm:'close my account'}});assert.equal(r.statusCode,200);
 assert.equal(store.materialReading.size,0);
 await app.close();
});

test('volunteer role preferences are durable, account-scoped and never authorize activity',async()=>{
 const {app,store}=await setup();const {cookie,csrf}=await login(app,store);
 const auth={...headers,cookie,'x-csrf-token':csrf};
 let r=await app.inject({url:'/api/account/role-preferences',headers:{cookie}});
 assert.deepEqual(r.json(),{preferences:null});
 for(const [payload,status]of [
  [{roleId:'ballot',minutes:30,willingToTrain:true},403],
  [{roleId:'staff',minutes:30,willingToTrain:true},400],
  [{roleId:'ballot',minutes:42,willingToTrain:true},400],
  [{roleId:'ballot',minutes:30,willingToTrain:'yes'},400],
  [{roleId:'ballot',minutes:30,willingToTrain:true,permission:'approved'},400]
 ]){
  const result=await app.inject({method:'POST',url:'/api/account/role-preferences',headers:status===403?{...headers,cookie}:auth,payload});
  assert.equal(result.statusCode,status);
 }
 const chosen={roleId:'ballot',minutes:120,willingToTrain:true};
 r=await app.inject({method:'POST',url:'/api/account/role-preferences',headers:auth,payload:chosen});
 assert.equal(r.statusCode,200);assert.deepEqual(r.json(),{saved:true,preferences:chosen,activityAuthorized:false});
 r=await app.inject({url:'/api/account/role-preferences',headers:{cookie}});
 assert.deepEqual(r.json(),{preferences:chosen});
 const another=await app.inject({url:'/api/account/role-preferences'});assert.equal(another.statusCode,401);
 r=await app.inject({method:'POST',url:'/api/account/close',headers:auth,payload:{confirm:'close my account'}});
 assert.equal(r.statusCode,200);assert.equal(store.rolePreferences.size,0);
 await app.close();
});


test('account data export returns only the authenticated volunteer own durable records',async()=>{
 const{app,store}=await setup();
 const{cookie}=await login(app,store);
 const s=(await app.inject({url:'/api/session',headers:{cookie}})).json();
 const id=s.account.id;
 await store.setRolePreferences(id,{roleId:'skills',minutes:120,willingToTrain:true});
 await store.setTaskCompletion(id,'choose-role',true);
 await store.setMaterialAck(id,'test-guide',{revision:1,contentSha256:'a'.repeat(64)});
 store.accounts.set(randomBytes(16).toString('hex'),{id:'unrelated',emailKey:'private-other-email',marketing:true});
 const r=await app.inject({url:'/api/account/export',headers:{cookie}});
 assert.equal(r.statusCode,200);
 assert.match(r.headers['content-disposition'],/attachment; filename="galinsky-volunteer-account.json"/);
 assert.match(r.headers['cache-control'],/no-store/);
 const data=r.json();
 assert.equal(data.schemaVersion,1);
 assert.equal(data.account.id,id);
 assert.equal(data.account.marketingConsent,false);
 assert.equal(data.account.termsVersion,config.termsVersion);
 assert.deepEqual(data.rolePreferences,{roleId:'skills',minutes:120,willingToTrain:true});
 assert.deepEqual(data.completedTasks,['choose-role']);
 assert.deepEqual(data.materialAcknowledgments,[{materialId:'test-guide',revision:1,contentSha256:'a'.repeat(64)}]);
 for(const forbidden of ['emailKey','deliveryEnvelope','private-other-email','token_hash','csrf','lease_token','unrelated']){
  assert(!r.body.includes(forbidden),'Account export must not contain '+forbidden);
 }
 assert.equal((await app.inject({url:'/api/account/export'})).statusCode,401);
 await app.close();
});

test('sign out everywhere uses CSRF and invalidates all of this account sessions',async()=>{
 const{app,store}=await setup();
 const a=await login(app,store);
 const b=await login(app,store);
 assert.equal((await app.inject({url:'/api/session',headers:{cookie:a.cookie}})).statusCode,200);
 assert.equal((await app.inject({url:'/api/session',headers:{cookie:b.cookie}})).statusCode,200);
 const hdr={...headers,cookie:a.cookie,'x-csrf-token':a.csrf};
 for(const [h,payload,status]of [
  [{...headers,cookie:a.cookie},{confirm:'sign out everywhere'},403],
  [hdr,{confirm:'yes'},400],
  [hdr,{confirm:'sign out everywhere',accountId:'someone-else'},400]
 ]){
  const r=await app.inject({method:'POST',url:'/api/account/revoke-sessions',headers:h,payload});
  assert.equal(r.statusCode,status);
 }
 const r=await app.inject({method:'POST',url:'/api/account/revoke-sessions',headers:hdr,payload:{confirm:'sign out everywhere'}});
 assert.equal(r.statusCode,200);
 assert.deepEqual(r.json(),{signedOutAll:true});
 assert.equal((await app.inject({url:'/api/session',headers:{cookie:a.cookie}})).statusCode,401);
 assert.equal((await app.inject({url:'/api/session',headers:{cookie:b.cookie}})).statusCode,401);
 assert.equal(store.accounts.size,1,'Revocation does not delete the user account');
 await app.close();
});

test('bookmarks are account-scoped, authorized, persistent and not accessible anonymously',async()=>{
 const {app,store}=await setup();const {cookie,csrf}=await login(app,store);
 const auth={...headers,cookie,'x-csrf-token':csrf};
 assert.deepEqual((await app.inject({url:'/api/account/bookmarks',headers:{cookie}})).json(),{materialIds:[]});
 for(const [path,head,payload,status] of [
  ['/api/materials/test-guide/bookmark',{...headers,cookie},{saved:true},403],
  ['/api/materials/archive/bookmark',auth,{saved:true},404],
  ['/api/materials/not-current/bookmark',auth,{saved:true},404],
  ['/api/materials/test-guide/bookmark',auth,{saved:'yes'},400],
  ['/api/materials/test-guide/bookmark',auth,{saved:true,accountId:'other'},400]
 ]){
  const r=await app.inject({method:'POST',url:path,headers:head,payload});
  assert.equal(r.statusCode,status);
 }
 let r=await app.inject({method:'POST',url:'/api/materials/test-guide/bookmark',headers:auth,payload:{saved:true}});
 assert.equal(r.statusCode,200);assert.deepEqual(r.json(),{materialId:'test-guide',saved:true,storedInAccount:true});
 assert.deepEqual((await app.inject({url:'/api/account/bookmarks',headers:{cookie}})).json(),{materialIds:['test-guide']});
 assert.deepEqual((await app.inject({url:'/api/account/export',headers:{cookie}})).json().bookmarkedMaterials,['test-guide']);
 assert.deepEqual(await store.listBookmarks('unrelated'),[]);
 assert.equal((await app.inject({url:'/api/account/bookmarks'})).statusCode,401);
 r=await app.inject({method:'POST',url:'/api/materials/test-guide/bookmark',headers:auth,payload:{saved:false}});
 assert.equal(r.statusCode,200);
 assert.deepEqual((await app.inject({url:'/api/account/bookmarks',headers:{cookie}})).json(),{materialIds:[]});
 await app.close();
});
