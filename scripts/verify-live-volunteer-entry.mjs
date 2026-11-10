#!/usr/bin/env node
// Read-only proof the public site navigates into the real, secured portal.
import assert from 'node:assert/strict';
const PUBLIC='https://galinsky2028-website.onrender.com';
const PORTAL='https://galinsky2028-volunteers.onrender.com';
const password=process.env.G28_PREVIEW_ACCESS_PASSWORD;
assert(typeof password==='string'&&password.length>=24,'Missing protected GitHub Actions password');
const authorization='Basic '+Buffer.from('preview:'+password,'utf8').toString('base64');
const badAuthorization='Basic '+Buffer.from('preview:not-the-private-password','utf8').toString('base64');
const roles=['network','digital','issue','canvass','phone','host','recruit','captain','ballot','voter','fundraising','skills'];
let requests=0;
async function get(origin,path,header=authorization) {
 const response=await fetch(origin+path,{
  redirect:'manual',signal:AbortSignal.timeout(20000),
  headers:header===null?{}:{Authorization:header}
 });
 requests++;
 return {response,body:await response.text()};
}
for(const origin of [PUBLIC,PORTAL]){
 for(const header of [null,badAuthorization]){
  const {response}=await get(origin,'/volunteer/',header);
  assert.equal(response.status,401,'Private website must reject unauthenticated or bad credentials');
  assert.match(response.headers.get('www-authenticate')||'',/^Basic\b/i);
 }
}
const home=await get(PUBLIC,'/');
assert.equal(home.response.status,200);
assert(home.body.includes('href="'+PORTAL+'/roles"'),'Main navigation must open actual portal');
const volunteer=await get(PUBLIC,'/volunteer/');
assert.equal(volunteer.response.status,200);
assert(volunteer.response.headers.get('x-robots-tag')?.includes('noindex'));
assert(!volunteer.body.includes('id="preview-workspace"'),'Local-only fake demo must be absent');
assert(!volunteer.body.includes('volunteer-preview.js'),'Old client demo must not be bundled');
for(const role of roles){
 assert(volunteer.body.includes('href="'+PORTAL+'/roles?role='+role+'"'),
  'Missing actual portal role link: '+role);
}
const page=await get(PORTAL,'/roles?role=skills');
assert.equal(page.response.status,200);
assert(page.body.includes('<div id="root">'),'Expected React portal shell');
const ready=await get(PORTAL,'/readyz');
assert.equal(ready.response.status,200,'Neon must be reachable');
assert.equal(JSON.parse(ready.body).ready,true);
const response=await get(PORTAL,'/api/roles');
assert.equal(response.response.status,200);
const actual=JSON.parse(response.body).roles.map(r=>r.id);
assert.deepEqual(actual,roles);
const config=await get(PORTAL,'/api/config');
assert.equal(config.response.status,200);
const cfg=JSON.parse(config.body);
assert.equal(cfg.publicOrigin,PUBLIC);
assert.equal(cfg.signupEnabled,false,'Do not release signup without verified mail');
assert.equal(cfg.features.staff,false);
assert.equal(cfg.features.payments,false);
const privateData=await get(PORTAL,'/api/materials');
assert.equal(privateData.response.status,401,'Restricted materials must not be public');
console.log(JSON.stringify({verdict:'PASS',publicOrigin:PUBLIC,realVolunteerPortal:PORTAL,
 canonicalRoleCount:roles.length,noLocalFakeDemo:true,neonReady:true,
 signup:'held for verified email',staffAndPayments:'held',readOnlyRequests:requests}));
