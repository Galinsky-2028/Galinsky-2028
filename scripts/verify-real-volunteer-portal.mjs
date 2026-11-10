#!/usr/bin/env node
// Read-only deployed acceptance of the REAL volunteer API, not a UI mock.
// Password is supplied by an encrypted GitHub Actions secret. Never log it.
const PORTAL='https://galinsky2028-volunteers.onrender.com';
const PUBLIC='https://galinsky2028-website.onrender.com';
const token=process.env.PREVIEW_ACCESS_PASSWORD;
if(typeof token!=='string'||token.length<24)throw Error('Private preview password unavailable.');
const good='Basic '+Buffer.from('preview:'+token).toString('base64');
const bad='Basic '+Buffer.from('preview:incorrect-password').toString('base64');
const checks=[];
async function checked(path,expected,authorization=good){
 const r=await fetch(PORTAL+path,{headers:authorization?{Authorization:authorization}:{},redirect:'manual',signal:AbortSignal.timeout(20000)});
 const contentType=r.headers.get('content-type')||'';
 if(r.status!==expected)throw Error('Portal '+path+' access expected '+expected+', got '+r.status);
 if(authorization===good&&r.headers.get('x-robots-tag')?.toLowerCase().includes('noindex')!==true)
  throw Error('Private portal robots exclusion missing: '+path);
 checks.push({path,status:r.status,kind:authorization===good?'authorized':'unauthorized'});
 if(expected===200&&contentType.includes('application/json'))return r.json();
 if(expected===200&&contentType.includes('text/html'))return r.text();
 return null;
}
for(const path of ['/','/roles','/join','/healthz','/readyz','/api/config','/api/roles','/api/materials','/api/session','/api/admin/something']){
 await checked(path,401,null);
 await checked(path,401,bad);
}
const health=await checked('/healthz',200);
if(health?.service!=='galinsky-2028-api')throw Error('Actual API service did not respond.');
const ready=await checked('/readyz',200);
if(ready?.ready!==true)throw Error('Neon database schema is not ready.');
const config=await checked('/api/config',200);
if(config?.signupEnabled!==false||config.features?.staff!==false||
  config.features?.payments!==false||config.features?.protectedSubmissions!==false||
  config.publicOrigin!==PUBLIC)throw Error('Unsafe preview feature flag or incorrect public origin.');
const roles=await checked('/api/roles',200);
if(roles?.roles?.length!==12)throw Error('The 12 canonical volunteer roles are not served.');
const index=await checked('/',200);
if(!index?.includes('Galinsky'))throw Error('React volunteer portal index is not deployed.');
await checked('/roles',200);
await checked('/join',200);
await checked('/api/materials',401);
await checked('/api/session',401);
await checked('/api/admin/something',503);
console.log(JSON.stringify({verified:true,service:'real-volunteer-portal-staging',
  storage:'Neon readiness confirmed through API /readyz',
  twelveCanonicalRoles:true,accountCreation:'gated until verified email',paymentAndStaffFeatures:'disabled',
  checks:checks.map(x=>({path:x.path,status:x.status,kind:x.kind}))},null,2));
