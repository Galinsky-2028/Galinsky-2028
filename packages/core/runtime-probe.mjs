// Read-only checks against this process's loopback listener. The private gate
// is exercised with the existing credential in memory, never returned/logged.
import {safeReleaseCommit} from './release-id.mjs';
export async function runtimeProbe({port,kind,env=process.env}){
 if(!Number.isInteger(port)||port<1||port>65535||!['web','portal'].includes(kind))throw Error('Invalid runtime probe target.');
 const commit=safeReleaseCommit(env.RENDER_GIT_COMMIT);
 if(!commit||!env.PREVIEW_ACCESS_PASSWORD)throw Error('Runtime probe requires release identity and private access.');
 const base='http://127.0.0.1:'+port,auth='Basic '+Buffer.from((env.PREVIEW_ACCESS_USER||'preview')+':'+env.PREVIEW_ACCESS_PASSWORD).toString('base64');
 const get=async(path,authenticated=true)=>{
  const response=await fetch(base+path,{headers:authenticated?{Authorization:auth}:{},redirect:'error',signal:AbortSignal.timeout(10000)});
  return {status:response.status,body:await response.text()};
 };
 let checks=0;const verify=(ok)=>{if(!ok)throw Error('Runtime application probe failed.');checks++;};
 verify((await get('/healthz',false)).status===401);
 const health=await get('/healthz');verify(health.status===200);const h=JSON.parse(health.body);
 verify(h.ok===true&&h.commit===commit&&h.service===(kind==='web'?'galinsky-2028-web':'galinsky-2028-api'));
 const paths=kind==='web'?['/','/volunteer/','/donate/','/issues/kirk-evers/','/issues/garden/','/issues/cornerstone/']:['/','/roles','/materials'];
 for(const path of paths){const page=await get(path);verify(page.status===200&&(kind==='web'?/<main\b/.test(page.body):/id=["']root["']/.test(page.body)));
  const assets=[...page.body.matchAll(/(?:src|href)="(\/assets\/[^"?#]+)(?:[?#][^"]*)?"/g)].map(x=>x[1]);
  verify(assets.length>0);for(const asset of new Set(assets))verify((await get(asset)).status===200);
 }
 if(kind==='portal'){
  verify((await get('/readyz')).status===200);
  const configuration=await get('/api/config');verify(configuration.status===200);const c=JSON.parse(configuration.body);
  verify(c.passkeyEnabled===(env.VOLUNTEER_PASSKEYS_ENABLED==='true')&&c.signupEnabled===(env.SIGNUP_ENABLED==='true'));
  verify(c.features.protectedSubmissions===false&&c.features.payments===false);
  verify((await get('/api/materials')).status===401);
 }
 return {event:'runtime_application_verified',kind,commit,checks,scope:'read-only-loopback-http-and-installed-assets'};
}
