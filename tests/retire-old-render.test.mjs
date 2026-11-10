import test from 'node:test';
import assert from 'node:assert/strict';
import {retireOldRender,OLD_SERVICES} from '../scripts/retire-old-render.mjs';
const env={GITHUB_REPOSITORY:'Galinsky-2028/Galinsky-2028',GITHUB_REF:'refs/heads/main',G28_RENDER_API_KEY:'synthetic'};
const service=t=>({...t,ownerId:'tea-db23jkks728c73av263g',environmentId:'evm-db57fnm7bikc739783qg',branch:'main',repo:'https://github.com/neophilism/Galinsky-2028'});
test('retirement checks every exact old service before deleting; audit never writes',async()=>{
 for(const action of ['audit','delete']){
  const methods=[];
  const result=await retireOldRender({action,env,transport:async(url,{method})=>{
   methods.push(method);const t=OLD_SERVICES.find(x=>url.endsWith('/'+x.id));assert(t);
   return {ok:true,json:async()=>service(t)};
  }});
  assert.deepEqual(methods,action==='audit'?['GET','GET']:['GET','GET','DELETE','DELETE']);
  assert.equal(result.deleted.length,action==='audit'?0:2);
 }
});
test('wrong branch, foreign service or inaccessible old account never triggers deletion',async()=>{
 for(const changed of ['branch','owner','missing']){
  let deletes=0;
  await assert.rejects(retireOldRender({action:'delete',env:changed==='branch'?{...env,GITHUB_REF:'refs/heads/other'}:env,transport:async(url,{method})=>{
   if(method==='DELETE')deletes++;
   const t=OLD_SERVICES.find(x=>url.endsWith('/'+x.id));
   return {ok:changed!=='missing',status:404,json:async()=>({...service(t),ownerId:'foreign'})};
  }}));
  assert.equal(deletes,0);
 }
});
