// Owner-authorized retirement of the two superseded campaign services only.
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
export const OLD_SERVICES=Object.freeze([
 {id:'srv-db5teuajnfac73bm8pug',name:'galinsky-2028-private-preview'},
 {id:'srv-db5v0lfavr4c73a62870',name:'galinsky-2028-volunteer-portal'}
]);
export async function retireOldRender({action,env=process.env,transport=fetch}){
 if(!['audit','delete'].includes(action))throw Error('Explicit audit/delete action required.');
 if(env.GITHUB_REPOSITORY!=='Galinsky-2028/Galinsky-2028'||env.GITHUB_REF!=='refs/heads/main')throw Error('Only the current campaign main branch may retire old services.');
 if(!env.G28_RENDER_API_KEY)throw Error('Old Render credential unavailable.');
 async function api(method,id){
  const r=await transport('https://api.render.com/v1/services/'+id,{method,headers:{Authorization:'Bearer '+env.G28_RENDER_API_KEY,Accept:'application/json'},signal:AbortSignal.timeout(30000)});
  if(!r.ok)throw Error('Old service '+method+' failed with HTTP '+r.status+'; response withheld.');
  return method==='GET'?r.json():null;
 }
 // Complete all identity checks before the first deletion. No project/database or
 // connected-workspace service can be selected through an input parameter.
 for(const expected of OLD_SERVICES){
  const raw=await api('GET',expected.id),s=raw.service||raw;
  if(s.id!==expected.id||s.name!==expected.name||s.ownerId!=='tea-db23jkks728c73av263g'||s.environmentId!=='evm-db57fnm7bikc739783qg'||s.branch!=='main'||!['https://github.com/neophilism/Galinsky-2028','https://github.com/Galinsky-2028/Galinsky-2028'].includes(s.repo))throw Error('Old campaign service identity or placement changed.');
 }
 if(action==='audit')return {verified:OLD_SERVICES.map(x=>x.id),deleted:[]};
 const deleted=[];
 for(const target of OLD_SERVICES){await api('DELETE',target.id);deleted.push(target.id);}
 return {deleted};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{console.log(JSON.stringify(await retireOldRender({action:process.env.G28_RETIRE_ACTION})));}
 catch(e){console.error(e.message);process.exitCode=1;}
}
