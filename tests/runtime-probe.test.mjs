import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {runtimeProbe} from '../packages/core/runtime-probe.mjs';
for(const kind of ['web','portal'])test('actual loopback '+kind+' probe checks private gate, exact revision and installed assets without returning credentials',async t=>{
 const env={RENDER_GIT_COMMIT:'a'.repeat(40),PREVIEW_ACCESS_PASSWORD:'synthetic-existing-private-gate-only',VOLUNTEER_PASSKEYS_ENABLED:'true'},authorization='Basic '+Buffer.from('preview:'+env.PREVIEW_ACCESS_PASSWORD).toString('base64');
 let bad=null;const paths=[];
 const server=createServer((req,res)=>{
  paths.push(req.url);
  if(req.headers.authorization!==authorization){res.writeHead(401);res.end();return;}
  if(req.url===bad){res.writeHead(503);res.end();return;}
  const body=req.url==='/healthz'?{ok:true,commit:env.RENDER_GIT_COMMIT,service:kind==='web'?'galinsky-2028-web':'galinsky-2028-api'}:req.url==='/readyz'?{ready:true}:req.url==='/api/config'?{passkeyEnabled:true,signupEnabled:false,features:{protectedSubmissions:false,payments:false}}:null;
  if(req.url==='/api/materials'){res.writeHead(401);res.end();return;}
  res.end(body?JSON.stringify(body):req.url.startsWith('/assets/')?'/* installed asset */':'<main><div id="root"></div><script src="/assets/main.js"></script></main>');
 });await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const args={port:server.address().port,kind,env},result=await runtimeProbe(args);
 assert.equal(result.commit,env.RENDER_GIT_COMMIT);assert(result.checks>10);assert(paths.includes('/assets/main.js'));assert(!JSON.stringify(result).includes(env.PREVIEW_ACCESS_PASSWORD));assert(!JSON.stringify(result).includes(authorization));
 bad='/assets/main.js';await assert.rejects(runtimeProbe(args),/probe failed/);
 await assert.rejects(runtimeProbe({...args,port:0}));await assert.rejects(runtimeProbe({...args,kind:'unknown'}));await assert.rejects(runtimeProbe({...args,env:{...env,RENDER_GIT_COMMIT:'wrong'}}));
});
