import {runtimeProbe} from '../../../packages/core/runtime-probe.mjs';
import {loadConfig} from './config.mjs';
import {createApp} from './app.mjs';
import {PostgresStore,databasePool} from './postgres-store.mjs';
import {MemoryStore} from './memory-store.mjs';
import {registerPortal} from './static.mjs';
import {registerCampaignEditor} from './campaign-routes.mjs';
import {runMailQueueLoop} from './worker.mjs';
const config=loadConfig();
const store=config.databaseUrl?new PostgresStore(databasePool(config.databaseUrl)):new MemoryStore();
const app=createApp({store,config});
registerCampaignEditor(app,{accountStore:store,config});
registerPortal(app,config.portalOrigin);
const mailController=new AbortController();
let mailLoop=null;
if(config.production&&(config.signup||config.adminLoginReady)&&config.mailDeliveryMode==='inline'){
 // Never allow public signup OR private verified staff email until the service
 // can reach its durable queue and verified mail provider. The worker may run
 // in invitation-only mode while general volunteer signup is disabled.
 // Keep startup fail-closed if the real database cannot be reached.
 // This requires the existing configured sender and operational acceptance.
 // The existing service can then reach its
 // durable queue and a valid mail transport configuration is present.
 if(!config.databaseUrl)throw new Error('Inline mail worker requires a real database.');
 await store.healthy();
 mailLoop=runMailQueueLoop({store,config,signal:mailController.signal});
}
let closing=false;
async function shutdown(){
 if(closing)return;closing=true;
 mailController.abort();
 try{
  if(mailLoop)await mailLoop;
  await app.close();
  await store.close();
  process.exit(0);
 }catch{
  console.error('Clean shutdown failed; check mail/database worker health.');
  process.exit(1);
 }
}
for(const signal of ['SIGTERM','SIGINT'])process.once(signal,shutdown);
try{
 await app.listen({host:config.host,port:config.port});
 if(process.env.RENDER==='true')console.log(JSON.stringify(await runtimeProbe({port:config.port,kind:'portal'})));
 console.log(JSON.stringify({event:'api_started',port:config.port,
  signupEnabled:config.signup,adminLoginEnabled:config.adminLoginReady,
  mailDelivery:config.signup||config.adminLoginReady?config.mailDeliveryMode:'disabled'}));
}catch{
 mailController.abort();
 if(mailLoop)await mailLoop;
 await store.close();
 throw new Error('Portal failed to bind; background mail delivery stopped.');
}
