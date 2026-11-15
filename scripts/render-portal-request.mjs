#!/usr/bin/env node
// Create the actual separately hosted volunteer portal/API in the designated
// Galinsky 2028 Render PROJECT and ENVIRONMENT. No preview facsimile.
// Staging database is configured separately as a Render secret via the Neon
// connector, NEVER in this repository, GitHub Actions logs, or request file.
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadPreviewGate} from '../packages/core/preview-gate.mjs';

export const PROJECT_ID='prj-db57fnm7bikc739783q0';
export const ENVIRONMENT_ID='evm-db57fnm7bikc739783qg';
export const OWNER_ID='tea-db23jkks728c73av263g';
export const PORTAL_NAME='galinsky-2028-volunteer-portal';
export const PORTAL_URL='https://galinsky-2028-volunteer-portal.onrender.com';
export const PUBLIC_URL='https://galinsky-2028-private-preview.onrender.com';
export const REPO='https://github.com/neophilism/Galinsky-2028';
const TARGET_IDS={projectId:PROJECT_ID,environmentId:ENVIRONMENT_ID,ownerId:OWNER_ID};
function validId(x,prefix){return typeof x==='string'&&x.startsWith(prefix+'-')&&/^[a-z0-9-]+$/.test(x);}
export function validateRequest(raw){
 const r=typeof raw==='string'?JSON.parse(raw):raw;
 if(!r||Array.isArray(r)||typeof r!=='object'||Object.keys(r).sort().join(',')!=='action,environmentId,ownerId,projectId,schemaVersion,serviceName')
  throw Error('Invalid request fields.');
 if(r.schemaVersion!==1||r.projectId!==PROJECT_ID||r.environmentId!==ENVIRONMENT_ID||r.ownerId!==OWNER_ID||r.serviceName!==PORTAL_NAME)
  throw Error('Exact Galinsky Render project/workspace/environment/service required.');
 if(!['inspect','create'].includes(r.action))throw Error('Only inspect/create actions are allowed.');
 return r;
}
export function createSpec(password){
 if(typeof password!=='string'||password.length<24)throw Error('Missing required 24+ character private password secret.');
 loadPreviewGate({PREVIEW_ACCESS_USER:'preview',PREVIEW_ACCESS_PASSWORD:password});
 return {
  type:'web_service',name:PORTAL_NAME,repo:REPO,branch:'main',
  ownerId:OWNER_ID,environmentId:ENVIRONMENT_ID,autoDeployTrigger:'off',
  envVars:[
   {key:'NODE_VERSION',value:'22.23.4'},
   {key:'NODE_ENV',value:'production'},
   {key:'PUBLIC_ORIGIN',value:PUBLIC_URL},
   {key:'PORTAL_ORIGIN',value:PORTAL_URL},
   {key:'PREVIEW_ACCESS_USER',value:'preview'},
   {key:'PREVIEW_ACCESS_PASSWORD',value:password},
   {key:'SIGNUP_ENABLED',value:'false'},
   {key:'MAIL_PROVIDER',value:'disabled'},
   {key:'STAFF_IDENTITY_ENABLED',value:'false'},
   {key:'PROTECTED_CONTENT_ENABLED',value:'false'},
   {key:'DONATIONS_ENABLED',value:'false'}
  ],
  serviceDetails:{
   runtime:'node',plan:'free',region:'ohio',
   envSpecificDetails:{buildCommand:'npm ci && npm run build:portal',startCommand:'npm start'},
   pullRequestPreviewsEnabled:'no',previews:{generation:'off'}
  }
 };
}
function unwrap(v,k){return v?.[k]||v;}
async function api(method,path,{token,body}={}){
 const result=await fetch('https://api.render.com/v1'+path,{
  method,headers:{Authorization:'Bearer '+token,Accept:'application/json',...(body?{'Content-Type':'application/json'}:{})},
  ...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(30000)
 });
 if(!result.ok)throw Error('Render '+method+' '+path.split('?')[0]+' returned HTTP '+result.status+'. Response withheld.');
 return result.json();
}
async function services(token,client){
 const found=[];let cursor='';
 for(let p=0;p<12;p++){
  const q=new URLSearchParams({limit:'100',ownerId:OWNER_ID});
  if(cursor)q.set('cursor',cursor);
  const batch=await client('GET','/services?'+q,{token});
  if(!Array.isArray(batch))throw Error('Invalid service listing.');
  for(const item of batch){
   const s=unwrap(item,'service');
   if(s?.name===PORTAL_NAME)found.push(s);
  }
  const next=batch.at(-1)?.cursor||'';
  if(!next)return found;
  if(next===cursor)throw Error('Repeated pagination cursor.');
  cursor=next;
 }
 throw Error('Incomplete service listing. No create attempted.');
}
export async function execute(raw,{env=process.env,client=api}={}){
 const request=validateRequest(raw);
 if(env.GITHUB_ACTIONS==='true'&&(env.GITHUB_REPOSITORY!=='neophilism/Galinsky-2028'||env.GITHUB_REF!=='refs/heads/main'))
  throw Error('Only the authorized main branch may run this workflow.');
 const token=env.G28_RENDER_API_KEY||'';
 if(token.length<10)throw Error('Missing private Render API token.');
 const project=unwrap(await client('GET','/projects/'+PROJECT_ID,{token}),'project');
 if(project?.id!==PROJECT_ID||(project.owner?.id||project.ownerId)!==OWNER_ID)throw Error('Project ownership failed verification.');
 const ids=project.environmentIds;
 if(!Array.isArray(ids)||!ids.includes(ENVIRONMENT_ID))throw Error('Project does not contain exact approved environment.');
 const environment=unwrap(await client('GET','/environments/'+ENVIRONMENT_ID,{token}),'environment');
 if(environment?.id!==ENVIRONMENT_ID||environment.projectId!==PROJECT_ID)throw Error('Environment-to-project binding invalid.');
 const previous=await services(token,client);
 if(previous.length>1)throw Error('Duplicate named services already exist.');
 if(request.action==='inspect'){
  console.log(JSON.stringify({projectId:PROJECT_ID,environmentId:ENVIRONMENT_ID,ownerId:OWNER_ID,serviceName:PORTAL_NAME,existingServiceCount:previous.length,
   deploymentPlan:{build:'npm ci && npm run build:portal',start:'npm start',autoDeploy:'off',signup:'disabled pending verified mail',database:'staging Neon supplied as Render secret after create'}}));
  return;
 }
 if(previous.length)throw Error('Portal service already exists: no duplicates are allowed.');
 const spec=createSpec(env.G28_PREVIEW_ACCESS_PASSWORD);
 const created=unwrap(await client('POST','/services',{token,body:spec}),'service');
 if(!validId(created?.id,'srv')||created.name!==PORTAL_NAME||created.ownerId!==OWNER_ID||created.environmentId!==ENVIRONMENT_ID)
  throw Error('Render returned unexpected service placement. Stop and inspect before retrying.');
 console.log(JSON.stringify({created:true,serviceId:created.id,portalUrl:created.serviceDetails?.url||null,
  dashboardUrl:created.dashboardUrl||null,projectId:PROJECT_ID,environmentId:ENVIRONMENT_ID,
  next:'Configure staging Neon DATABASE_URL as a secret; verify the live API readiness. Registration remains OFF.'}));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 execute(await readFile('ops/render-portal-request.json','utf8')).catch(e=>{
  console.error('Exact-project volunteer portal provisioning stopped: '+(e instanceof Error?e.message:'Unknown safe failure'));
  process.exitCode=1;
 });
}
