#!/usr/bin/env node
/**
 * Operator-only Render project deployment.
 * No production changes occur unless a human manually dispatches "create".
 * Do not use the workspace-only connector for this application.
 */
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadPreviewGate} from '../packages/core/preview-gate.mjs';

export const TARGET_PROJECT_ID='prj-db57fnm7bikc739783q0';
export const TARGET_SERVICE='galinsky-2028-private-preview';
export const TARGET_REPO='https://github.com/neophilism/Galinsky-2028';

export function chooseEnvironment(project,environments,requestedId=''){
 if(!project||project.id!==TARGET_PROJECT_ID)throw new Error('Render project does not match the authorized Galinsky project.');
 if(!Array.isArray(environments)||environments.length===0)throw new Error('The requested Render project has no environments.');
 const ids=new Set();
 for(const e of environments){
  if(!e||typeof e.id!=='string'||e.projectId!==TARGET_PROJECT_ID||ids.has(e.id))
   throw new Error('Render environment data is inconsistent with the authorized project.');
  ids.add(e.id);
 }
 if(requestedId){
  const match=environments.find(e=>e.id===requestedId);
  if(!match)throw new Error('The specified environment does not belong to the authorized Galinsky project.');
  return match;
 }
 if(environments.length===1)return environments[0];
 throw new Error('The project has multiple environments. Run inspect and specify a verified environment ID.');
}

export function createPreviewSpec(ownerId,environmentId,password){
 if(typeof ownerId!=='string'||!/^(tea|usr|own)-[a-z0-9-]+$/.test(ownerId))
  throw new Error('Missing or invalid Render project owner ID.');
 if(typeof environmentId!=='string'||!/^evm-[a-z0-9-]+$/.test(environmentId))
  throw new Error('A verified Render environment ID is required.');
 if(typeof password!=='string'||password.length<24)
  throw new Error('Set a private 24+ character G28_PREVIEW_ACCESS_PASSWORD GitHub Actions secret before creating the service.');
 loadPreviewGate({PREVIEW_ACCESS_USER:'preview',PREVIEW_ACCESS_PASSWORD:password});
 return {
  type:'web_service',
  name:TARGET_SERVICE,
  ownerId,
  environmentId,
  repo:TARGET_REPO,
  branch:'main',
  autoDeployTrigger:'off',
  envVars:[
   {key:'NODE_VERSION',value:'22.23.4'},
   {key:'G28_PUBLIC_MODE',value:'preview'},
   {key:'PREVIEW_ACCESS_USER',value:'preview'},
   {key:'PREVIEW_ACCESS_PASSWORD',value:password}
  ],
  serviceDetails:{
   runtime:'node',plan:'free',region:'ohio',
   envSpecificDetails:{buildCommand:'npm ci && npm run build:web',startCommand:'npm run preview:serve'},
   pullRequestPreviewsEnabled:'no',
   previews:{generation:'off'}
  }
 };
}

function unwrap(resource,field){return resource?.[field]||resource;}
// Only fixed, safe classifications may appear in public CI logs. Render may
// echo the repository's confidential password or request body in error text.
export function classifyRenderRejection(raw){
 const source=typeof raw==='string'?raw.slice(0,16384).toLowerCase():'';
 const probes=[
  ['plan','plan'],['free','free_tier'],['billing','billing'],['payment','billing'],
  ['limit','quota_limit'],['quota','quota_limit'],
  ['service details','service_details'],['servicedetails','service_details'],
  ['envspecificdetails','build_start_configuration'],['buildcommand','build_start_configuration'],['startcommand','build_start_configuration'],
  ['runtime','runtime'],['region','region'],['repository','git_repository'],['repo','git_repository'],['github','git_provider'],
  ['environment','environment'],['owner','ownership'],['workspace','workspace'],
  ['envvars','environment_variables'],['secret','environment_variables'],
  ['previews','preview_configuration'],['autodeploy','automatic_deployment'],
  ['unauthorized','authorization'],['permission','authorization'],['access','authorization'],
  ['already exists','duplicate_name'],['name','service_name'],['invalid','invalid_request'],
  ['not found','not_found'],['not supported','unsupported'],['unsupported','unsupported']
 ];
 const tags=[...new Set(probes.filter(([needle])=>source.includes(needle)).map(([,tag])=>tag))].slice(0,10);
 return tags.length?tags.join(','):'unclassified';
}
async function api(method,path,{token,body}={}){
 const response=await fetch('https://api.render.com/v1'+path,{
  method,
  headers:{Accept:'application/json',Authorization:'Bearer '+token,...(body?{'Content-Type':'application/json'}:{})},
  ...(body?{body:JSON.stringify(body)}:{})
 });
 if(!response.ok){
  const raw=await response.text().catch(()=>'');
  throw new Error('Render API '+method+' failed (HTTP '+response.status+'; safe categories: '+classifyRenderRejection(raw)+'). Request and response values withheld.');
 }
 return response.json();
}
async function findExisting(token,client=api){
 const found=[];let cursor='';
 for(let page=0;page<10;page++){
  const params=new URLSearchParams({limit:'100'});
  if(cursor)params.set('cursor',cursor);
  const result=await client('GET','/services?'+params.toString(),{token});
  if(!Array.isArray(result))throw new Error('Unexpected Render service listing; refusing to create.');
  for(const row of result){
   const service=unwrap(row,'service');
   if(service?.name===TARGET_SERVICE)found.push(service);
  }
  cursor=result.length?result[result.length-1]?.cursor||'':'';
  if(!cursor)return found;
 }
 throw new Error('Service listing was truncated; refusing to create a potentially duplicate service.');
}

export async function run({env=process.env,client=api}={}){
 const mode=env.G28_RENDER_ACTION||'inspect';
 if(!['inspect','create'].includes(mode))throw new Error('Action must be inspect or create.');
 const token=env.G28_RENDER_API_KEY||'';
 if(token.length<10)throw new Error('Add a Render API key in GitHub Actions as G28_RENDER_API_KEY.');
 const project=unwrap(await client('GET','/projects/'+TARGET_PROJECT_ID,{token}),'project');
 if(project?.id!==TARGET_PROJECT_ID)throw new Error('Render returned a different project; refusing action.');
 const ownerId=project.owner?.id||project.ownerId;
 if(!ownerId)throw new Error('Render project owner information is missing.');
 const environmentIds=project.environmentIds;
 if(!Array.isArray(environmentIds)||environmentIds.length===0)
  throw new Error('The exact Render project has no discoverable environments. Check its settings.');
 const environments=[];
 for(const environmentId of environmentIds){
  if(typeof environmentId!=='string'||!/^evm-[a-z0-9-]+$/.test(environmentId))
   throw new Error('Unrecognized Render environment identifier.');
  const entry=unwrap(await client('GET','/environments/'+environmentId,{token}),'environment');
  environments.push(entry);
 }
 const verifiedEnvironments=environments.map(e=>({id:e.id,name:e.name,projectId:e.projectId}));
 const summary={
  project:{id:project.id,name:project.name,workspaceId:ownerId,workspaceName:project.owner?.name||null},
  environments:verifiedEnvironments
 };
 if(mode==='inspect'){console.log(JSON.stringify(summary,null,2));return summary;}
 const chosen=chooseEnvironment(project,verifiedEnvironments,env.G28_RENDER_ENVIRONMENT_ID||'');
 // Validate secret and entire create request BEFORE any write operation.
 const body=createPreviewSpec(ownerId,chosen.id,env.G28_PREVIEW_ACCESS_PASSWORD);
 const existing=await findExisting(token,client);
 if(existing.length)throw new Error('A service named '+TARGET_SERVICE+' already exists. No service created; inspect its project and configuration.');
 const created=unwrap(await client('POST','/services',{token,body}),'service');
 if(!created||!/^srv-[a-z0-9-]+$/.test(created.id))
  throw new Error('Render did not return a valid service ID. Check the target project before retrying.');
 if(created.environmentId!==chosen.id||created.ownerId!==ownerId||created.name!==TARGET_SERVICE)
  throw new Error('Render service placement verification failed. Inspect the created service before continuing.');
 const output={created:true,projectId:TARGET_PROJECT_ID,environmentId:chosen.id,
  serviceId:created.id,serviceUrl:created.serviceDetails?.url||null,
  dashboardUrl:created.dashboardUrl||null,
  autoDeploy:'off',protectedBy:'PREVIEW_ACCESS_PASSWORD'};
 console.log(JSON.stringify(output,null,2));
 return output;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 run().catch(error=>{console.error('Render project operation stopped: '+error.message);process.exitCode=1;});
}
