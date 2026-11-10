import {assert,exactKeys,safeText,httpsUrl} from './validation.mjs';
import {roles} from './roles.mjs';
import {activityDecision} from './activity.mjs';
export const operationKinds=['task','training','tool'];
export const operationId=x=>{assert(typeof x==='string'&&/^[a-z][a-z0-9-]{2,79}$/.test(x),'invalid_operation_id','Choose a stable identifier.');return x;};
const text=(x,n=240)=>{const v=safeText(x,n).trim();assert(v,'invalid_operation_text','Complete all required fields.');return v;};
const list=x=>{assert(Array.isArray(x)&&x.length<=24&&new Set(x).size===x.length,'invalid_operation_list','Choose distinct bounded requirements.');return x.map(operationId);};
export function operationDefinition(kind,input){
 assert(operationKinds.includes(kind),'invalid_operation_kind','Unknown operational capability.');
 const common=['id','title','active'];
 const b=exactKeys(input,[...common,...(kind==='task'?['roleId','description','stopConditions','estimatedMinutes','capacity','startsAt','endsAt','materialId','materialRevision','training','restricted','moduleId','moduleRevision','toolId','reviewers']:kind==='training'?['materialId','materialRevision']:['url','purpose','reviewDigest','reviewUntil','capabilityMode','suppressionMode','health'])]);
 assert(typeof b.active==='boolean','invalid_operation_state','Choose an active state.');
 const result={id:operationId(b.id),title:text(b.title,120),active:b.active};
 if(kind==='tool'){
  const url=new URL(httpsUrl(b.url));assert(!url.username&&!url.password&&!url.search&&!url.hash&&!url.port&&url.hostname.includes('.')&&!/^\d+\.\d+\.\d+\.\d+$/.test(url.hostname)&&!url.hostname.endsWith('.local'),'invalid_tool_url','Use the approved stable HTTPS tool destination.');
  assert(/^[a-f0-9]{64}$/.test(b.reviewDigest)&&Number.isFinite(Date.parse(b.reviewUntil)),'invalid_tool_review','Record the source-bound review digest and expiry.');
  assert(['manual-link','provider-api-required'].includes(b.capabilityMode)&&['provider-managed','synchronized-api-required'].includes(b.suppressionMode),'tool_capability_review','Review whether this tool works by manual handoff or requires a provider/suppression API.');
  const health=exactKeys(b.health,['state','checkedAt','validUntil','evidenceDigest']);assert(['available','paused','suppression_failed'].includes(health.state)&&/^[a-f0-9]{64}$/.test(health.evidenceDigest)&&Number.isFinite(Date.parse(health.checkedAt))&&Date.parse(health.validUntil)>Date.parse(health.checkedAt)&&Date.parse(health.validUntil)-Date.parse(health.checkedAt)<=7*86400000,'tool_health_review','Record an actual tool/suppression status review with at most seven days of validity.');
  return {...result,url:url.href,purpose:text(b.purpose,500),reviewDigest:b.reviewDigest,reviewUntil:new Date(b.reviewUntil).toISOString(),capabilityMode:b.capabilityMode,suppressionMode:b.suppressionMode,health:{...health,checkedAt:new Date(health.checkedAt).toISOString(),validUntil:new Date(health.validUntil).toISOString()}};
 }
 assert(Number.isSafeInteger(b.materialRevision)&&b.materialRevision>0,'invalid_material_revision','Pin a current material revision.');
 const materialId=operationId(b.materialId);
 if(kind==='training')return {...result,materialId,materialRevision:b.materialRevision};
 assert(roles.some(r=>r.id===b.roleId)&&typeof b.restricted==='boolean','invalid_task_role','Choose one of the twelve roles and its authorization requirements.');
 assert(!roles.find(r=>r.id===b.roleId).restricted||b.restricted,'restricted_task_role','This role requires a current activity module.');
 assert(Number.isSafeInteger(b.estimatedMinutes)&&b.estimatedMinutes>=1&&b.estimatedMinutes<=1440&&Number.isSafeInteger(b.capacity)&&b.capacity>=1&&b.capacity<=10000,'invalid_task_capacity','Use bounded task time and capacity.');
 assert(Number.isFinite(Date.parse(b.startsAt))&&Date.parse(b.endsAt)>Date.parse(b.startsAt),'invalid_task_window','Choose the availability window.');
 assert(Array.isArray(b.reviewers)&&b.reviewers.length<=16&&new Set(b.reviewers).size===b.reviewers.length&&b.reviewers.every(x=>/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(x)),'invalid_task_reviewers','Use verified staff account identifiers.');
 assert(b.restricted?typeof b.moduleId==='string'&&Number.isSafeInteger(b.moduleRevision)&&b.moduleRevision>0&&typeof b.toolId==='string':b.moduleId===null&&b.moduleRevision===null&&b.toolId===null,'invalid_task_module','Pin the exact module and tool for restricted activity.');
 return {...result,roleId:b.roleId,description:text(b.description,1500),stopConditions:text(b.stopConditions,1000),estimatedMinutes:b.estimatedMinutes,capacity:b.capacity,startsAt:new Date(b.startsAt).toISOString(),endsAt:new Date(b.endsAt).toISOString(),materialId,materialRevision:b.materialRevision,training:list(b.training),restricted:b.restricted,moduleId:b.moduleId===null?null:operationId(b.moduleId),moduleRevision:b.moduleRevision,toolId:b.toolId===null?null:operationId(b.toolId),reviewers:b.reviewers};
}
export function toolReadiness(tool,now=Date.now()){
 const deny=reason=>({allowed:false,reason});
 if(!tool?.active||!Number.isFinite(Date.parse(tool.reviewUntil))||Date.parse(tool.reviewUntil)<=now)return deny('The approved tool is paused or its capability review expired.');
 if(tool.capabilityMode!=='manual-link'||tool.suppressionMode!=='provider-managed')return deny('This tool requires an approved provider or suppression API adapter. None is configured; outreach handoffs remain stopped.');
 if(tool.health?.state!=='available')return deny('Provider or suppression status is paused or failed. Outreach handoffs are stopped.');
 if(!/^[a-f0-9]{64}$/.test(tool.health.evidenceDigest)||!Number.isFinite(Date.parse(tool.health.checkedAt))||Date.parse(tool.health.checkedAt)>now+60000||Date.parse(tool.health.validUntil)<=now||!Number.isFinite(Date.parse(tool.health.validUntil))||Date.parse(tool.health.validUntil)-Date.parse(tool.health.checkedAt)>7*86400000)return deny('The actual tool/suppression health review is missing, stale or outside its approved window.');
 return {allowed:true,reason:'Reviewed manual handoff; opt-outs and retained outreach data stay in the approved provider tool. No automated contact or supporter export is provided.'};
}
export function operationReadiness(task,{material,training=[],attestations=[],tool,module},now=Date.now()){
 const deny=reason=>({allowed:false,reason});
 if(!task.active||Date.parse(task.startsAt)>now||Date.parse(task.endsAt)<=now)return deny('This task is outside its available window.');
 if(!material||material.status!=='published'||material.audience!=='volunteer'||material.revision!==task.materialRevision)return deny('The pinned current guide is unavailable or changed.');
 const completed=training.filter(t=>t.active&&attestations.some(a=>a.trainingId===t.id&&a.revision===t.revision&&!a.revoked&&Date.parse(a.expiresAt)>now)).map(t=>t.id);
 if(task.training.some(id=>!completed.includes(id)))return deny('Complete the current verified training prerequisites.');
 if(task.restricted){
  const toolStatus=toolReadiness(tool,now);if(!toolStatus.allowed)return deny(toolStatus.reason);
  if(!module||module.id!==task.moduleId||module.revision!==task.moduleRevision)return deny('The pinned activity module changed. Recheck current requirements.');
  if(!module.sources?.length||module.sources.some(s=>!Number.isFinite(Date.parse(s.checkedAt))||Date.parse(s.checkedAt)>now+60000||Date.parse(s.checkedAt)<now-30*86400000))return deny('Official source review is no longer current.');
  const decision=activityDecision(module,{jurisdiction:module.jurisdiction,election:module.election,activity:module.activity,tool:task.toolId,completedTraining:completed},new Date(now));
  if(!decision.allowed)return deny(decision.reason);
 }
 return {allowed:true,reason:task.restricted?'Current module, training, guide and tool requirements match.':'This is an approved low-risk task.'};
}
export function operationReport(input){
 const b=exactKeys(input,['count','minutes','feedback']);
 assert(Number.isSafeInteger(b.count)&&b.count>=0&&b.count<=100000&&Number.isSafeInteger(b.minutes)&&b.minutes>=0&&b.minutes<=1440&&['completed','blocked','needs_help'].includes(b.feedback),'invalid_task_report','Use bounded aggregate results and a standard feedback choice.');
 return {...b,provenance:'self_reported'};
}
