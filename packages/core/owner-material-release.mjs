import {createHash} from 'node:crypto';
import {validateMaterialRelease} from './material-publication.mjs';
import {validateSignedMaterialRelease} from './staff-review.mjs';

export const OWNER_REVIEW_MODE='owner-authorized-ai-reviewed';
function canonical(value){
 if(Array.isArray(value))return value.map(canonical);
 if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));
 return value;
}
export function ownerMaterialDigest(record){return createHash('sha256').update(JSON.stringify(canonical(record))).digest('hex');}
export function validateConfiguredMaterialRelease(records,{staffRegistry,ownerRelease,now=Date.now()}={}){
 const ownerDirected=Array.isArray(records)&&records.some(m=>m.publication?.mode===OWNER_REVIEW_MODE);
 if(!ownerDirected)return validateSignedMaterialRelease(records,staffRegistry,{now});
 validateMaterialRelease(records);
 const r=ownerRelease;
 if(!r||r.schemaVersion!==1||r.mode!==OWNER_REVIEW_MODE||r.authorizedBy!=='campaign-owner'||
  r.instruction!=='Use an owner-authorized, AI-reviewed release'||r.scope!=='volunteer-reading-only'||
  r.fieldActivitiesAuthorized!==false||r.independentHumanReview!==false||r.certificationClaim!==false||
  typeof r.releaseId!=='string'||!/^owner-[0-9]{8}-[a-z0-9-]+$/.test(r.releaseId)||
  !/^[a-f0-9]{40}$/.test(r.sourceCommit||'')||
  r.sourceDirectory!=='content/materials/source-edition-1'||
  r.reviewReport!=='docs/evidence/VOLUNTEER_MATERIAL_REVIEW_20261109.md'||
  !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(r.authorizedAt||'')||
  !Number.isFinite(Date.parse(r.authorizedAt))||Date.parse(r.authorizedAt)>now+300000||
  Date.parse(r.authorizedAt)<now-90*86400000||!Array.isArray(r.materials)||r.materials.length!==records.length)
  throw Error('Exact owner-authorized AI review release is required; staff signatures are not inferred.');
 const approved=new Map();
 for(const entry of r.materials){
  if(!entry||approved.has(entry.id)||!Number.isSafeInteger(entry.revision)||! /^[a-f0-9]{64}$/.test(entry.sha256||''))throw Error('Invalid owner release digest manifest.');
  approved.set(entry.id,entry);
 }
 for(const m of records){
  const entry=approved.get(m.id);
  if(m.publication?.mode!==OWNER_REVIEW_MODE||m.publication.releaseId!==r.releaseId||
   m.author!=='campaign-owner-source'||m.review.approvedBy!=='codex-ai-editorial-review'||
   m.review.method!=='ai-editorial-review'||m.review.at!==r.authorizedAt||
   entry?.revision!==m.revision||entry.sha256!==ownerMaterialDigest(m))
   throw Error('Owner release does not approve these exact reviewed material bytes.');
 }
 return records;
}
