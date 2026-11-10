import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateConfiguredMaterialRelease,ownerMaterialDigest} from '../packages/core/owner-material-release.mjs';
const records=JSON.parse(readFileSync('content/materials/current.json','utf8'));
const release=JSON.parse(readFileSync('content/materials/owner-release.json','utf8'));
const options=()=>({ownerRelease:structuredClone(release),staffRegistry:{version:1,keys:[]}});
test('the exact owner-directed release provides nineteen attributed guides without inventing human signatures',()=>{
 assert.equal(validateConfiguredMaterialRelease(records,options()).length,19);
 assert.equal(records.filter(m=>m.category==='role').length,12);
 assert.deepEqual(records.filter(m=>m.category==='policy').map(m=>m.id),['policy-kirk-evers','policy-garden','policy-cornerstone']);
 for(const record of records){assert(record.body.includes('owner-authorized, AI-reviewed'));assert(record.body.includes('never substitutes'));assert.equal(record.approvals,undefined);}
});
test('body, review, provenance, scope, authorization and mixed-mode tampering cannot reuse approval',()=>{
 for(const mutate of [m=>{m[0].body+='Changed';},m=>{m[0].review.approvedBy=m[0].author;},m=>{m[0].provenance[0].sha256='0'.repeat(64);},m=>{delete m[0].publication;}]){
  const copy=structuredClone(records);mutate(copy);assert.throws(()=>validateConfiguredMaterialRelease(copy,options()));
 }
 for(const mutate of [r=>{r.fieldActivitiesAuthorized=true;},r=>{r.independentHumanReview=true;},r=>{r.instruction='A source import is approval';},r=>{r.materials.push(r.materials[0]);},r=>{r.authorizedAt='2099-01-01T00:00:00.000Z';}]){
  const opt=options();mutate(opt.ownerRelease);assert.throws(()=>validateConfiguredMaterialRelease(records,opt));
 }
 assert.throws(()=>validateConfiguredMaterialRelease(records,{staffRegistry:{version:1,keys:[]}}));
});
test('ordinary unsigned records do not gain the owner exception',()=>{
 const copy=structuredClone(records);for(const m of copy)delete m.publication;
 assert.throws(()=>validateConfiguredMaterialRelease(copy,options()));
 assert.match(ownerMaterialDigest(records[0]),/^[a-f0-9]{64}$/);
 const reordered=Object.fromEntries(Object.entries(records[0]).reverse());
 assert.equal(ownerMaterialDigest(reordered),ownerMaterialDigest(records[0]),'Database JSON key order does not change approved content');
});
