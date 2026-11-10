import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';

const inventory=JSON.parse(readFileSync('security/e2eesa-inventory.json','utf8'));
const status=JSON.parse(readFileSync('security/e2eesa-status.json','utf8'));
test('discovered E2EESA boundaries have unique source paths and no blanket E2EE claims',()=>{
 assert.equal(inventory.coverageComplete,false);
 assert.equal(inventory.reviewed,false);
 assert.equal(inventory.classificationStatus,'preliminary-source-mapped');
 assert.equal(inventory.standardBasis.conformanceArtifactProduced,false);
 assert(inventory.components.length>=12);
 const ids=new Set(inventory.components.map(c=>c.id));
 assert.equal(ids.size,inventory.components.length);
 for(const component of inventory.components){
  assert(component.sourcePaths.length>0);
  assert(component.sourcePaths.every(p=>existsSync(p)),'Evidence paths must exist: '+component.id);
  assert(!component.e2ee.startsWith('certified'));
 }
 const flowIds=inventory.dataFlows.map(x=>x.id);
 assert.equal(new Set(flowIds).size,flowIds.length);
 for(const flow of inventory.dataFlows){
  assert(ids.has(flow.componentId),flow.id);
  assert.equal(flow.claim,'no-production-e2ee-certification');
 }
});
test('intentionally server-readable data cannot masquerade as E2EE',()=>{
 for(const id of ['volunteer-email','volunteer-session','processor-hosted-checkout','campaign-editor','team-events']){
  const c=inventory.components.find(c=>c.id===id);
  assert(c&&c.e2ee.startsWith('not-claimed'),id);
 }
 for(const id of ['protected-recipient-directory','protected-incidents']){
  const c=inventory.components.find(c=>c.id===id);
  assert.equal(c?.status,'implemented-activation-gated');
  assert.equal(c?.e2ee,'client-encrypted-specific-recipient-records');
 }
 assert.equal(status.implementation.complete,false);
 assert.equal(status.testing.complete,false);
 assert.equal(status.independentReview.complete,false);
 assert.equal(status.inventory.reviewed,false);
 assert.equal(status.source.digest,null);
});
