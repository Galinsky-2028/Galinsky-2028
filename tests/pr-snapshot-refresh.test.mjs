import test from 'node:test';
import assert from 'node:assert/strict';
import {withObservedPullRequests,fetchObservedPullRequests} from '../scripts/refresh-pr-snapshot.mjs';
const observed='2026-10-12T14:00:00.000Z';
const previous=()=>({schemaVersion:1,repository:'Galinsky-2028/Galinsky-2028',
 roadmapVersion:1,planVerified:true,plannedPrCount:2,observedAt:'2026-10-11T12:00:00.000Z',
 units:[{id:'G28-001',title:'Identity',origin:'original',prs:[]},
  {id:'G28-002',title:'Approved exact task',origin:'original',prs:[5]}],
 pullRequests:[]});
const pr=(number,overrides={})=>({
 id:100000+number,number,title:'Actual PR #'+number,html_url:'https://github.com/Galinsky-2028/Galinsky-2028/pull/'+number,
 state:'closed',draft:false,created_at:'2026-10-11T12:00:00Z',
 updated_at:'2026-10-12T12:00:00Z',closed_at:'2026-10-12T12:00:00Z',
 merged_at:'2026-10-12T12:00:00Z',head:{sha:'a'.repeat(40)},base:{ref:'main'},
 merge_commit_sha:'b'.repeat(40),...overrides
});
test('GitHub snapshot refresh preserves exact work-unit mappings without fabricating acceptance',()=>{
 const input=previous(),originalUnits=JSON.stringify(input.units);
 const out=withObservedPullRequests(input,[pr(3),pr(5),pr(9,{state:'open',closed_at:null,merged_at:null})],observed);
 assert.equal(out.plannedPrCount,2);
 assert.equal(JSON.stringify(out.units),originalUnits);
 assert.deepEqual(out.pullRequests.map(x=>x.number),[9,5,3]);
 assert.equal(out.pullRequests[0].state,'open');
 assert.equal(out.pullRequests[0].mergedAt,null);
 assert.equal(out.pullRequests[1].mergedAt,'2026-10-12T12:00:00Z');
 assert.notEqual(out.observedAt,input.observedAt);
});
test('invalid/missing source PR, wrong repo, or impossible merge date cannot be published',()=>{
 assert.throws(()=>withObservedPullRequests(previous(),[pr(3)],observed),/work-unit reference/);
 assert.throws(()=>withObservedPullRequests(previous(),[pr(5),pr(5)],observed),/duplicate/);
 assert.throws(()=>withObservedPullRequests(previous(),[pr(5,{state:'open'})],observed),/inconsistent open/);
 assert.throws(()=>withObservedPullRequests(previous(),[pr(5,{merged_at:'2028-01-01T00:00:00Z'})],observed),/future timestamp/);
 assert.throws(()=>withObservedPullRequests(previous(),[pr(5,{html_url:'https://github.com/evil/repo/pull/5'})],observed),/wrong PR URL/);
});
test('paginated private-repo fetch refuses unauthenticated and non-JSON responses',async()=>{
 await assert.rejects(()=>fetchObservedPullRequests({token:''}),/read token/);
 let called=0;
 const data=await fetchObservedPullRequests({token:'private-fixture-access-token',
  fetchImpl:async(url,opts)=>{
   called++;
   assert.match(url,/api.github.com\/repos\/Galinsky-2028\/Galinsky-2028\/pulls/);
   assert.equal(opts.headers.Authorization,'Bearer private-fixture-access-token');
   return {ok:true,json:async()=>[pr(5)]};
  }});
 assert.equal(called,1);
 assert.equal(data.length,1);
 await assert.rejects(()=>fetchObservedPullRequests({token:'private-fixture-access-token',
  fetchImpl:async()=>({ok:false,status:403})}),/HTTP 403/);
});
