import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
import {parsePrRegistry} from '../registry/pr-contract.mjs';

const registry=parsePrRegistry(readFileSync('registry/prs.json','utf8'),'Galinsky-2028/Galinsky-2028').document;
const plan=JSON.parse(readFileSync('docs/PR_REGISTER.json','utf8'));
const delivery=JSON.parse(readFileSync('docs/evidence/DELIVERY.json','utf8'));
const prs=new Map(registry.pullRequests.map(pr=>[pr.number,pr]));
const statuses=['completed','implemented','in_progress','not_started'];

test('all approved work-package IDs and statuses agree across the canonical and human-readable registries',()=>{
 const total=registry.units.length;
 assert.ok(total>0,'An empty registry is not a verified plan');
 assert.equal(plan.packages.length,total);
 assert.equal(registry.plannedPrCount,total);
 assert.equal(plan.planned_work_packages,total);
 for(let i=0;i<total;i++){
  const n=i+1, unit=registry.units[i],pkg=plan.packages[i];
  assert.equal(unit.id,'G28-'+String(n).padStart(3,'0'));
  assert.equal(pkg.id,'G28-'+String(n).padStart(2,'0'));
  assert.equal(unit.status,pkg.status,unit.id);
  assert.ok(statuses.includes(unit.status),unit.id);
  assert.deepEqual([...(unit.prs||[])].sort((a,b)=>a-b),[...(pkg.github_prs||[])].sort((a,b)=>a-b),unit.id);
  assert.equal(pkg.acceptance_review?.status,pkg.status,unit.id);
  assert.ok(typeof pkg.implementation_note==='string'&&pkg.implementation_note.length>25,unit.id);
  assert.ok(typeof pkg.acceptance_review?.report==='string'&&existsSync(pkg.acceptance_review.report),
   unit.id+' must have a checked-in acceptance report');
  if(unit.status==='completed'){
   assert.ok(unit.prs.length>0,unit.id+' needs explicit merged PR evidence');
   assert.match(unit.reviewedSourceSha,/^[0-9a-f]{40}$/,unit.id);
   assert.equal(pkg.acceptance_review.reviewed_source_sha,unit.reviewedSourceSha,unit.id);
   assert.ok(Number.isFinite(Date.parse(unit.acceptedAt)),unit.id);
   assert.ok(unit.acceptanceSummary?.length>25,unit.id);
   assert.ok(unit.evidence?.length>0,unit.id);
   for(const source of unit.evidence)assert.ok(existsSync(source),unit.id+' missing '+source);
   for(const number of unit.prs)assert.ok(prs.get(number)?.mergedAt,unit.id+' maps nonmerged PR '+number);
   assert.ok(!unit.prs.some(number=>(unit.contributingPrs||[]).includes(number)),unit.id);
  }else if(unit.status==='implemented'){
   assert.equal(unit.implementationReview?.implementation,'implemented',unit.id);
   assert.equal(unit.implementationReview?.softwareGap,null,unit.id);
   assert.ok(unit.implementationReview?.sourceFiles.length,unit.id);
   assert.ok(unit.implementationReview?.activationRequirement,unit.id);
  }else{
   assert.equal(unit.implementationReview?.implementation,'remaining_implementation',unit.id);
   assert.ok(unit.implementationReview?.softwareGap,unit.id);
   assert.ok(unit.acceptanceBlocker?.length>25,unit.id+' needs an explicit blocker');
   // In-flight PRs may be mapped without pretending they are already accepted.
   for(const number of unit.prs)assert.equal(prs.get(number)?.state,'open',
    unit.id+' maps a closed PR as fully accepted while incomplete');
  }
 }
});

test('status totals, PR observations and deployment counters are derived instead of frozen to one audit',()=>{
 const counts=Object.fromEntries(statuses.map(s=>[s,plan.packages.filter(p=>p.status===s).length]));
 assert.equal(Object.values(counts).reduce((a,b)=>a+b,0),registry.units.length);
 assert.equal(plan.implemented_packages,counts.completed+counts.implemented);
 assert.equal(plan.merged_packages,counts.completed);
 assert.equal(plan.deployed_packages,plan.packages.filter(p=>p.status==='completed'&&p.acceptance_review.scoped_deployed).length);
 assert.equal(delivery.full_work_packages_accepted,counts.completed);
 assert.equal(delivery.last_acceptance_audit.completed,counts.completed);
 assert.equal(delivery.last_acceptance_audit.implemented,counts.implemented);
 assert.equal(delivery.implemented_software_packages,counts.completed+counts.implemented);
 assert.equal(delivery.last_acceptance_audit.in_progress,counts.in_progress);
 assert.equal(delivery.last_acceptance_audit.not_started,counts.not_started);
 assert.equal(registry.pullRequests.filter(pr=>pr.mergedAt).length,delivery.last_acceptance_audit.observed_merged_prs);
 assert.equal(registry.pullRequests.filter(pr=>pr.state==='closed'&&!pr.mergedAt).length,delivery.last_acceptance_audit.observed_closed_unmerged_prs);
 assert.equal(registry.pullRequests.filter(pr=>pr.state==='open').length,delivery.last_acceptance_audit.observed_open_prs||0);
 assert.equal(prs.size,registry.pullRequests.length);
 assert.equal(typeof delivery.production_release_verified,'boolean');
 // Accepting the public-launch package is necessary before claiming a verified production release.
 if(delivery.production_release_verified)
  assert.equal(registry.units.find(unit=>unit.id==='G28-059')?.status,'completed');
});


test('merged pull requests are accepted PRs independently of full package completion',()=>{
 const accepted=registry.pullRequests.filter(pr=>pr.mergedAt);
 assert.equal(plan.accepted_pull_requests,accepted.length);
 assert.equal(delivery.accepted_merged_prs,accepted.length);
 assert.equal(plan.accepted_prs_observed_at,registry.observedAt);
 assert.equal(delivery.accepted_prs_observed_at,registry.observedAt);
 assert.ok(accepted.length>plan.merged_packages,'PR acceptance must not be constrained by package completion count');
 const merged=new Set(accepted.map(pr=>pr.number));
 const acceptedContributions=registry.units.flatMap(unit=>unit.contributingPrs||[]).filter(n=>merged.has(n));
 assert.ok(acceptedContributions.length>0,'Accepted merged contributions to unfinished packages must be recognized');
 // Feature scope may remain open, but the contributing PR is accepted as a PR.
 assert.equal(delivery.full_work_packages_accepted,registry.units.filter(unit=>unit.status==='completed').length);
 assert.equal(registry.pullRequests.some(pr=>pr.state==='open'&&pr.mergedAt),false);
});
