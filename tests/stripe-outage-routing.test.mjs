import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createPrivatePreviewServer} from '../apps/web/private-preview.mjs';

const accepted=reference=>({accepted:true,reference});
const releaseKeys=['processorAccount','treasurerApproval','electionRules','processorContract','securityReview','reconciliationTest'];
const policyKeys=['stripeRestrictedBusinessApproval','federalCommitteeIdentity','cardSourcePolicy','donorAttestations','directCheckoutRules','recurringControls'];
const env=()=>({
 PREVIEW_ACCESS_PASSWORD:'stripe-outage-test-password-12345678',G28_PUBLIC_MODE:'production',
 DONATIONS_ENABLED:'true',DONATIONS_TREASURER_APPROVED:'true',G28_STRIPE_LIVE_APPROVED:'true',
 STRIPE_SECRET_KEY:'sk_live_12345678901234567890',G28_STRIPE_RETURN_ORIGIN:'https://preview.example.test',
 G28_STRIPE_PRIMARY_LIMIT_CENTS:'50000',G28_STRIPE_GENERAL_LIMIT_CENTS:'50000',
 G28_STRIPE_RELEASE_JSON:JSON.stringify({enabled:true,evidence:{...Object.fromEntries(releaseKeys.map(k=>[k,accepted('test-reviewed-'+k)])),validUntil:'2099-01-01T00:00:00Z'}}),
 G28_STRIPE_POLICY_EVIDENCE_JSON:JSON.stringify(Object.fromEntries(policyKeys.map(k=>[k,accepted('test-reviewed-'+k)])))
});
test('former live automatic checkout cannot dispatch or invent outage evidence even with every release flag',async t=>{
 const directory=await mkdtemp(join(tmpdir(),'stripe-failure-http-'));
 await writeFile(join(directory,'index.html'),'private');
 const signals=[];
 const rotationStore={
  async statuses(){return [{provider_id:'stripe',status:'active'}]},
  async observe(id,entry){signals.push({id,...entry});return {accepted:true,status:signals.length>=3?'quarantined':'active'}}
 };
 const stripeStore={async recordSession(){throw Error('Unexpected Stripe checkout session after rejected transport')}};
 let upstream=0;
 const transport=async()=>{upstream++;return {ok:false,status:503,json:async()=>({})}};
 const server=createPrivatePreviewServer({directory,env:env(),rotationStore,stripeStore,stripeTransport:transport});
 await new Promise(ok=>server.listen(0,'127.0.0.1',ok));
 t.after(async()=>{await new Promise(ok=>server.close(ok));await rm(directory,{force:true,recursive:true});});
 const origin='http://127.0.0.1:'+server.address().port,auth={'Authorization':'Basic '+Buffer.from('preview:'+env().PREVIEW_ACCESS_PASSWORD).toString('base64')};
 for(let i=0;i<3;i++){
  const get=await fetch(origin+'/donate/stripe',{headers:auth});
  assert.equal(get.status,503);
  const body=new URLSearchParams({form_token:'unavailable',amount:'25',frequency:'once',agree:'yes'});
  const post=await fetch(origin+'/donate/stripe/checkout',{
   method:'POST',redirect:'manual',
   headers:{...auth,origin:'https://preview.example.test','content-type':'application/x-www-form-urlencoded'},body:body.toString()
  });
  assert.equal(post.status,503);
 }
 assert.equal(upstream,0);
 assert.equal(signals.length,0);

});
