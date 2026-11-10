import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {request as httpRequest} from 'node:http';
import {createPrivatePreviewServer} from '../apps/web/private-preview.mjs';
import {stripeSettings,checkoutNonceKey,createCheckoutToken,checkCheckoutToken,parseCheckoutForm,openStripeSession,validDonationOrigin} from '../packages/core/stripe-web-checkout.mjs';
import {CONTRIBUTION_TERMS_VERSION,CONTRIBUTION_TERMS_PATH} from '../packages/core/contribution-terms.mjs';

const password='test-preview-password-long-2026';
const sandbox=()=>({PREVIEW_ACCESS_PASSWORD:password,G28_PUBLIC_MODE:'preview',
 G28_STRIPE_TEST_ENABLED:'true',STRIPE_SECRET_KEY:'sk_test_12345678901234567890',
 G28_STRIPE_RETURN_ORIGIN:'https://preview.example.test',DONATIONS_ENABLED:'false'});
const body=(nonce)=>new URLSearchParams({form_token:nonce,amount:'25.00',
 frequency:'once',agree:'yes'}).toString();
test('sandbox is explicit, isolated from real money and legal release keys',()=>{
 assert.equal(stripeSettings({}),null);
 assert.equal(stripeSettings({...sandbox(),STRIPE_SECRET_KEY:'sk_live_12345678901234567890'}),null);
 assert.equal(stripeSettings({...sandbox(),G28_STRIPE_TEST_ENABLED:'false'}),null);
 assert.equal(stripeSettings({...sandbox(),G28_STRIPE_RETURN_ORIGIN:'http://preview.example.test'}),null);
 assert.equal(stripeSettings({...sandbox(),G28_PUBLIC_MODE:'production',DONATIONS_ENABLED:'true',
  DONATIONS_TREASURER_APPROVED:'true',G28_STRIPE_LIVE_APPROVED:'true'}),null);
 const accepted=Object.fromEntries(['processorAccount','treasurerApproval','electionRules','processorContract','securityReview','reconciliationTest','stripeRestrictedBusinessApproval','federalCommitteeIdentity','cardSourcePolicy','donorAttestations','directCheckoutRules','recurringControls'].map(k=>[k,{accepted:true,reference:'synthetic-copy-of-all-former-release-flags'}]));
 assert.equal(stripeSettings({...sandbox(),G28_PUBLIC_MODE:'production',STRIPE_SECRET_KEY:'sk_live_synthetic_blocked_12345678',DONATIONS_ENABLED:'true',DONATIONS_TREASURER_APPROVED:'true',G28_STRIPE_LIVE_APPROVED:'true',G28_STRIPE_PRIMARY_LIMIT_CENTS:'10000',G28_STRIPE_GENERAL_LIMIT_CENTS:'10000',G28_STRIPE_RELEASE_JSON:JSON.stringify({enabled:true,evidence:{...accepted,validUntil:'2099-01-01T00:00:00Z'}}),G28_STRIPE_POLICY_EVIDENCE_JSON:JSON.stringify(accepted)}),null,'all former flags and approval objects cannot open automatic live capture');
 const cfg=stripeSettings(sandbox());
 assert.equal(cfg.sandbox,true);assert.equal(cfg.live,false);
 assert.equal(cfg.policy.recurringEnabled,false);
});
test('a signed checkout form remains valid across server restarts but not key rotations',()=>{
 const keyA=checkoutNonceKey(sandbox().STRIPE_SECRET_KEY);
 const keyB=checkoutNonceKey(sandbox().STRIPE_SECRET_KEY);
 const keyOther=checkoutNonceKey('sk_test_'+'Z'.repeat(28));
 const stamp=1700000000000;
 const token=createCheckoutToken(keyA,stamp);
 assert.deepEqual(keyA,keyB);
 assert.notDeepEqual(keyA,keyOther);
 assert.match(checkCheckoutToken(keyB,token,stamp),/^attempt_[a-f0-9]{32}$/);
 assert.equal(checkCheckoutToken(keyOther,token,stamp),null);
 assert.equal(checkCheckoutToken(keyB,token,stamp+901000),null);
 assert.throws(()=>createCheckoutToken(keyA,stamp,'forged'),/nonce/);
});
test('signed form tokens expire and enforce exact origin, amount and eligibility',async()=>{
 const cfg=stripeSettings(sandbox()),key=checkoutNonceKey();
 const token=createCheckoutToken(key,1700000000000);
 assert.match(checkCheckoutToken(key,token,1700000000000),/^attempt_[0-9a-f]{32}$/);
 assert.equal(checkCheckoutToken(key,token,1700001000000),null);
 assert.equal(checkCheckoutToken(checkoutNonceKey(),token,1700000000000),null);
 const parsed=parseCheckoutForm(body(token));
 assert.equal(parsed.amountCents,2500);
 assert.equal(parsed.election,'general');
 assert.equal(parsed.termsVersion,CONTRIBUTION_TERMS_VERSION);
 assert(Object.values(parsed.attestations).every(Boolean));
 for(const bad of [
   body(token).replace('agree=yes','agree=no'),
   body(token).replace('&agree=yes',''),
   body(token).replace('25.00','0'),
   body(token).replace('frequency=once','frequency=monthly'),
   body(token)+'&amount=25',
   body(token)+'&election=primary',
   body(token)+'&terms_version=forged',
   body(token)+'&ownFunds=yes',
   body(token)+'&card_number=4111111111111111'])
  assert.throws(()=>parseCheckoutForm(bad));
 await assert.rejects(()=>openStripeSession({raw:body(token),settings:cfg,nonceKey:key,
  request:{headers:{origin:'https://evil.example.test'}}}),/Cross-origin/);
});
test('real-browser origin fallback accepts privacy-suppressed Origin only on the correct host',()=>{
 const cfg=stripeSettings(sandbox());
 const req=headers=>({headers});
 const host='preview.example.test';
 assert.equal(validDonationOrigin(req({host,'sec-fetch-site':'same-origin'}),cfg),true);
 assert.equal(validDonationOrigin(req({host,origin:'null','sec-fetch-site':'same-origin'}),cfg),true);
 assert.equal(validDonationOrigin(req({host}),cfg),true); // authenticated sandbox plus signed token
 assert.equal(validDonationOrigin(req({host,referer:'https://preview.example.test/donate/stripe'}),cfg),true);
 for(const headers of [
  {host:'evil.example.test'},
  {host,origin:'https://evil.example.test'},
  {host,origin:'null','sec-fetch-site':'cross-site'},
  {host,'sec-fetch-site':'same-site'},
  {host,referer:'https://evil.example.test/donate/stripe'}
 ])assert.equal(validDonationOrigin(req(headers),cfg),false);
 assert.equal(validDonationOrigin(req({host}),{...cfg,sandbox:false}),false);
 assert.equal(validDonationOrigin(req({host,'sec-fetch-site':'same-origin'}),{...cfg,sandbox:false}),true);
});
test('sandbox return origin follows deployed Render preview host, not a future domain',()=>{
 const settings=stripeSettings({...sandbox(),G28_STRIPE_RETURN_ORIGIN:'https://galinsky2028.us',
  RENDER_EXTERNAL_URL:'https://galinsky-2028-private-preview.onrender.com'});
 assert.equal(settings.origin,'https://galinsky-2028-private-preview.onrender.com');
});
test('password-protected sandbox returns form and 303 to verified Stripe checkout, no charges',async t=>{
 const dir=await mkdtemp(join(tmpdir(),'stripe-checkout-'));await writeFile(join(dir,'index.html'),'private');
 let called=0;
 const transport=async(url,options)=>{
  called++;assert.equal(url,'https://api.stripe.com/v1/checkout/sessions');
  assert.match(options.headers.Authorization,/^Bearer sk_test_/);
  const req=new URLSearchParams(options.body);
  assert.equal(req.get('mode'),'payment');
  assert.equal(req.get('custom_fields[0][key]'),'occupation');
  assert.equal(req.get('custom_fields[1][key]'),'employer');
  assert.equal(req.get('line_items[0][price_data][unit_amount]'),'2500');
  assert.equal(req.get('metadata[election]'),'general');
  assert.equal(req.get('metadata[terms_version]'),CONTRIBUTION_TERMS_VERSION);
  return {ok:true,json:async()=>({id:'cs_test_ABCDEFGHIJKLM',url:'https://checkout.stripe.com/c/pay/session'})};
 };
 const stored=[];
 const stripeStore={async recordSession(data){stored.push(data);},async receiveSignedWebhook(){return {status:200,outcome:'verified_captured_not_settled'};}};
 const server=createPrivatePreviewServer({directory:dir,env:sandbox(),stripeTransport:transport,stripeStore});
 await new Promise(ok=>server.listen(0,'127.0.0.1',ok));
 t.after(async()=>{await new Promise(ok=>server.close(ok));await rm(dir,{recursive:true,force:true});});
 const root='http://127.0.0.1:'+server.address().port;
 const unauthorized=await fetch(root+'/donate/stripe');
 assert.equal(unauthorized.status,401);assert.equal(called,0);
 const auth={'authorization':'Basic '+Buffer.from('preview:'+password).toString('base64')};
 const get=await fetch(root+'/donate/stripe',{headers:auth});
 assert.equal(get.status,200);
 const page=await get.text();
 assert.match(page,/Stripe TEST MODE/);
 assert.equal((page.match(/type="checkbox"/g)||[]).length,1);
 assert.match(page,/name="agree" value="yes" required/);
 assert.match(page,/I agree to the/);
 assert.match(page,/Stripe will ask for your card details on its own secure checkout page/i);
 assert.match(page,new RegExp('href="'+CONTRIBUTION_TERMS_PATH+'"'));
 assert(!page.includes('name="election"'));
 assert(!page.includes('<fieldset class="eligibility">'));
 assert.match(page,/Federal law requires us to use our best efforts/i);
 const terms=await fetch(root+CONTRIBUTION_TERMS_PATH,{headers:auth});
 assert.equal(terms.status,200);
 const policy=await terms.text();
 assert.match(policy,/I am a U\.S\. citizen or lawfully admitted permanent resident/);
 assert.match(policy,/2028 general election/);
 assert.match(policy,/not a corporate or business credit card/);
 assert.match(policy,new RegExp(CONTRIBUTION_TERMS_VERSION));
 assert.match(get.headers.get('content-security-policy'),/form-action 'self'/);
 const token=page.match(/name="form_token" value="([^"]+)"/)?.[1];
 assert(token);
 const bad=await fetch(root+'/donate/stripe/checkout',{method:'POST',redirect:'manual',
  headers:{...auth,origin:'https://attacker.example', 'content-type':'application/x-www-form-urlencoded'},
  body:body(token)});
 assert.equal(bad.status,400);assert.equal(called,0);
 // A URL-encoded test form never contains real card numbers.
 // Use Node's low-level HTTP client rather than fetch: fetch may inject its
 // own Origin/Fetch Metadata, so it cannot model a privacy-suppressed browser.
 const privacy=await new Promise((resolve,reject)=>{
  const u=new URL(root+'/donate/stripe/checkout');
  const payload=body(token);
  const req=httpRequest({hostname:u.hostname,port:u.port,path:u.pathname,method:'POST',headers:{
   ...auth,Host:'preview.example.test','Sec-Fetch-Site':'same-origin',
   'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(payload)
  }},res=>{
   res.resume();res.on('end',()=>resolve({status:res.statusCode,location:res.headers.location}));
  });
  req.on('error',reject);req.end(payload);
 });
 assert.equal(privacy.status,303);assert.equal(privacy.location,'https://checkout.stripe.com/c/pay/session');
 const ok=await fetch(root+'/donate/stripe/checkout',{method:'POST',redirect:'manual',
  headers:{...auth,origin:'https://preview.example.test','content-type':'application/x-www-form-urlencoded'},
  body:body(token)});
 assert.equal(ok.status,303);assert.equal(ok.headers.get('location'),'https://checkout.stripe.com/c/pay/session');
 assert.equal(called,2);
 assert.equal(stored.length,2);
 assert.equal(stored[0].amountCents,2500);
 assert.equal(stored[0].livemode,false);
 assert.equal(stored[0].election,'general');
 assert.equal(stored[0].termsVersion,CONTRIBUTION_TERMS_VERSION);
 assert.equal((await ok.text()),'');
});
test('a stale checkout token shows a safe recovery page rather than an unhelpful text error',async t=>{
 const dir=await mkdtemp(join(tmpdir(),'stripe-token-expired-'));
 await writeFile(join(dir,'index.html'),'private');
 let requests=0;
 const server=createPrivatePreviewServer({directory:dir,env:sandbox(),
  stripeStore:{async recordSession(){throw Error('Checkout may not reach DB');}},
  stripeTransport:async()=>{requests++;throw Error('Checkout may not reach Stripe');}});
 await new Promise(ok=>server.listen(0,'127.0.0.1',ok));
 t.after(async()=>{await new Promise(ok=>server.close(ok));await rm(dir,{recursive:true,force:true});});
 const origin='http://127.0.0.1:'+server.address().port;
 const auth={Authorization:'Basic '+Buffer.from('preview:'+password).toString('base64')};
 const oldKey=checkoutNonceKey('sk_test_'+'Z'.repeat(28));
 const badToken=createCheckoutToken(oldKey);
 const response=await fetch(origin+'/donate/stripe/checkout',{method:'POST',redirect:'manual',
  headers:{...auth,Origin:'https://preview.example.test','Content-Type':'application/x-www-form-urlencoded'},
  body:body(badToken)});
 assert.equal(response.status,400);
 assert.match(response.headers.get('content-type'),/text\/html/);
 const page=await response.text();
 assert.match(page,/form was opened before a recent update or has expired/i);
 assert.match(page,/href="\/donate\/stripe"/);
 assert.equal(requests,0);
});
test('Stripe test mode is unconfigured by default and cannot leak live donation routes',async t=>{
 const dir=await mkdtemp(join(tmpdir(),'stripe-disabled-'));await writeFile(join(dir,'index.html'),'private');
 const server=createPrivatePreviewServer({directory:dir,env:{PREVIEW_ACCESS_PASSWORD:password,G28_PUBLIC_MODE:'preview'}});
 await new Promise(ok=>server.listen(0,'127.0.0.1',ok));
 t.after(async()=>{await new Promise(ok=>server.close(ok));await rm(dir,{recursive:true,force:true});});
 const response=await fetch('http://127.0.0.1:'+server.address().port+'/donate/stripe',{headers:{authorization:'Basic '+Buffer.from('preview:'+password).toString('base64')}});
 assert.equal(response.status,503);
 assert.match(await response.text(),/No payment was attempted/);
});
