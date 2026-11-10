import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {stripeCheckoutPlan,createStripeCheckout,verifyStripeWebhook} from '../packages/core/stripe-campaign.mjs';

const accepted=ref=>({accepted:true,reference:ref});
const release=()=>({
 enabled:true,
 evidence:{
  processorAccount:accepted('staff-approved-account'),
  treasurerApproval:accepted('treasurer-signed-2028'),
  electionRules:accepted('2028-effective-election-config'),
  processorContract:accepted('stripe-restricted-business-approval'),
  securityReview:accepted('security-team-review'),
  reconciliationTest:accepted('processor-approved-ledger-test'),
  validUntil:'2030-01-01T00:00:00Z'
 }
});
const policy=()=>({
 publicOrigin:'https://campaign.example',
 committeeName:'Example Approved Campaign Committee',
 limits:{general:350000,primary:350000},
 recurringEnabled:true,
 evidence:{
  stripeRestrictedBusinessApproval:accepted('stripe-merchant-approval'),
  federalCommitteeIdentity:accepted('committee-id-verified'),
  cardSourcePolicy:accepted('approved-credit-source-handling'),
  donorAttestations:accepted('treasurer-attestation-text'),
  directCheckoutRules:accepted('provider-direct-rules'),
  recurringControls:accepted('approved-cancel-and-reconciliation')
 }
});
const contribution=(overrides={})=>({
 amountCents:2500,frequency:'once',election:'general',clientRef:'test_donation_123',
 attestations:{eligibleResidency:true,ownFunds:true,age18:true,notFederalContractor:true,personalCreditCard:true},
 ...overrides
});
test('Stripe is blocked without independently accepted political-merchant and treasury evidence',()=>{
 const invalid=release();invalid.enabled=false;
 assert.throws(()=>stripeCheckoutPlan({contribution:contribution(),policy:policy(),release:invalid}),/release gates/);
 const p=policy();p.evidence.stripeRestrictedBusinessApproval.accepted=false;
 assert.throws(()=>stripeCheckoutPlan({contribution:contribution(),policy:p,release:release()}),/restricted-business/);
 const missing=policy();delete missing.evidence.cardSourcePolicy;
 assert.throws(()=>stripeCheckoutPlan({contribution:contribution(),policy:missing,release:release()}),/restricted-business/);
});
test('Checkout is processor-hosted, carries no donor PII, and does not mark payment successful',()=>{
 const p=stripeCheckoutPlan({contribution:contribution(),policy:policy(),release:release()});
 assert.equal(p.endpoint,'https://api.stripe.com/v1/checkout/sessions');
 assert.equal(p.mode,'payment');
 assert.equal(p.body.get('payment_method_types[0]'),'card');
 assert.equal(p.body.get('billing_address_collection'),'required');
 assert.equal(p.body.get('line_items[0][price_data][unit_amount]'),'2500');
 assert.equal(p.body.get('custom_fields[0][key]'),'occupation');
 assert.equal(p.body.get('custom_fields[1][key]'),'employer');
 assert.equal(p.body.get('success_url'),'https://campaign.example/donate/manage?checkout=processing');
 assert.equal(p.body.get('customer_creation'),'always');
 assert(!p.body.toString().includes('@'));
 assert(!p.body.toString().includes('card_number'));
 const withTerms=stripeCheckoutPlan({contribution:contribution({termsVersion:'2026-10-13-general-v1'}),policy:policy(),release:release()});
 assert.equal(withTerms.body.get('metadata[terms_version]'),'2026-10-13-general-v1');
});
test('invalid election/amount/attestations/recurrence fail before contacting Stripe',()=>{
 for(const c of [
  contribution({amountCents:0}),
  contribution({amountCents:350001}),
  contribution({election:'none'}),
  contribution({clientRef:'wrong format!'}),
  contribution({attestations:{eligibleResidency:true}}),
  contribution({frequency:'weekly'})
 ])assert.throws(()=>stripeCheckoutPlan({contribution:c,policy:policy(),release:release()}));
 const p=policy();p.recurringEnabled=false;
 assert.throws(()=>stripeCheckoutPlan({contribution:contribution({frequency:'monthly'}),policy:p,release:release()}),/Recurring/);
 const monthly=stripeCheckoutPlan({contribution:contribution({frequency:'monthly'}),policy:policy(),release:release()});
 assert.equal(monthly.body.get('mode'),'subscription');
 assert.equal(monthly.body.get('line_items[0][price_data][recurring][interval]'),'month');
});
test('Stripe request has idempotency and validates hosted response without live network',async()=>{
 const plan=stripeCheckoutPlan({contribution:contribution(),policy:policy(),release:release()});
 let called=0;
 const fake=async(url,opts)=>{
  called++;
  assert.equal(url,'https://api.stripe.com/v1/checkout/sessions');
  assert.equal(opts.headers['Idempotency-Key'],'g28-test_donation_123');
  assert.match(opts.headers.Authorization,/^Bearer sk_test_/);
  assert(opts.body.includes('mode=payment'));
  return {ok:true,json:async()=>({id:'cs_test_ABCDEFGHIJKLM',url:'https://checkout.stripe.com/c/pay/abc'})};
 };
 const result=await createStripeCheckout({plan,secretKey:'sk_test_1234567890123456',transport:fake});
 assert.equal(called,1);
 assert.equal(result.paymentConfirmed,false);
 assert.equal(result.hostedCheckoutUrl,'https://checkout.stripe.com/c/pay/abc');
 await assert.rejects(createStripeCheckout({plan,secretKey:'sk_test_1234567890123456',
  transport:async()=>({ok:true,json:async()=>({id:'cs_test_ABCDEFGHIJKLM',url:'https://evil.example/phish'})})}),/checkout destination/);
});
test('raw-body HMAC webhook verification rejects stale, modified, forged and unsupported events',()=>{
 const secret='whsec_1234567890123456789',now=1770000000;
 const data={id:'evt_123456789',type:'checkout.session.completed',livemode:false,
  created:now,data:{object:{id:'cs_test_ABCDEFGHIJKLM',amount_total:2500,currency:'usd',
   customer_email:'not-part-of-log@example.com'}}};
 const raw=Buffer.from(JSON.stringify(data));
 const signed=(buf,t)=>'t='+t+',v1='+createHmac('sha256',secret).update(String(t)+'.').update(buf).digest('hex');
 const good=verifyStripeWebhook(raw,signed(raw,now),secret,{now});
 assert.equal(good.valid,true);
 assert.equal(good.event.id,data.id);
 assert.equal(good.event.amountTotal,2500);
 assert(!JSON.stringify(good).includes('not-part-of-log'));
 assert.equal(verifyStripeWebhook(raw,signed(raw,now),secret,{now:now+301}).valid,false);
 assert.equal(verifyStripeWebhook(Buffer.from('{}'),signed(raw,now),secret,{now}).valid,false);
 assert.equal(verifyStripeWebhook(raw,'t='+now+',v1='+'0'.repeat(64),secret,{now}).valid,false);
 assert.equal(verifyStripeWebhook(raw,signed(raw,now),secret,{now,tolerance:0}).valid,true);
 const unsupported=Buffer.from(JSON.stringify({...data,type:'customer.created'}));
 assert.equal(verifyStripeWebhook(unsupported,signed(unsupported,now),secret,{now}).reason,'unsupported_event');
});
