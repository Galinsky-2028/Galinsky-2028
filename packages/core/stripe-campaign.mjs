// Stripe political-campaign adapter. NEVER enables itself: the campaign's
// restricted-business onboarding, treasury/legal rules and reliable finance
// ledger must be signed off separately before any live checkout route exists.
import {createHmac,timingSafeEqual} from 'node:crypto';
import {assert,DomainError} from './validation.mjs';
import {releaseDecision} from './finance.mjs';

const CHECKOUT_ENDPOINT='https://api.stripe.com/v1/checkout/sessions';
const SESSION_ID=/^cs_(test|live)_[A-Za-z0-9]{10,}$/;
const REF_ID=/^[a-z0-9][a-z0-9_-]{5,63}$/;
const ELECTION=/^(primary|general)$/;
const EVENT_TYPES=new Set([
 'checkout.session.completed','checkout.session.async_payment_succeeded',
 'checkout.session.async_payment_failed','checkout.session.expired','payment_intent.succeeded',
 'payment_intent.payment_failed','charge.refunded','charge.dispute.created',
 'invoice.paid','invoice.payment_failed','customer.subscription.deleted',
 'refund.created','refund.updated','refund.failed','charge.dispute.closed'
]);

function safeUrl(origin,path){
 const u=new URL(origin);
 assert(u.protocol==='https:'&&u.hostname.includes('.')&&!u.username&&!u.password&&!u.port&&!u.hash&&!u.search,
  'stripe_url','A verified HTTPS campaign origin is required.');
 return new URL(path,u).toString();
}
export function stripeCheckoutPlan({contribution,policy,release}){
 const gate=releaseDecision(release);
 assert(gate.allowed,'donations_unapproved','Fundraising has not passed the treasurer and system release gates.',503);
 const e=policy?.evidence;
 for(const key of ['stripeRestrictedBusinessApproval','federalCommitteeIdentity',
   'cardSourcePolicy','donorAttestations','directCheckoutRules','recurringControls']){
  assert(e?.[key]?.accepted===true&&typeof e[key].reference==='string'&&e[key].reference.trim(),
   'donations_unapproved',"Stripe's restricted-business and contribution compliance approvals are incomplete.",503);
 }
 assert(contribution&&typeof contribution==='object'&&!Array.isArray(contribution),
  'invalid_contribution','Invalid contribution request.');
 const {amountCents,frequency,election,clientRef,attestations,termsVersion}=contribution;
 assert(Number.isSafeInteger(amountCents)&&amountCents>0&&amountCents<=100000000,
  'invalid_amount','Enter a permitted positive amount in cents.');
 assert(frequency==='once'||frequency==='monthly','invalid_frequency','Choose one-time or monthly giving.');
 assert(ELECTION.test(election),'invalid_election','Choose a valid election designation.');
 assert(REF_ID.test(clientRef),'invalid_reference','A valid campaign-created reference is required.');
 assert(attestations&&Object.values(attestations).length===5&&
  ['eligibleResidency','ownFunds','age18','notFederalContractor','personalCreditCard'].every(k=>attestations[k]===true),
  'eligibility','The campaign eligibility attestations are required.');
 const limits=policy?.limits;
 assert(limits&&Number.isSafeInteger(limits[election])&&limits[election]>=amountCents,
  'limit_review','No approved remaining contribution limit is available for this election.',503);
 assert(policy?.committeeName&&typeof policy.committeeName==='string'&&policy.committeeName.length<180,
  'committee_unverified','The committee name must be approved.',503);
 if(frequency==='monthly')assert(policy.recurringEnabled===true&&
  e.recurringControls.accepted===true,'recurrence_unapproved','Recurring contributions are not authorized.',503);
 // Stripe Checkout accepts the "card" method family (including debit) and
 // therefore is NOT proof of a personal credit card funding source. The
 // independent cardSourcePolicy evidence must address this provider limitation.
 const params=new URLSearchParams();
 const fields={
  mode:frequency==='monthly'?'subscription':'payment',
  'payment_method_types[0]':'card',
  'line_items[0][price_data][currency]':'usd',
  'line_items[0][price_data][unit_amount]':String(amountCents),
  'line_items[0][price_data][product_data][name]':'Campaign contribution to '+policy.committeeName,
  'line_items[0][quantity]':'1',
  'client_reference_id':clientRef,
  'billing_address_collection':'required',
  'success_url':safeUrl(policy.publicOrigin,'/donate/manage?checkout=processing'),
  'cancel_url':safeUrl(policy.publicOrigin,'/donate/?checkout=cancelled'),
  'metadata[client_reference]':clientRef,
  'metadata[election]':election,
  'metadata[frequency]':frequency,
  'custom_fields[0][key]':'occupation',
  'custom_fields[0][type]':'text',
  'custom_fields[0][label][type]':'custom',
  'custom_fields[0][label][custom]':'Occupation or not employed',
  'custom_fields[0][optional]':'false',
  'custom_fields[1][key]':'employer',
  'custom_fields[1][type]':'text',
  'custom_fields[1][label][type]':'custom',
  'custom_fields[1][label][custom]':'Employer or not employed',
  'custom_fields[1][optional]':'false'
 };
 if(frequency==='monthly')fields['line_items[0][price_data][recurring][interval]']='month';
 else fields.customer_creation='always';
 // The browser cannot select or forge the terms version. Record the server's
 // version in Stripe metadata so the eventual signed event has audit context.
 if(termsVersion!==undefined){
  assert(typeof termsVersion==='string'&&/^[0-9]{4}-[0-9]{2}-[0-9]{2}-[a-z0-9-]{4,40}$/.test(termsVersion),
   'invalid_terms_version','Invalid contribution terms version.');
  fields['metadata[terms_version]']=termsVersion;
 }
 for(const [key,value] of Object.entries(fields))params.set(key,value);
 return {endpoint:CHECKOUT_ENDPOINT,method:'POST',body:params,
  idempotencyKey:'g28-'+clientRef,mode:fields.mode,amountCents,
  processingUrl:fields.success_url};
}
export async function createStripeCheckout({plan,secretKey,transport=fetch,signal}){
 assert(typeof secretKey==='string'&&/^(sk_test|sk_live)_[A-Za-z0-9_]{12,}$/.test(secretKey),
  'stripe_credentials','Valid server-side Stripe credentials are required.',503);
 assert(plan?.endpoint===CHECKOUT_ENDPOINT&&plan.method==='POST'&&plan.body instanceof URLSearchParams,
  'invalid_plan','Checkout plan must be constructed by the approved adapter.');
 let response;
 try{response=await transport(CHECKOUT_ENDPOINT,{
  method:'POST',headers:{
   'Authorization':'Bearer '+secretKey,
   'Content-Type':'application/x-www-form-urlencoded',
   'Idempotency-Key':plan.idempotencyKey
  },
  body:plan.body.toString(),signal
 });}catch{throw new DomainError('checkout_unavailable','Stripe Checkout is temporarily unavailable. No payment has been confirmed.',503);}
 if(!response.ok)throw new DomainError('checkout_unavailable',
  'Stripe Checkout could not be started. Please try later; no donation has been confirmed.',503);
 const data=await response.json();
 assert(typeof data?.id==='string'&&SESSION_ID.test(data.id),'invalid_provider_response','Unexpected checkout response.',503);
 const url=new URL(data.url);
 assert(url.protocol==='https:'&&url.hostname==='checkout.stripe.com'&&!url.username&&!url.password,
  'invalid_provider_response','Unexpected checkout destination.',503);
 return {sessionId:data.id,hostedCheckoutUrl:url.toString(),paymentConfirmed:false};
}
export function verifyStripeWebhook(raw,signature,secret,{now=Math.floor(Date.now()/1000),tolerance=300}={}){
 if(!Buffer.isBuffer(raw)||raw.length===0||raw.length>1024*1024||
   typeof signature!=='string'||signature.length>4096||
   typeof secret!=='string'||!/^whsec_[A-Za-z0-9_]{10,}$/.test(secret))
  return {valid:false,reason:'invalid_signature'};
 const parts=signature.split(',');
 const timestamp=parts.filter(x=>/^t=\d+$/.test(x)).map(x=>Number(x.slice(2)));
 const candidates=parts.filter(x=>/^v1=[a-f0-9]{64}$/i.test(x)).map(x=>x.slice(3));
 if(timestamp.length!==1||!Number.isSafeInteger(timestamp[0])||candidates.length===0||
    Math.abs(now-timestamp[0])>tolerance)return {valid:false,reason:'invalid_signature'};
 const digest=createHmac('sha256',secret).update(String(timestamp[0])+'.').update(raw).digest();
 let matched=false;
 for(const candidate of candidates){
  const actual=Buffer.from(candidate,'hex');
  if(actual.length===digest.length&&timingSafeEqual(actual,digest))matched=true;
 }
 if(!matched)return {valid:false,reason:'invalid_signature'};
 let event;
 try{event=JSON.parse(raw.toString('utf8'))}catch{return {valid:false,reason:'invalid_payload'}}
 if(!event||typeof event.id!=='string'||!/^evt_[A-Za-z0-9]{5,}$/.test(event.id)||
   typeof event.type!=='string'||!EVENT_TYPES.has(event.type)||event.livemode!==true&&event.livemode!==false)
  return {valid:false,reason:'unsupported_event'};
 const data=event.data?.object;
 if(!data||typeof data.id!=='string'||data.id.length>150)
  return {valid:false,reason:'invalid_payload'};
 // Only IDs and event type leave the adapter; donor names, addresses,
 // emails, card details and full raw payloads must not reach ordinary logs.
 return {valid:true,event:{id:event.id,type:event.type,livemode:event.livemode,
  objectId:data.id,created:event.created,amountTotal:Number.isSafeInteger(data.amount_total)?data.amount_total:null,
  paymentIntentId:typeof data.payment_intent==='string'&&/^pi_[A-Za-z0-9]{5,100}$/.test(data.payment_intent)?data.payment_intent:null,
  remedy:['refund.created','refund.updated','refund.failed','charge.dispute.created','charge.dispute.closed'].includes(event.type)?{
   reference:data.id,amountCents:Number.isSafeInteger(data.amount)?data.amount:null,
   currency:data.currency,status:data.status,
   commandId:typeof data.metadata?.g28_treasury_command==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(data.metadata.g28_treasury_command)?data.metadata.g28_treasury_command:null
  }:null,
  currency:typeof data.currency==='string'?data.currency:null,
  paymentStatus:data.payment_status==='paid'?'paid':data.payment_status==='unpaid'?'unpaid':null,
  clientReferenceId:typeof data.client_reference_id==='string'&&/^attempt_[a-f0-9]{32}$/.test(data.client_reference_id)?data.client_reference_id:null,
  election:data.metadata?.election==='primary'||data.metadata?.election==='general'?data.metadata.election:null,
  termsVersion:typeof data.metadata?.terms_version==='string'&&/^\d{4}-\d{2}-\d{2}-[a-z0-9-]{4,40}$/.test(data.metadata.terms_version)?data.metadata.terms_version:null}};
}
