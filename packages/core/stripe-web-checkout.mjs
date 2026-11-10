// Checkout entry point: server-hosted, no card data or donor identity stored here.
// Production never opens on test credentials or missing treasury / Stripe approvals.
import {randomBytes,createHmac,timingSafeEqual} from 'node:crypto';
import {stripeCheckoutPlan,createStripeCheckout} from './stripe-campaign.mjs';
import {cents} from './finance.mjs';
import {CONTRIBUTION_TERMS_PATH,CONTRIBUTION_TERMS_VERSION,ONLINE_DONATION_ELECTION} from './contribution-terms.mjs';

const SAFE_NAME='Phillip Galinsky for America';
const approved=(reference)=>({accepted:true,reference});
const releaseKeys=['processorAccount','treasurerApproval','electionRules','processorContract','securityReview','reconciliationTest'];
const policyKeys=['stripeRestrictedBusinessApproval','federalCommitteeIdentity','cardSourcePolicy','donorAttestations','directCheckoutRules','recurringControls'];
const dollarLimit=x=>typeof x==='string'&&/^[1-9]\d{0,7}$/.test(x)&&Number(x)<=99999999?Number(x):null;
const literal=x=>String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const routeBlocked=()=>new Error('Stripe Checkout is not configured or approved for this campaign.');

export function stripeSettings(env){
 const sandbox=env.G28_PUBLIC_MODE==='preview'&&env.G28_STRIPE_TEST_ENABLED==='true';
 // Native auto-capture Checkout cannot enforce the current all-channel
 // reservation and personal-credit-card review before collection. No set of
 // environment approvals may activate that old live entry point.
 const live=false;
 if(!sandbox)return null;
 const key=env.STRIPE_SECRET_KEY;
 if(typeof key!=='string'||!(sandbox?/^sk_test_[A-Za-z0-9_]{12,}$/:/^sk_live_[A-Za-z0-9_]{12,}$/).test(key))
  return null;
 // In protected sandbox previews, use the actual Render hostname being viewed,
 // not an optional future public-domain return URL. A mismatched configured
 // origin rejects every real browser POST even though synthetic API tests pass.
 const supplied=(sandbox&&env.RENDER_EXTERNAL_URL)||env.G28_STRIPE_RETURN_ORIGIN||env.RENDER_EXTERNAL_URL;
 let origin;
 try{origin=new URL(supplied);}catch{return null;}
 if(origin.protocol!=='https:'||origin.username||origin.password||origin.port||
  origin.pathname!=='/'||origin.search||origin.hash||!origin.hostname.includes('.'))return null;
 const primary=dollarLimit(env.G28_STRIPE_PRIMARY_LIMIT_CENTS);
 const general=dollarLimit(env.G28_STRIPE_GENERAL_LIMIT_CENTS);
 const limits={primary:primary||10000,general:general||10000};
 const release={enabled:true,evidence:Object.fromEntries(releaseKeys.map(k=>[k,approved('stripe-sandbox-only')]))};
 release.evidence.validUntil='2099-01-01T00:00:00Z';
 const policyEvidence=Object.fromEntries(policyKeys.map(k=>[k,approved('stripe-sandbox-only')]));
 return {sandbox,live,secretKey:key,origin:origin.origin,limits,
  policy:{publicOrigin:origin.origin,committeeName:env.G28_STRIPE_COMMITTEE_NAME||SAFE_NAME,
    limits,recurringEnabled:false,evidence:policyEvidence},release};
}

export function checkoutNonceKey(stripeSecretKey=null){
 // A random per-process signing key invalidates a form whenever Render deploys
 // or scales, leaving users stuck before reaching Stripe. Derive a separate
 // domain-separated CSRF key from the private, stable server-only Stripe key.
 // It never leaves the backend and is not sent to Stripe or the browser.
 if(typeof stripeSecretKey==='string'&&/^(sk_test|sk_live)_[A-Za-z0-9_]{12,}$/.test(stripeSecretKey))
  return createHmac('sha256',stripeSecretKey).update('galinsky-2028:stripe-csrf-form:v1').digest();
 return randomBytes(32);
}
export function createCheckoutToken(secret,now=Date.now(),nonce=randomBytes(16).toString('hex')){
 if(typeof nonce!=='string'||!/^[a-f0-9]{32}$/.test(nonce))throw Error('Invalid checkout token nonce.');
 const issued=Math.floor(now/1000);
 const payload=issued+'.'+nonce;
 const sig=createHmac('sha256',secret).update(payload).digest('hex');
 return payload+'.'+sig;
}
export function checkCheckoutToken(secret,token,now=Date.now()){
 if(typeof token!=='string'||!/^\d{10}\.[a-f0-9]{32}\.[a-f0-9]{64}$/.test(token))return null;
 const [issued,nonce,tag]=token.split('.');
 if(Number(issued)>Math.floor(now/1000)+10||Math.floor(now/1000)-Number(issued)>900)return null;
 const actual=Buffer.from(tag,'hex');
 const expected=createHmac('sha256',secret).update(issued+'.'+nonce).digest();
 return actual.length===expected.length&&timingSafeEqual(actual,expected)?'attempt_'+nonce:null;
}
export function validDonationOrigin(req,settings){
 const headers=req?.headers||{};
 const reported=headers.origin;
 const site=headers['sec-fetch-site'];
 // Browser Fetch Metadata never identifies an ordinary same-origin form POST
 // as cross-site or same-site. Reject cross-site submissions even if a proxy
 // or extension has removed the Origin header.
 if(site && site!=='same-origin' && site!=='none')return false;
 // An explicit non-opaque Origin must always be the configured campaign origin.
 if(reported && reported!=='null')return reported===settings.origin;
 // Firefox privacy modes and browser extensions can suppress/opaque Origin.
 // Only recover on the verified public host; a valid HMAC-signed, expiring
 // form token is separately mandatory before any Stripe call.
 let expectedHost;
 try{expectedHost=new URL(settings.origin).host;}catch{return false;}
 if(typeof headers.host!=='string'||headers.host.toLowerCase()!==expectedHost.toLowerCase())return false;
 let sameOriginReferrer=false;
 if(headers.referer){
  if(typeof headers.referer!=='string')return false;
  try{sameOriginReferrer=new URL(headers.referer).origin===settings.origin;}catch{return false;}
  if(!sameOriginReferrer)return false;
 }
 // In production, a stripped Origin still needs positive same-origin browser
 // evidence. The password-protected TEST preview may instead rely on the
 // expected host plus its existing signed form token and preview authorization.
 return site==='same-origin'||sameOriginReferrer||settings.sandbox===true;
}
export function parseCheckoutForm(raw){
 if(typeof raw!=='string'||raw.length>4096)throw Error('Invalid contribution form.');
 const p=new URLSearchParams(raw);
 // No donor-supplied election choice, eligibility flags or untrusted terms
 // version: a single affirmative agreement to the linked, versioned terms
 // constitutes all of the disclosed certifications.
 const allowed=new Set(['amount','frequency','form_token','agree']);
 for(const [k] of p)if(!allowed.has(k)||p.getAll(k).length!==1)throw Error('Invalid contribution form.');
 const amountCents=cents(p.get('amount'));
 if(p.get('frequency')!=='once')throw Error('Recurring contributions are not yet supported.');
 if(p.get('agree')!=='yes')throw Error('Agreement to the contribution terms is required.');
 const attestations=Object.fromEntries(
  ['eligibleResidency','ownFunds','age18','notFederalContractor','personalCreditCard'].map(k=>[k,true]));
 return {amountCents,frequency:'once',election:ONLINE_DONATION_ELECTION,attestations,
  termsVersion:CONTRIBUTION_TERMS_VERSION,formToken:p.get('form_token')};
}
export async function openStripeSession({raw,settings,nonceKey,request,transport=fetch,onStage=()=>{}}){
 onStage('configuration');
 if(!settings)throw routeBlocked();
 onStage('origin');
 if(!validDonationOrigin(request,settings))throw Error('Cross-origin payment request refused.');
 onStage('form');
 const input=parseCheckoutForm(raw);
 onStage('token');
 const clientRef=checkCheckoutToken(nonceKey,input.formToken);
 if(!clientRef)throw Error('Expired or invalid checkout form. Reload before submitting.');
 onStage('plan');
 const plan=stripeCheckoutPlan({contribution:{amountCents:input.amountCents,frequency:input.frequency,
  election:input.election,clientRef,attestations:input.attestations,termsVersion:input.termsVersion},
  policy:settings.policy,release:settings.release});
 onStage('stripe_api');
 const created=await createStripeCheckout({plan,secretKey:settings.secretKey,transport,
  signal:AbortSignal.timeout(10000)});
 onStage('stripe_created');
 return {...created,clientRef,amountCents:input.amountCents,election:input.election,
  termsVersion:input.termsVersion};
}
export function stripeDonationHtml(settings,nonceKey,amount='25'){
 if(!settings)throw routeBlocked();
 const token=createCheckoutToken(nonceKey);
 const n=/^(?:[1-9]\d{0,6})(?:\.\d{1,2})?$/.test(amount)?amount:'25';
 const approval=settings.sandbox?
  '<p class="service-notice" role="status"><strong>Stripe TEST MODE.</strong> This page accepts only Stripe test cards; no real money will move.</p>':
  '<p class="service-notice">Secure credit-card checkout. Your contribution is not confirmed until the payment processor and campaign ledger verify it.</p>';
 return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'+
 '<meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer">'+
 '<title>Secure contribution | Galinsky 2028</title><link rel="stylesheet" href="/assets/design.css"><link rel="stylesheet" href="/assets/site.css"></head>'+
 '<body><main id="main" class="wrap" style="max-width:800px;padding:42px 20px">'+
 '<a href="/donate/">← Donation information</a><h1>Secure campaign contribution</h1>'+approval+
 '<p>Paid for by Phillip Galinsky for America. Contributions are not tax deductible.</p>'+
 '<form method="post" action="/donate/stripe/checkout" class="donate-form" style="margin-top:20px" autocomplete="off">'+
 '<input type="hidden" name="form_token" value="'+token+'">'+
 '<label class="field">Amount in US dollars<input required type="number" name="amount" min="1" max="'+(settings.limits.general/100).toFixed(2)+'" step=".01" value="'+literal(n)+'"></label>'+ 
 '<input type="hidden" name="frequency" value="once">'+
 '<p class="tiny">One-time contribution only. The approved maximum applies to each donor across ALL fundraising channels, not just this transaction. Name and mailing address are collected by the secure provider; occupation and employer are required there as well.</p>'+
 '<div class="donor-consent">'+
 '<input id="donor-terms-agreement" type="checkbox" name="agree" value="yes" required aria-required="true">'+
 '<label for="donor-terms-agreement">I agree to the <a href="'+CONTRIBUTION_TERMS_PATH+'" target="_blank" rel="noopener noreferrer">contribution terms</a>.</label>'+ 
 '</div>'+ 
 '<p class="donor-reporting">Federal law requires us to use our best efforts to collect and report the name, mailing address, occupation and employer of individuals whose contributions exceed $200 in an election cycle.</p>'+
 '<button class="btn blue" type="submit">Continue to secure card checkout</button>'+ 
 '<p class="tiny" style="margin:14px 0 0">Next, Stripe will ask for your card details on its own secure checkout page. No card number is entered on this campaign page.</p></form>'+
 '<p class="tiny">Do not submit again if a previous payment is still processing.</p></main></body></html>';
}
