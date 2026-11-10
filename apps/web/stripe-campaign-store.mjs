import {createHash} from 'node:crypto';
import {recordStripeRemedy} from './stripe-remedies.mjs';
import {verifyStripeWebhook} from '../../packages/core/stripe-campaign.mjs';

const SESSION=/^cs_(test|live)_[A-Za-z0-9]{10,}$/;
export class StripeCampaignStore {
 constructor(pool){this.pool=pool;}
 async donorIntent(clientRef,sessionId){return (await this.pool.query("SELECT i.amount_cents,i.election,i.payment_state,i.livemode,i.terms_version,(SELECT COALESCE(sum(e.amount_cents),0)::text FROM g28.financial_provider_events e WHERE e.payment_id=i.session_id AND e.provider=CASE WHEN i.livemode THEN 'stripe' ELSE 'stripe-test' END AND e.event_kind IN ('refunded','partially_refunded')) AS refunded_cents FROM g28.stripe_checkout_intents i WHERE i.client_reference=$1 AND i.session_id=$2",[clientRef,sessionId])).rows[0]||null;}
 async recordSession({clientRef,sessionId,amountCents,election,livemode,termsVersion=null}){
  if(!/^attempt_[a-f0-9]{32}$/.test(clientRef)||!SESSION.test(sessionId)||
   !Number.isSafeInteger(amountCents)||amountCents<=0||amountCents>100000000||
   !['primary','general'].includes(election)||typeof livemode!=='boolean'||
   termsVersion!==null&&(typeof termsVersion!=='string'||!/^\d{4}-\d{2}-\d{2}-[a-z0-9-]{4,40}$/.test(termsVersion)))
   throw new Error('Invalid Stripe checkout session record.');
  if(livemode !== sessionId.startsWith('cs_live_'))throw Error('Live and test Stripe session identity mismatch');
  await this.pool.query(
   "INSERT INTO g28.stripe_checkout_intents(client_reference,session_id,election,amount_cents,livemode,terms_version,agreed_at) VALUES($1,$2,$3,$4,$5,$6,CASE WHEN $6::text IS NULL THEN NULL ELSE now() END) ON CONFLICT(client_reference) DO NOTHING",
   [clientRef,sessionId,election,amountCents,livemode,termsVersion]);
  const found=await this.pool.query(
   'SELECT session_id,election,amount_cents,livemode,terms_version FROM g28.stripe_checkout_intents WHERE client_reference=$1',[clientRef]);
  if(found.rowCount!==1||found.rows[0].session_id!==sessionId||
     found.rows[0].election!==election||Number(found.rows[0].amount_cents)!==amountCents||
     found.rows[0].livemode!==livemode||found.rows[0].terms_version!==termsVersion)
   throw Error('Conflicting Stripe checkout idempotency reference');
 }
 async receiveSignedWebhook({raw,header,secret,sandbox}){
  const result=verifyStripeWebhook(raw,header,secret);
  if(!result.valid)return {status:400,outcome:'invalid_signature'};
  const e=result.event;
  if(e.livemode===sandbox)return {status:400,outcome:'environment_mismatch'};
  if(e.remedy)return recordStripeRemedy(this.pool,e,raw);
  const confirmed=e.type==='checkout.session.completed'||e.type==='checkout.session.async_payment_succeeded';
  const nonPaymentState=e.type==='checkout.session.expired'?'expired':
   e.type==='checkout.session.async_payment_failed'?'failed':null;
  if(!confirmed&&!nonPaymentState)return {status:200,outcome:'verified_other_event_requires_manual_reconciliation'};
  if(confirmed&&e.paymentStatus!=='paid')return {status:200,outcome:'no_capture_confirmed'};
  if(nonPaymentState&&e.paymentStatus==='paid')return {status:422,outcome:'conflicting_payment_status'};
  if(!SESSION.test(e.objectId)||!e.clientReferenceId||
     !['primary','general'].includes(e.election)||e.currency!=='usd'||
     !Number.isSafeInteger(e.amountTotal)||e.amountTotal<=0||
     !Number.isSafeInteger(e.created)||e.created<=0)return {status:422,outcome:'unmatched_payment'};
  const digest=createHash('sha256').update(raw).digest('hex');
  const c=await this.pool.connect();
  try{
   await c.query('BEGIN');
   const attempts=await c.query(
    'SELECT client_reference,election,amount_cents,livemode,payment_state,terms_version FROM g28.stripe_checkout_intents WHERE session_id=$1 FOR UPDATE',
    [e.objectId]);
   const record=attempts.rows[0];
   if(!record||record.client_reference!==e.clientReferenceId||
       record.election!==e.election||Number(record.amount_cents)!==e.amountTotal||
       record.livemode!==e.livemode||record.terms_version!==e.termsVersion){
    await c.query('ROLLBACK');return {status:422,outcome:'unmatched_payment'};
   }
   const receipt=await c.query(
    'INSERT INTO g28.stripe_webhook_receipts(event_id,event_sha256,session_id,livemode,event_type) VALUES($1,$2,$3,$4,$5) ON CONFLICT(event_id) DO NOTHING RETURNING event_id',
    [e.id,digest,e.objectId,e.livemode,e.type]);
   if(!receipt.rowCount){
    const old=await c.query('SELECT event_sha256 FROM g28.stripe_webhook_receipts WHERE event_id=$1',[e.id]);
    if(old.rows[0]?.event_sha256!==digest)throw Error('Stripe webhook duplicate ID content mismatch');
    await c.query('COMMIT');return {status:200,outcome:'duplicate'};
   }
   if(nonPaymentState){
    // A late expiration or failure event must never overwrite a paid status.
    if(record.payment_state==='pending'){
     await c.query(
      'UPDATE g28.stripe_checkout_intents SET payment_state=$1,status_updated_at=now() WHERE client_reference=$2',
      [nonPaymentState,e.clientReferenceId]);
    }
    await c.query('COMMIT');
    return {status:200,outcome:record.payment_state==='pending'?
     'verified_'+nonPaymentState+'_no_charge':'already_'+record.payment_state};
   }
   if(record.payment_state==='paid'){
    await c.query('COMMIT');return {status:200,outcome:'already_captured'};
   }
   if(record.payment_state!=='pending'){
    // A signed paid event after an expiration/failure is a real discrepancy.
    // Record the capture for human reconciliation, not as cleared funds.
    await c.query(
     "UPDATE g28.stripe_checkout_intents SET payment_state='requires_review',status_updated_at=now() WHERE client_reference=$1",
     [e.clientReferenceId]);
   }else{
    await c.query(
     "UPDATE g28.stripe_checkout_intents SET payment_state='paid',confirmed_at=now(),status_updated_at=now() WHERE client_reference=$1",
     [e.clientReferenceId]);
   }
   if(e.paymentIntentId){
    await c.query('INSERT INTO g28.stripe_payment_identities(session_id,payment_intent_id,livemode) VALUES($1,$2,$3) ON CONFLICT(session_id) DO NOTHING',[e.objectId,e.paymentIntentId,e.livemode]);
    const identity=(await c.query('SELECT payment_intent_id FROM g28.stripe_payment_identities WHERE session_id=$1',[e.objectId])).rows[0];if(identity?.payment_intent_id!==e.paymentIntentId)throw Error('Conflicting provider payment identity');
   }
   await c.query(
    "INSERT INTO g28.financial_provider_events(provider,event_id,payment_id,event_digest,event_kind,amount_cents,occurred_at) VALUES($1,$2,$3,$4,'captured',$5,$6) ON CONFLICT(provider,event_id) DO NOTHING",
    [sandbox?'stripe-test':'stripe',e.id,e.objectId,digest,e.amountTotal,new Date(e.created*1000)]);
   await c.query('COMMIT');
   return {status:200,outcome:record.payment_state==='pending'?
    'verified_captured_not_settled':'verified_capture_requires_reconciliation'};
  }catch(error){await c.query('ROLLBACK');throw error;}finally{c.release();}
 }
}
