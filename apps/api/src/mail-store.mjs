import {assert} from '../../../packages/core/validation.mjs';
const suppressionReason=e=>e.type==='email.complained'?'complaint':e.type==='email.suppressed'?'provider_suppressed':'hard_bounce';
async function suppress(client,id){
 await client.query(`INSERT INTO g28.mail_suppressions(subject_key,reason)
  SELECT o.subject_key,CASE WHEN e.event_type='email.complained' THEN 'complaint' WHEN e.event_type='email.suppressed' THEN 'provider_suppressed' ELSE 'hard_bounce' END
  FROM g28.outbox o JOIN g28.mail_events e ON e.provider_email_id=o.provider_email_id
  WHERE o.provider_email_id=$1 AND e.permanent_suppression=true
  ORDER BY e.received_at DESC LIMIT 1 ON CONFLICT(subject_key) DO NOTHING`,[id]);
}
export async function queueNoticeSQL(c,accountId,eventKey,job){
 const q=await c.query('INSERT INTO g28.account_notice_keys(account_id,event_key) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING event_key',[accountId,eventKey]);
 if(q.rowCount)await c.query('INSERT INTO g28.outbox(id,kind,subject_key,payload_envelope) VALUES($1,$2,$3,$4)',[job.id,job.kind,job.subjectKey,job.envelope]);
 return Boolean(q.rowCount);
}
export const postgresMail={
 async mailDeliveryStatus(){
  const events=await this.pool.query("SELECT event_type,count(DISTINCT provider_email_id)::integer AS count,max(received_at) AS latest FROM g28.mail_events WHERE received_at>now()-interval '30 days' GROUP BY event_type");
  const suppressed=await this.pool.query('SELECT count(*)::integer AS count FROM g28.mail_suppressions');
  return {windowDays:30,events:Object.fromEntries(events.rows.map(r=>[r.event_type,r.count])),suppressedRecipients:suppressed.rows[0].count,lastCallbackAt:events.rows.reduce((latest,r)=>!latest||r.latest>latest?r.latest:latest,null)};
 },
 async deliveryAllowed(job){
  if(job.kind==='finance_attention'){
   const current=await this.pool.query("SELECT 1 FROM g28.treasury_case_notices n JOIN g28.treasury_cases c ON c.id=n.case_id JOIN g28.treasury_gifts g ON g.id=c.gift_id JOIN g28.treasury_donors d ON d.id=g.donor_id WHERE n.job_id=$1 AND c.document->>'status'<>'closed' AND (c.document->>'deadline')::timestamptz>now() AND n.donor_id=d.id AND n.donor_version=d.version",[job.id]);
   if(!current.rowCount)return false;
  }
  const q=await this.pool.query(`SELECT NOT EXISTS(SELECT 1 FROM g28.mail_suppressions WHERE subject_key=$1) AS allowed,
   EXISTS(SELECT 1 FROM g28.accounts WHERE email_key=$1 AND marketing_consent=true) AS opted_in`,[job.subject_key]);
  return q.rows[0].allowed&&(job.kind!=='account_reminder'||q.rows[0].opted_in);
 },
 async recordMailAcceptance(job,providerId){
  const c=await this.pool.connect();try{await c.query('BEGIN');
   await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,282024))',[providerId]);
   const q=await c.query('UPDATE g28.outbox SET provider_email_id=$2 WHERE id=$1 AND (provider_email_id IS NULL OR provider_email_id=$2) RETURNING id',[job.id,providerId]);
   assert(q.rowCount===1,'mail_receipt_conflict','Mail receipt could not be recorded.',409);await suppress(c,providerId);await c.query('COMMIT');
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 },
 async recordMailEvent(event){
  const c=await this.pool.connect();try{await c.query('BEGIN');
   await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,282024))',[event.providerId]);
   const q=await c.query(`INSERT INTO g28.mail_events(event_id,digest,provider_email_id,event_type,permanent_suppression) VALUES($1,$2,$3,$4,$5) ON CONFLICT(event_id) DO NOTHING RETURNING event_id`,[event.id,event.digest,event.providerId,event.type,event.suppress]);
   if(!q.rowCount){const previous=await c.query('SELECT digest FROM g28.mail_events WHERE event_id=$1',[event.id]);assert(previous.rows[0]?.digest===event.digest,'mail_event_conflict','Conflicting delivery receipt.',409);}
   await suppress(c,event.providerId);await c.query('COMMIT');return {duplicate:!q.rowCount};
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 },
 async deliveryAccount(id){const q=await this.pool.query('SELECT email_key,delivery_envelope FROM g28.accounts WHERE id=$1',[id]);return q.rows[0]||null;},
 async queueAccountNotice(accountId,eventKey,job){
  const c=await this.pool.connect();try{await c.query('BEGIN');
   const queued=await queueNoticeSQL(c,accountId,eventKey,job);await c.query('COMMIT');return queued;
  }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
 }
};
export const memoryMail={
 async mailDeliveryStatus(){const events={};for(const e of this.mailEvents?.values()||[]){events[e.type]??=new Set();events[e.type].add(e.providerId);}return {windowDays:30,events:Object.fromEntries(Object.entries(events).map(([kind,ids])=>[kind,ids.size])),suppressedRecipients:this.mailSuppressions?.size||0,lastCallbackAt:null};},
 async deliveryAllowed(job){const key=job.subject_key||job.subjectKey;return !this.mailSuppressions?.has(key)&&(job.kind!=='account_reminder'||[...this.accounts.values()].some(a=>a.emailKey===key&&a.marketing));},
 async recordMailAcceptance(job,providerId){const found=this.outbox.find(j=>j.id===job.id);if(!found)return;assert(!found.providerId||found.providerId===providerId,'mail_receipt_conflict','Mail receipt conflict.',409);found.providerId=providerId;for(const e of this.mailEvents?.values()||[])if(e.providerId===providerId&&e.suppress){this.mailSuppressions??=new Map();this.mailSuppressions.set(found.subjectKey,suppressionReason(e));}},
 async recordMailEvent(event){this.mailEvents??=new Map();const previous=this.mailEvents.get(event.id);assert(!previous||previous.digest===event.digest,'mail_event_conflict','Conflicting delivery receipt.',409);this.mailEvents.set(event.id,event);for(const j of this.outbox)if(j.providerId===event.providerId&&event.suppress){this.mailSuppressions??=new Map();this.mailSuppressions.set(j.subjectKey,suppressionReason(event));}return {duplicate:Boolean(previous)};},
 async deliveryAccount(id){const a=this.accounts.get(id);return a?{email_key:a.emailKey,delivery_envelope:a.deliveryEnvelope}:null;},
 async queueAccountNotice(accountId,eventKey,job){this.noticeKeys??=new Set();const key=accountId+':'+eventKey;if(this.noticeKeys.has(key))return false;this.noticeKeys.add(key);this.outbox.push({...job,status:'queued',attempts:0,availableAt:Date.now()});return true;}
};
