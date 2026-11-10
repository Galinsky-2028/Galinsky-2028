import {randomUUID,createHash} from 'node:crypto';
import {assert,exactKeys} from '../../../packages/core/validation.mjs';
import {staffCan} from '../../../packages/core/staff-permissions.mjs';
import {publicProtectedKey,verifyProtected,validateProtectedEnvelope,canonical} from '../../../packages/core/protected-crypto.mjs';
import {protectedId,protectedEnvelope} from '../../../packages/core/protected-records.mjs';
export function registerProtected(app,{store,config,account,writeSession,clock}){
 let retentionTimer,retentionRun=Promise.resolve();
 const sweep=()=>store.withProtected(async tx=>{const ids=await tx.purge(clock());for(const id of ids)await tx.audit('retention-worker',id,'expired_ciphertext_deleted');});
 app.addHook('onReady',async()=>{if(config.protectedContent){await sweep();retentionTimer=setInterval(()=>{retentionRun=retentionRun.then(sweep).catch(()=>{console.error(JSON.stringify({event:'protected_retention_failed'}));});},3600000);retentionTimer.unref();}});
 app.addHook('onClose',async()=>{clearInterval(retentionTimer);await retentionRun;});
 const ready=()=>assert(config.protectedContent===true&&config.staffIdentity&&typeof store.withProtected==='function','protected_unavailable','Protected reporting is not yet configured. Nothing has been stored.',503);
 async function staff(req,scope){ready();const s=await writeSession(req),role=await store.adminRole(s.account,config.adminOwnerEmailKey);assert([scope].flat().some(p=>staffCan(role,p)),'staff_forbidden','Your current role cannot perform this protected action.',403);assert(await store.staffMfaValid(s.account.id,s.hash,clock()),'mfa_required','Verify your staff passkey first.',403);return s;}
 async function activeRecipient(d){return d.state==='approved'&&await store.protectedRecipientAuthorized(d.accountId,d.scope,config.adminOwnerEmailKey);}
 app.get('/api/protected/directory',async req=>{ready();const s=await account(req),role=await store.adminRole(s.account,config.adminOwnerEmailKey),security=staffCan(role,'security:manage')&&await store.staffMfaValid(s.account.id,s.hash,clock());return store.withProtected(async tx=>({devices:(await Promise.all(tx.devices.map(async d=>security||d.accountId===s.account.id&&d.state!=='revoked'||await activeRecipient(d)?d:null))).filter(Boolean),notice:'Verify each recipient fingerprint through a separate trusted channel before sending. A directory entry alone cannot prove who controls a key.'}));});
 app.post('/api/protected/devices',async req=>{
  ready();const s=await writeSession(req),b=exactKeys(req.body,['id','publicKey','label','signature']);protectedId(b.id);
  assert(typeof b.label==='string'&&b.label.trim().length>=2&&b.label.length<=60&&!/[\x00-\x1f]/.test(b.label),'invalid_device_label','Choose a short device label.');
  const info=await publicProtectedKey(b.publicKey),proof={action:'enroll',accountId:s.account.id,id:b.id,fingerprint:info.fingerprint};
  assert(await verifyProtected(proof,b.signature,info.key),'device_proof_required','Proof of the device private key is required.',403);
  return store.withProtected(async tx=>{
   assert(tx.devices.length<2000&&tx.devices.filter(d=>d.accountId===s.account.id&&d.state!=='revoked').length<8,'protected_device_limit','Remove an unused device before adding another.',409);
   assert(!tx.devices.some(d=>d.id===b.id||d.fingerprint===info.fingerprint),'duplicate_device','This key or device reference already exists.',409);
   const d={id:b.id,accountId:s.account.id,publicKey:b.publicKey,fingerprint:info.fingerprint,label:b.label.trim(),state:'enrolled',scope:null,approvedBy:null,generation:1};await tx.saveDevice(d);await tx.audit(s.account.id,d.id,'device_enrolled');return {device:d};
  });
 });
 app.post('/api/protected/devices/:id/approve',async req=>{
  const s=await staff(req,'security:manage'),b=exactKeys(req.body,['fingerprint','scope','confirm']);
  assert(['incident','help','correction','profile','operational_note'].includes(b.scope)&&b.confirm==='verified recipient fingerprint independently','recipient_confirmation','Verify the recipient identity and exact fingerprint independently.');
  return store.withProtected(async tx=>{const d=tx.devices.find(d=>d.id===protectedId(req.params.id));assert(d&&d.state!=='revoked'&&d.fingerprint===b.fingerprint,'recipient_mismatch','The device changed or was revoked.',409);assert(await store.protectedRecipientAuthorized(d.accountId,b.scope,config.adminOwnerEmailKey),'recipient_scope','The recipient does not hold the required current staff role.',403);d.state='approved';d.scope=b.scope;d.approvedBy=s.account.id;await tx.saveDevice(d);await tx.audit(s.account.id,d.id,'recipient_approved');return {device:d};});
 });
 app.post('/api/protected/devices/:id/revoke',async req=>{
  ready();const s=await writeSession(req),b=exactKeys(req.body,['signature']);
  return store.withProtected(async tx=>{const d=tx.devices.find(d=>d.id===protectedId(req.params.id));assert(d,'not_found','Device not found.',404);
   const signed=d.accountId===s.account.id&&await verifyProtected({action:'revoke',id:d.id,generation:d.generation},b.signature,(await publicProtectedKey(d.publicKey)).key);
   if(!signed){const role=await store.adminRole(s.account,config.adminOwnerEmailKey);assert(staffCan(role,'security:manage')&&await store.staffMfaValid(s.account.id,s.hash,clock()),'revocation_forbidden','Use the device key or authorized security staff with a fresh passkey.',403);}
   d.state='revoked';d.generation++;await tx.saveDevice(d);await tx.audit(s.account.id,d.id,'device_revoked');return {revoked:true,notice:'Previously downloaded content cannot be erased. A recovered key does not restore recipient approval.'};
  });
 });
 app.get('/api/protected/records',async req=>{ready();const s=await account(req);return store.withProtected(tx=>tx.list(s.account.id));});
 async function readable(tx,id,s){const doc=await tx.get(id);assert(doc&&doc.participants.includes(s.account.id)&&(Date.parse(doc.retainUntil)>clock()||doc.legalHold),'not_found','Protected record not found.',404);const own=tx.devices.filter(d=>d.accountId===s.account.id&&d.state!=='revoked'&&doc.messages[0].context.recipients.includes(d.id));assert((await Promise.all(own.map(d=>s.account.id===doc.authorId||activeRecipient(d)))).some(Boolean),'recipient_revoked','No current authorized device can retrieve this record.',403);if(s.account.id!==doc.authorId)assert(await store.staffMfaValid(s.account.id,s.hash,clock()),'mfa_required','Verify your staff passkey before accessing protected records.',403);return doc;}
 app.get('/api/protected/records/:id',async req=>{ready();const s=await account(req);return store.withProtected(async tx=>{const doc=await readable(tx,protectedId(req.params.id),s);await tx.audit(s.account.id,doc.id,'ciphertext_read');return {record:doc,devices:tx.devices.filter(d=>doc.messages.some(m=>m.context.recipients.includes(d.id)))};});});
 app.post('/api/protected/records/:id/export',async req=>{ready();const s=await writeSession(req),b=exactKeys(req.body,['deviceId','version','signature','confirm']);assert(b.confirm==='export exact encrypted record','export_confirmation','Confirm this exact encrypted record export.');return store.withProtected(async tx=>{const doc=await readable(tx,protectedId(req.params.id),s),device=tx.devices.find(d=>d.id===b.deviceId&&d.accountId===s.account.id&&d.state!=='revoked'&&doc.messages[0].context.recipients.includes(d.id));assert(device&&b.version===doc.messages.length,'stale_protected_record','Reload the exact current record.',409);const proof={action:'export',recordId:doc.id,version:b.version,deviceId:b.deviceId};assert(await verifyProtected(proof,b.signature,(await publicProtectedKey(device.publicKey)).key),'export_proof','Unlock your authorized recipient device before exporting.',403);await tx.audit(s.account.id,doc.id,'ciphertext_export',createHash('sha256').update(canonical(proof)).digest('hex'));return {record:doc,devices:tx.devices.filter(d=>doc.messages[0].context.recipients.includes(d.id))};});});
 app.post('/api/protected/records', {bodyLimit:410000},async req=>{
  ready();const s=await writeSession(req),message=protectedEnvelope(req.body);
  assert(await store.rate('protected-submit:'+s.account.id,30,clock()+3600000),'rate_limited','Please wait before submitting more protected records.',429);
  return store.withProtected(async tx=>{
   const ctx=message.context,sender=tx.devices.find(d=>d.id===ctx.sender&&d.accountId===s.account.id&&d.state!=='revoked');assert(sender,'sender_device','Enroll and unlock your current device first.',403);
   assert(sender.generation===ctx.generation,'stale_key_generation','Reload current key-generation metadata.',409);
   const recipients=ctx.recipients.map(id=>tx.devices.find(d=>d.id===id));assert(recipients.every(Boolean)&&recipients.every(d=>d.state!=='revoked')&&recipients.some(d=>d.id===sender.id),'recipient_revoked','A required recipient device is missing or revoked.',409);
   const old=await tx.get(ctx.recordId);
   assert(old||!await tx.used(ctx.recordId),'retired_protected_record','This protected reference was retired. Start a new record with verified recipients.',409);
   assert(!old||old.messages.reduce((n,m)=>n+m.ciphertext.length,0)+message.ciphertext.length<=2000000,'protected_record_full','This encrypted thread has reached its size limit. Start a new record with verified recipients.',409);
   if(old){assert(old.participants.includes(s.account.id)&&(Date.parse(old.retainUntil)>clock()||old.legalHold)&&old.status!=='closed'&&ctx.sequence===old.messages.length+1&&ctx.kind===old.kind&&canonical(ctx.recipients)===canonical(old.messages[0].context.recipients),'stale_protected_record','Reload the exact current record and original recipient set.',409);if(old.authorId!==s.account.id)assert(await store.staffMfaValid(s.account.id,s.hash,clock()),'mfa_required','Verify your staff passkey before replying.',403);}
   else assert(ctx.sequence===1&&recipients.some(d=>d.accountId!==s.account.id),'protected_recipients','Select at least one named staff recipient.',403);
   for(const d of recipients)if(d.accountId!==(old?.authorId||s.account.id))assert(d.scope===ctx.kind&&await activeRecipient(d),'recipient_scope','The recipient no longer holds approval for this record type.',403);
   try{await validateProtectedEnvelope(message,sender,recipients);}catch{assert(false,'invalid_protected_proof','Encryption or sender proof failed. No content was stored.',400);}
   const doc=old||{id:ctx.recordId,authorId:s.account.id,kind:ctx.kind,participants:[...new Set(recipients.map(d=>d.accountId))],status:'received',messages:[],retainUntil:new Date(clock()+90*86400000).toISOString()};
   doc.messages.push(message);await tx.save(doc);await tx.audit(s.account.id,doc.id,'ciphertext_committed',createHash('sha256').update(canonical(message)).digest('hex'));return {id:doc.id,version:doc.messages.length,status:doc.status};
  });
 });
 app.post('/api/protected/records/:id/status',async req=>{const s=await staff(req,['safety:review','content:edit']),b=exactKeys(req.body,['status','version']);assert(['acknowledged','escalated','closed'].includes(b.status),'invalid_status','Choose a supported status.');return store.withProtected(async tx=>{const doc=await readable(tx,protectedId(req.params.id),s);assert(staffCan(await store.adminRole(s.account,config.adminOwnerEmailKey),doc.kind==='correction'?'content:edit':'safety:review'),'staff_forbidden','Your role does not cover this record type.',403);assert(doc.messages.length===b.version,'stale_protected_record','Reload the current record.',409);doc.status=b.status;await tx.save(doc);await tx.audit(s.account.id,doc.id,'status_'+b.status);return {status:doc.status};});});
 app.post('/api/protected/records/:id/hold',async req=>{const s=await staff(req,'security:manage'),b=exactKeys(req.body,['held','evidenceDigest']);assert(typeof b.held==='boolean'&&/^[a-f0-9]{64}$/.test(b.evidenceDigest),'hold_evidence','Supply a legal-hold decision and evidence digest.');return store.withProtected(async tx=>{assert(await tx.hold(protectedId(req.params.id),b.held),'not_found','Record not found.',404);await tx.audit(s.account.id,req.params.id,b.held?'hold_set':'hold_released',b.evidenceDigest);return {held:b.held};});});
 app.post('/api/protected/lifecycle/purge',async req=>{const s=await staff(req,'security:manage');exactKeys(req.body,[]);return store.withProtected(async tx=>{const ids=await tx.purge(clock());for(const id of ids)await tx.audit(s.account.id,id,'expired_ciphertext_deleted');return {deleted:ids.length,notice:'Active legal holds are preserved. Restored backups must replay deletion/hold events before service. Retained recipient downloads cannot be recalled.'};});});
}
