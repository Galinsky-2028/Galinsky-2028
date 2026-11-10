import {randomUUID} from 'node:crypto';
import {openDelivery,sealDelivery} from '../../../packages/core/auth.mjs';
import {assert} from '../../../packages/core/validation.mjs';
export const NOTICE_KINDS=['account_welcome','account_security','account_reminder','finance_attention'];
export async function queueAccountNotice(store,config,accountId,kind,eventKey,now=Date.now()){
 assert(NOTICE_KINDS.includes(kind)&&kind!=='finance_attention'&&typeof eventKey==='string'&&/^[a-zA-Z0-9:_-]{1,180}$/.test(eventKey),'invalid_notice','Invalid account notification.');
 const a=await store.deliveryAccount(accountId);if(!a)return false;
 return store.queueAccountNotice(accountId,eventKey,prepareAccountNotice(a,config,kind,now));
}
export function prepareAccountNotice(a,config,kind,now=Date.now()){
 const address=openDelivery(a.delivery_envelope,config.deliveryKey).email;
 return {id:randomUUID(),kind,subjectKey:a.email_key,envelope:sealDelivery({email:address,expires:now+86400000},config.deliveryKey)};
}
export function noticeTemplate(kind,origin,publicOrigin=origin){
 const link=origin+'/';
 switch(kind){
  case 'account_welcome':return {subject:'Your volunteer workspace is ready',text:'Your verified account can read current volunteer materials. Materials access does not authorize regulated activity. Open your workspace to review orientation and available tasks.',link};
  case 'account_security':return {subject:'A security setting changed on your account',text:'A staff passkey setting changed. If you did not make this change, sign in from a trusted device, revoke unfamiliar devices and contact the campaign owner. This message contains no private reports or recovery keys.',link:origin+'/security'};
  case 'account_reminder':return {subject:'Your volunteer workspace reminder',text:'There is an optional reminder in your volunteer workspace. Review the current task and training requirements before taking action. You can stop optional updates in Account settings.',link};
  case 'finance_attention':return {subject:'A campaign contribution needs your review',text:'Please review your contribution through the official payment processor or contact campaign treasury using the contact information on the campaign website. This transactional notice contains no gift amount, case details or private documents. It does not subscribe you to campaign updates.',link:publicOrigin+'/donate/manage'};
  default:throw Error('Unsupported account notice.');
 }
}
