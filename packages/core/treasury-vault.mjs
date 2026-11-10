// Server-side encrypted treasury configuration; NOT end-to-end encryption.
// No payment cards/PANs, routing/account numbers or API secrets ever leave
// this module in GET responses, session JSON, logs or application code.
import {randomBytes,createCipheriv,createDecipheriv} from 'node:crypto';
import {assert} from './validation.mjs';

const slotIds=['bank','merchant-a','merchant-b','merchant-c','merchant-d'];
export const MERCHANT_SLOTS=Object.freeze(slotIds.slice(1));

export function treasuryVaultKey(encoded){
 const raw=typeof encoded==='string'&&/^[A-Za-z0-9+/]{43}=$/.test(encoded)?Buffer.from(encoded,'base64'):Buffer.alloc(0);
 assert(raw.length===32,'vault_unavailable','Treasury vault encryption is not configured.',503);
 return raw;
}
export function treasurySlot(raw){
 assert(slotIds.includes(raw),'invalid_treasury_slot','Choose a supported treasury slot.');
 return raw;
}
export function sealTreasury(slot,fields,encodedKey){
 treasurySlot(slot);
 const key=treasuryVaultKey(encodedKey);
 const iv=randomBytes(12);
 const cipher=createCipheriv('aes-256-gcm',key,iv);
 cipher.setAAD(Buffer.from('g28:treasury:v1:'+slot));
 const encrypted=Buffer.concat([cipher.update(JSON.stringify(fields),'utf8'),cipher.final()]);
 return ['g28v1',iv.toString('base64url'),cipher.getAuthTag().toString('base64url'),encrypted.toString('base64url')].join('.');
}
export function openTreasury(slot,envelope,encodedKey){
 treasurySlot(slot);
 const key=treasuryVaultKey(encodedKey);
 assert(typeof envelope==='string'&&envelope.length<300000,'invalid_vault_record','Treasury record is invalid.',500);
 const [version,nonce,tag,data,...extra]=envelope.split('.');
 assert(version==='g28v1'&&nonce&&tag&&data&&extra.length===0,'invalid_vault_record','Treasury record is invalid.',500);
 try{
  const iv=Buffer.from(nonce,'base64url'),authTag=Buffer.from(tag,'base64url');
  assert(iv.length===12&&authTag.length===16,'invalid_vault_record','Treasury record is invalid.',500);
  const cipher=createDecipheriv('aes-256-gcm',key,iv);
  cipher.setAAD(Buffer.from('g28:treasury:v1:'+slot));
  cipher.setAuthTag(authTag);
  return JSON.parse(Buffer.concat([cipher.update(Buffer.from(data,'base64url')),cipher.final()]).toString('utf8'));
 }catch{throw new Error('Treasury envelope integrity check failed.');}
}
export function cleanTreasuryPayload(slot,body){
 treasurySlot(slot);
 assert(body&&typeof body==='object'&&!Array.isArray(body),'invalid_treasury_payload','Expected a settings record.');
 const keys=Object.keys(body);
 if(slot==='bank'){
  assert(keys.every(k=>['bankName','accountName','routingNumber','accountNumber'].includes(k)),
   'invalid_treasury_payload','Unsupported bank account field.');
  const bankName=String(body.bankName||'').trim();
  const accountName=String(body.accountName||'').trim();
  const routing=String(body.routingNumber||'').replace(/[\s-]/g,'');
  const account=String(body.accountNumber||'').replace(/[\s-]/g,'');
  assert(bankName.length>=2&&bankName.length<=120&&accountName.length>=3&&accountName.length<=180,
   'invalid_treasury_payload','Enter the legal account name and bank name.');
  assert(/^\d{9}$/.test(routing),'invalid_bank_routing','A 9-digit ABA routing number is required.');
  const digits=[...routing].map(Number);
  assert((3*(digits[0]+digits[3]+digits[6])+7*(digits[1]+digits[4]+digits[7])+
   digits[2]+digits[5]+digits[8])%10===0,'invalid_bank_routing','The routing checksum does not match.');
  assert(/^\d{4,17}$/.test(account),'invalid_bank_account','Enter a valid bank account number.');
  return {value:{bankName,accountName,routingNumber:routing,accountNumber:account},
   maskedLabel:bankName+' ending '+account.slice(-4)};
 }
 assert(keys.every(k=>['merchantId','apiKey','webhookSecret','checkoutUrl','mode'].includes(k)),
  'invalid_treasury_payload','Unsupported payment provider field.');
 assert(body.mode==='sandbox','live_payment_disabled','Only sandbox credentials may be saved. Live payment activation requires separate review.',403);
 const merchantId=String(body.merchantId||'').trim();
 const apiKey=String(body.apiKey||'').trim();
 const webhookSecret=String(body.webhookSecret||'').trim();
 const checkoutUrl=String(body.checkoutUrl||'').trim();
 assert(merchantId.length>=2&&merchantId.length<=140&&!/[\r\n\u0000]/.test(merchantId),
  'invalid_merchant','Enter your approved merchant account identifier.');
 assert(apiKey.length>=8&&apiKey.length<=4096&&!/[\r\n\u0000]/.test(apiKey),
  'invalid_api_key','Enter a sandbox credential of the correct length.');
 assert(!webhookSecret||(webhookSecret.length>=8&&webhookSecret.length<=4096&&!/[\r\n\u0000]/.test(webhookSecret)),
  'invalid_webhook_secret','Invalid sandbox webhook secret.');
 assert(!checkoutUrl||(/^https:\/\/[a-z0-9.-]+(?::443)?(?:\/|$)/i.test(checkoutUrl)&&checkoutUrl.length<=2048&&!/@/.test(checkoutUrl)),
  'invalid_checkout_url','Only an approved HTTPS sandbox checkout URL may be recorded.');
 return {value:{mode:'sandbox',merchantId,apiKey,webhookSecret,checkoutUrl},
  maskedLabel:slot+' / sandbox / merchant '+merchantId.slice(0,3)+'…'};
}
