import {assert,exactKeys} from './validation.mjs';
import {PROTECTED_PROFILE} from './protected-crypto.mjs';
export const protectedId=x=>{assert(typeof x==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(x),'invalid_protected_id','Use a valid protected record reference.');return x;};
export function protectedContext(input){
 const b=exactKeys(input,['profile','recordId','sequence','kind','sender','recipients','generation']);
 assert(b.profile===PROTECTED_PROFILE,'protected_profile','Reload the current protected client.');
 protectedId(b.recordId);protectedId(b.sender);
 assert(['incident','help','correction','profile','operational_note'].includes(b.kind)&&Number.isSafeInteger(b.sequence)&&b.sequence>=1&&b.sequence<=100,'invalid_protected_context','Choose a supported record type and sequence.');
 assert(Number.isSafeInteger(b.generation)&&b.generation>0&&Array.isArray(b.recipients)&&b.recipients.length>=2&&b.recipients.length<=12&&new Set(b.recipients).size===b.recipients.length,'invalid_recipients','Choose the exact approved recipient devices.');
 b.recipients.forEach(protectedId);
 return {profile:b.profile,recordId:b.recordId,sequence:b.sequence,kind:b.kind,sender:b.sender,recipients:[...b.recipients].sort(),generation:b.generation};
}
export function protectedEnvelope(input){
 const b=exactKeys(input,['context','ciphertext','signature']),context=protectedContext(b.context);
 assert(typeof b.ciphertext==='string'&&b.ciphertext.length<=400000&&b.ciphertext.startsWith('-----BEGIN PGP MESSAGE-----')&&typeof b.signature==='string'&&b.signature.length<=4000&&b.signature.startsWith('-----BEGIN PGP SIGNATURE-----'),'invalid_ciphertext','Submit a bounded encrypted, signed record.');
 return {context,ciphertext:b.ciphertext,signature:b.signature};
}
