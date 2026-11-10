// Application profile G28-PGP-1. OpenPGP implements all cryptography. The host
// still controls delivered browser code; fingerprints must be checked elsewhere.
import * as pgp from 'openpgp';
const config={v6Keys:true,aeadProtect:true,preferredSymmetricAlgorithm:pgp.enums.symmetric.aes256};
export const PROTECTED_PROFILE='G28-PGP-1/openpgp-6.3.2';
// PostgreSQL JSONB and JSON transports reorder properties. Bind the same
// recursively sorted JSON representation at every signing/verifying boundary.
export const canonical=value=>JSON.stringify(sorted(value));
function sorted(value){return Array.isArray(value)?value.map(sorted):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(k=>[k,sorted(value[k])])):value;}
export async function newProtectedKey(accountId,passphrase){
 if(typeof passphrase!=='string'||passphrase.length<16)throw Error('Use a recovery passphrase of at least 16 characters.');
 return pgp.generateKey({type:'curve25519',userIDs:[{name:accountId}],passphrase,format:'armored',config});
}
export async function publicProtectedKey(armored){
 if(typeof armored!=='string'||armored.length>12000)throw Error('Invalid public key.');
 const key=await pgp.readKey({armoredKey:armored});
 await key.verifyPrimaryKey();
 if(key.isPrivate()||key.keyPacket.version!==6||!await key.getEncryptionKey())throw Error('A valid version 6 encryption/signing public key is required.');
 return {key,fingerprint:key.getFingerprint(),encryptionId:(await key.getEncryptionKey()).getKeyID().toHex()};
}
export async function unlockProtectedKey(armored,passphrase){return pgp.decryptKey({privateKey:await pgp.readPrivateKey({armoredKey:armored}),passphrase});}
export async function signProtected(value,privateKey){return pgp.sign({message:await pgp.createMessage({text:canonical(value)}),signingKeys:privateKey,detached:true});}
export async function verifyProtected(value,signature,publicKey){
 try{
  const result=await pgp.verify({message:await pgp.createMessage({text:canonical(value)}),signature:await pgp.readSignature({armoredSignature:signature}),verificationKeys:publicKey});
  if(result.signatures.length!==1)return false;await result.signatures[0].verified;return true;
 }catch{return false;}
}
export async function encryptProtected(context,payload,recipients,privateKey){
 const keys=await Promise.all(recipients.map(async r=>(await publicProtectedKey(r.publicKey)).key));
 const ciphertext=await pgp.encrypt({message:await pgp.createMessage({text:canonical({context,payload})}),encryptionKeys:keys,signingKeys:privateKey,format:'armored',config});
 const envelope={context,ciphertext};return {...envelope,signature:await signProtected(envelope,privateKey)};
}
export async function validateProtectedEnvelope(envelope,sender,recipients){
 const source=await publicProtectedKey(sender.publicKey);
 if(!await verifyProtected({context:envelope.context,ciphertext:envelope.ciphertext},envelope.signature,source.key))throw Error('Invalid sender signature.');
 const message=await pgp.readMessage({armoredMessage:envelope.ciphertext});
 const expected=await Promise.all(recipients.map(async r=>(await publicProtectedKey(r.publicKey)).encryptionId));
 const actual=message.getEncryptionKeyIDs().map(x=>x.toHex());
 if(JSON.stringify(actual.sort())!==JSON.stringify(expected.sort())||message.packets.some(p=>p.constructor.tag===3))throw Error('Encryption recipients differ from the authorized devices.');
}
export async function decryptProtected(envelope,privateKey,sender){
 const source=await publicProtectedKey(sender.publicKey);
 if(!await verifyProtected({context:envelope.context,ciphertext:envelope.ciphertext},envelope.signature,source.key))throw Error('Sender signature failed.');
 const result=await pgp.decrypt({message:await pgp.readMessage({armoredMessage:envelope.ciphertext}),decryptionKeys:privateKey,verificationKeys:source.key,expectSigned:true});
 for(const signature of result.signatures)await signature.verified;
 const opened=JSON.parse(result.data);
 if(canonical(opened.context)!==canonical(envelope.context))throw Error('Protected record context does not match.');
 return opened.payload;
}
