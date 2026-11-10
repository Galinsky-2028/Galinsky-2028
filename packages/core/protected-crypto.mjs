// Application profile G28-PGP-1. OpenPGP implements all cryptography. The host
// still controls delivered browser code; fingerprints must be checked elsewhere.
import * as pgp from 'openpgp';
import {protectedContext,protectedEnvelope,protectedPayload} from './protected-records.mjs';
export {PROTECTED_PROFILE} from './protected-profile.mjs';
const config={v6Keys:true,aeadProtect:true,preferredSymmetricAlgorithm:pgp.enums.symmetric.aes256,maxDecompressedMessageSize:260000,maxArgon2MemoryExponent:16};
// PostgreSQL JSONB and JSON transports reorder properties. Bind the same
// recursively sorted JSON representation at every signing/verifying boundary.
export const canonical=value=>JSON.stringify(sorted(value));
function sorted(value){return Array.isArray(value)?value.map(sorted):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(k=>[k,sorted(value[k])])):value;}
export async function newProtectedKey(accountId,passphrase){
 if(typeof passphrase!=='string'||passphrase.length<16||passphrase.length>256)throw Error('Use a recovery passphrase of 16–256 characters.');
 return pgp.generateKey({type:'curve25519',userIDs:[{name:accountId}],passphrase,format:'armored',config});
}
export async function publicProtectedKey(armored){
 if(typeof armored!=='string'||armored.length>12000)throw Error('Invalid public key.');
 const key=await pgp.readKey({armoredKey:armored,config});
 await key.verifyPrimaryKey();
 const encryption=await key.getEncryptionKey();
 if(key.isPrivate()||key.keyPacket.version!==6||key.getAlgorithmInfo().algorithm!=='ed25519'||encryption?.getAlgorithmInfo().algorithm!=='x25519'||key.users.length!==1||!key.users[0].userID)throw Error('A valid version 6 Ed25519/X25519 public key with one account identifier is required.');
 return {key,fingerprint:key.getFingerprint(),encryptionId:encryption.getKeyID().toHex(),encryptionFingerprint:encryption.getFingerprint()};
}
export async function unlockProtectedKey(armored,passphrase){if(typeof armored!=='string'||armored.length>20000)throw Error('Choose a bounded encrypted recovery key.');const key=await pgp.readPrivateKey({armoredKey:armored,config});await publicProtectedKey(key.toPublic().armor());return pgp.decryptKey({privateKey:key,passphrase,config});}
export async function signProtected(value,privateKey){return pgp.sign({message:await pgp.createMessage({text:canonical(value)}),signingKeys:privateKey,detached:true});}
export async function verifyProtected(value,signature,publicKey){
 try{
  const result=await pgp.verify({message:await pgp.createMessage({text:canonical(value)}),signature:await pgp.readSignature({armoredSignature:signature,config}),verificationKeys:publicKey,config});
  if(result.signatures.length!==1)return false;await result.signatures[0].verified;return true;
 }catch{return false;}
}
export async function encryptProtected(context,payload,recipients,privateKey){
 context=protectedContext(context);payload=protectedPayload(payload);
 const keys=await Promise.all(recipients.map(async r=>(await publicProtectedKey(r.publicKey)).key));
 const ciphertext=await pgp.encrypt({message:await pgp.createMessage({text:canonical({context,payload})}),encryptionKeys:keys,signingKeys:privateKey,format:'armored',config});
 const envelope={context,ciphertext};return {...envelope,signature:await signProtected(envelope,privateKey)};
}
export async function validateProtectedEnvelope(envelope,sender,recipients){
 envelope=protectedEnvelope(envelope);
 const source=await publicProtectedKey(sender.publicKey);
 if(!await verifyProtected({context:envelope.context,ciphertext:envelope.ciphertext},envelope.signature,source.key))throw Error('Invalid sender signature.');
 const message=await pgp.readMessage({armoredMessage:envelope.ciphertext,config});
 const expected=await Promise.all(recipients.map(async r=>(await publicProtectedKey(r.publicKey)).encryptionFingerprint));
 const packets=cipherPackets(message,envelope.context.recipients.length),actual=packets.map(p=>Array.from(p.publicKeyFingerprint||[],x=>x.toString(16).padStart(2,'0')).join(''));
 if(JSON.stringify(actual.sort())!==JSON.stringify(expected.sort()))throw Error('Encryption recipients differ from the authorized devices.');
}
function cipherPackets(message,count){const packets=message.packets.filter(p=>p.constructor.tag===1);if(packets.length!==count||packets.some(p=>p.version!==6||p.publicKeyVersion!==6)||message.packets.filter(p=>p.constructor.tag===18&&p.version===2).length!==1||message.packets.some(p=>![1,18,21].includes(p.constructor.tag)))throw Error('The encrypted message does not match the reviewed authenticated-encryption profile.');return packets;}
export async function decryptProtected(envelope,privateKey,sender){
 envelope=protectedEnvelope(envelope);
 const source=await publicProtectedKey(sender.publicKey);
 if(!await verifyProtected({context:envelope.context,ciphertext:envelope.ciphertext},envelope.signature,source.key))throw Error('Sender signature failed.');
 const message=await pgp.readMessage({armoredMessage:envelope.ciphertext,config});cipherPackets(message,envelope.context.recipients.length);
 const result=await pgp.decrypt({message,decryptionKeys:privateKey,verificationKeys:source.key,expectSigned:true,config});
 for(const signature of result.signatures)await signature.verified;
 if(typeof result.data!=='string'||result.data.length>260000)throw Error('Protected message exceeds the reviewed size limit.');
 const opened=JSON.parse(result.data);
 if(!opened||Object.keys(opened).sort().join(',')!=='context,payload'||canonical(protectedContext(opened.context))!==canonical(envelope.context))throw Error('Protected record context does not match.');
 return protectedPayload(opened.payload);
}
