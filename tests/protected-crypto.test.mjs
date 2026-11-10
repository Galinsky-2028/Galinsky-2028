import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readMessage,decrypt as rawDecrypt} from 'openpgp';
import {newProtectedKey,publicProtectedKey,unlockProtectedKey,encryptProtected,decryptProtected,validateProtectedEnvelope,PROTECTED_PROFILE} from '../packages/core/protected-crypto.mjs';
import {protectedEnvelope} from '../packages/core/protected-records.mjs';
test('RFC9580 records authenticate context and exact recipients; host and wrong keys cannot open narratives or attachments',async()=>{
 const password='synthetic recovery passphrase only';
 const [a,b,c]=await Promise.all(['author','safety','outsider'].map(id=>newProtectedKey(id,password)));
 const [ak,bk,ck]=await Promise.all([a,b,c].map(k=>unlockProtectedKey(k.privateKey,password)));
 const context={profile:PROTECTED_PROFILE,recordId:randomUUID(),sequence:1,kind:'incident',sender:randomUUID(),recipients:[randomUUID(),randomUUID()].sort(),generation:1};
 const payload={text:'CONFIDENTIAL_CANARY_7592',attachment:{name:'sensitive.txt',bytes:Buffer.from('ATTACHMENT_CANARY_7492').toString('base64')}};
 const record=protectedEnvelope(await encryptProtected(context,payload,[a,b],ak));
 assert(!JSON.stringify(record).includes(payload.text));assert(!JSON.stringify(record).includes(payload.attachment.bytes));
 await validateProtectedEnvelope(record,a,[a,b]);assert.deepEqual(await decryptProtected(record,ak,a),payload);assert.deepEqual(await decryptProtected(record,bk,a),payload);
 // Independent OpenPGP API consumes the standard wire message directly.
 const interoperable=await rawDecrypt({message:await readMessage({armoredMessage:record.ciphertext}),decryptionKeys:bk,verificationKeys:(await publicProtectedKey(a.publicKey)).key,expectSigned:true});assert.deepEqual(JSON.parse(interoperable.data).payload,payload);
 await assert.rejects(decryptProtected(record,ck,a));await assert.rejects(decryptProtected(record,bk,c));
 await assert.rejects(validateProtectedEnvelope(record,a,[a,c]),/recipients/);
 await assert.rejects(decryptProtected({...record,context:{...context,recordId:randomUUID()}},bk,a),/signature/);
 await assert.rejects(unlockProtectedKey(a.privateKey,'wrong passphrase'));
 assert.equal((await publicProtectedKey(a.publicKey)).fingerprint.length,64);
 await assert.rejects(publicProtectedKey(a.privateKey));await assert.rejects(newProtectedKey('author','short'));
 assert.throws(()=>protectedEnvelope({...record,narrative:'plaintext forbidden'}));
});
