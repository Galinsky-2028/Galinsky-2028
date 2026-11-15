import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {buildWebClosure} from '../security/web-release-closure.mjs';
import {loadConfig} from '../apps/api/src/config.mjs';
import {
 canonicalJson,publicKeyId,signEd25519,leafHash,merkleRoot,inclusionProof,verifyInclusion,checkpointBody,
 releaseStatement,verifyReleaseEvidence,validateTrustPolicy,loadTrustPolicy,protectedActivationReadiness,RELEASE_EVIDENCE_SCHEMA,
} from '../packages/core/release-authenticity.mjs';

const COMMIT='a'.repeat(40),ORIGIN='https://galinsky2028-volunteers.onrender.com',NOW=Date.parse('2026-11-15T12:00:00Z');
function keypair(){const {publicKey,privateKey}=generateKeyPairSync('ed25519');const spki=publicKey.export({format:'der',type:'spki'}).toString('base64');return {privateKey,entry:{keyId:publicKeyId(spki),publicKey:spki}};}
const release=keypair(),log=keypair(),w1=keypair(),w2=keypair(),w3=keypair(),stranger=keypair();
const trust=validateTrustPolicy({schemaVersion:1,project:'Galinsky-2028/Galinsky-2028',note:'test',releaseKeys:[release.entry],logOrigin:'log.example/g28',logKey:log.entry,witnessKeys:[w1.entry,w2.entry,w3.entry],witnessQuorum:2,minimumSequence:3});

async function fixture(){
 const root=await mkdtemp(join(tmpdir(),'g28-release-'));
 await mkdir(join(root,'dist/portal/assets'),{recursive:true});
 await writeFile(join(root,'dist/portal/index.html'),'<!doctype html><title>portal</title>');
 await writeFile(join(root,'dist/portal/assets/app.js'),'export const app=1;');
 return root;
}
function evidenceFor(root,{sequence=3,transport={origin:ORIGIN,tls13Only:true,fallbackRefused:true,observedAt:'2026-11-14T12:00:00Z'},witnesses=[w1,w2],index=5,size=9,closure}={}){
 const installed=closure||buildWebClosure(root,COMMIT,['dist/portal']);
 const statement=releaseStatement({closure:installed,sequence,issuedAt:'2026-11-14T12:00:00Z',transport});
 const bytes=Buffer.from(canonicalJson(statement));
 const leaves=Array.from({length:size},(_,i)=>i===index?leafHash(bytes):leafHash(Buffer.from('other release '+i)));
 const body=checkpointBody({origin:'log.example/g28',treeSize:size,rootHash:merkleRoot(leaves)});
 return {
  schema:RELEASE_EVIDENCE_SCHEMA,statement,
  releaseSignature:{keyId:release.entry.keyId,signature:signEd25519(release.privateKey,canonicalJson(statement))},
  inclusion:{index,proof:inclusionProof(leaves,index).map((b)=>b.toString('base64'))},
  checkpoint:{body,signatures:[{keyId:log.entry.keyId,signature:signEd25519(log.privateKey,body)},...witnesses.map((w)=>({keyId:w.entry.keyId,signature:signEd25519(w.privateKey,body)}))]},
 };
}
const verify=(root,evidence,extra={})=>verifyReleaseEvidence({evidence,trust,installedClosure:buildWebClosure(root,COMMIT,['dist/portal']),publicOrigin:ORIGIN,now:NOW,...extra});

// The tree size itself is authenticated by the signed checkpoint, not by the proof.
test('RFC 9162 inclusion proofs verify for every leaf of every tree size and reject any change',()=>{
 for(let size=1;size<=17;size++){
  const leaves=Array.from({length:size},(_,i)=>leafHash(Buffer.from('leaf '+i))),root=merkleRoot(leaves);
  for(let index=0;index<size;index++){
   const proof=inclusionProof(leaves,index);
   assert.equal(verifyInclusion({leaf:leaves[index],index,treeSize:size,proof,rootHash:root}),true,`${size}/${index}`);
   assert.equal(verifyInclusion({leaf:leaves[(index+1)%size],index,treeSize:size,proof,rootHash:root}),size===1,'wrong leaf');
   if(proof.length){const bad=proof.map((p)=>Buffer.from(p));bad[0][0]^=1;assert.equal(verifyInclusion({leaf:leaves[index],index,treeSize:size,proof:bad,rootHash:root}),false);}
   assert.equal(verifyInclusion({leaf:leaves[index],index:size,treeSize:size,proof,rootHash:root}),false,'index outside the tree');
  }
 }
 assert.equal(verifyInclusion({leaf:leafHash(Buffer.from('x')),index:1,treeSize:1,proof:[],rootHash:leafHash(Buffer.from('x'))}),false);
});

test('a signed, logged, witnessed release of the exact installed bytes verifies',async()=>{
 const root=await fixture();
 try{
  const result=verify(root,evidenceFor(root));
  assert.equal(result.ok,true,JSON.stringify(result));assert.equal(result.sequence,3);assert.equal(result.witnesses.length,2);
 }finally{await rm(root,{recursive:true,force:true});}
});

test('tampering, rollback, missing witnesses, wrong log/origin and stale transport fail closed',async()=>{
 const root=await fixture();
 try{
  const good=evidenceFor(root);
  const cases={
   'installed bytes differ':async()=>{await writeFile(join(root,'dist/portal/assets/app.js'),'export const app=2;');const r=verify(root,good);await writeFile(join(root,'dist/portal/assets/app.js'),'export const app=1;');return r;},
   'anti-rollback':()=>verify(root,evidenceFor(root,{sequence:2})),
   'witness cosignatures':()=>verify(root,evidenceFor(root,{witnesses:[w1]})),
   'duplicate or malformed':()=>{const e=evidenceFor(root,{witnesses:[w1]});e.checkpoint.signatures.push({...e.checkpoint.signatures[1]});return verify(root,e);},
   'not signed by the pinned log':()=>{const e=evidenceFor(root);e.checkpoint.signatures[0]={keyId:log.entry.keyId,signature:signEd25519(stranger.privateKey,e.checkpoint.body)};return verify(root,e);},
   'not signed by a pinned release key':()=>{const e=evidenceFor(root);e.releaseSignature={keyId:stranger.entry.keyId,signature:signEd25519(stranger.privateKey,canonicalJson(e.statement))};return verify(root,e);},
   'release signature is invalid':()=>{const e=evidenceFor(root);e.statement={...e.statement,sequence:4};return verify(root,e);},
   'not included':()=>{const e=evidenceFor(root);e.inclusion.index=4;return verify(root,e);},
   'different origin':()=>verify(root,evidenceFor(root),{publicOrigin:'https://example.org'}),
   'stale':()=>verify(root,evidenceFor(root),{now:Date.parse('2027-02-01T00:00:00Z')}),
   'TLS 1.3 only':()=>verify(root,evidenceFor(root,{transport:{origin:ORIGIN,tls13Only:false,fallbackRefused:true,observedAt:'2026-11-14T12:00:00Z'}})),
   'different log':()=>{const e=evidenceFor(root);const body=e.checkpoint.body.replace('log.example/g28','other.example/log');e.checkpoint={body,signatures:[log,w1,w2].map((k)=>({keyId:k.entry.keyId,signature:signEd25519(k.privateKey,body)}))};return verify(root,e);},
   'wrong schema':()=>verify(root,{...good,schema:'other'}),
  };
  for(const [reason,run] of Object.entries(cases)){
   const result=await run();
   assert.equal(result.ok,false,reason);assert.match(result.missing.join(' '),new RegExp(reason),reason);
  }
 }finally{await rm(root,{recursive:true,force:true});}
});

test('trust policy rejects weak quorums, mismatched ids and keys reused across roles',()=>{
 const base={schemaVersion:1,project:'Galinsky-2028/Galinsky-2028',releaseKeys:[],logOrigin:'x',logKey:null,witnessKeys:[],witnessQuorum:2,minimumSequence:0};
 assert.throws(()=>validateTrustPolicy({...base,witnessQuorum:1}),/quorum/);
 assert.throws(()=>validateTrustPolicy({...base,releaseKeys:[{...release.entry,keyId:'0'.repeat(64)}]}),/id does not match/);
 assert.throws(()=>validateTrustPolicy({...base,releaseKeys:[release.entry],witnessKeys:[release.entry]}),/two trust roles/);
 const {publicKey}=generateKeyPairSync('ec',{namedCurve:'P-256'});const spki=publicKey.export({format:'der',type:'spki'}).toString('base64');
 assert.throws(()=>validateTrustPolicy({...base,releaseKeys:[{keyId:publicKeyId(spki),publicKey:spki}]}),/Ed25519/);
});

test('the committed trust policy pins no keys, so the deployed gate stays closed',()=>{
 const committed=loadTrustPolicy();
 assert.deepEqual([committed.releaseKeys.length,committed.logKey,committed.witnessKeys.length],[0,null,0]);
 assert.throws(()=>loadConfig({PROTECTED_CONTENT_ENABLED:'true',STAFF_IDENTITY_ENABLED:'false',G28_PROTECTED_RECOVERY_POLICY:'no-backup'}),
  (e)=>e.code==='protected_unavailable'&&e.status===503&&/no campaign release signing key is pinned/.test(e.message)&&/verified staff identity/.test(e.message));
});

test('activation needs staff identity and a selected recovery policy in addition to verified release evidence',async()=>{
 const root=await fixture();
 try{
  await mkdir(join(root,'security'));await writeFile(join(root,'security/release-trust.json'),JSON.stringify(trust));
  await writeFile(join(root,'dist/release-evidence.json'),JSON.stringify(evidenceFor(root)));
  const env={RENDER_GIT_COMMIT:COMMIT,G28_PROTECTED_RECOVERY_POLICY:'no-backup'};
  const ready=protectedActivationReadiness({env,staffIdentity:true,publicOrigin:ORIGIN,root,now:NOW});
  assert.equal(ready.ready,true,ready.missing.join('; '));
  assert.deepEqual(protectedActivationReadiness({env,staffIdentity:false,publicOrigin:ORIGIN,root,now:NOW}).missing,['verified staff identity is not enabled']);
  assert.match(protectedActivationReadiness({env:{...env,G28_PROTECTED_RECOVERY_POLICY:'server-escrow'},staffIdentity:true,publicOrigin:ORIGIN,root,now:NOW}).missing[0],/recovery policy/);
  assert.match(protectedActivationReadiness({env:{...env,RENDER_GIT_COMMIT:'b'.repeat(40)},staffIdentity:true,publicOrigin:ORIGIN,root,now:NOW}).missing.join(' '),/different commit/);
  await rm(join(root,'dist/release-evidence.json'));
  assert.match(protectedActivationReadiness({env,staffIdentity:true,publicOrigin:ORIGIN,root,now:NOW}).missing.join(' '),/release evidence is missing/);
 }finally{await rm(root,{recursive:true,force:true});}
});
