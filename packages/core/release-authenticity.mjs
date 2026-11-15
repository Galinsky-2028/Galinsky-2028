// Authenticated release, transparency-log and activation evidence for protected reporting.
//
// The protected volunteer reporting runtime may open only when the bytes this service is
// about to deliver to browsers are bound to:
//   1. a release statement signed by a pinned campaign release key (Ed25519), whose
//      sequence is not below the pinned anti-rollback floor;
//   2. inclusion of that exact statement in an append-only transparency log (RFC 9162
//      Merkle inclusion proof) at a checkpoint signed by the pinned log key AND cosigned
//      by a quorum of distinct pinned independent witness keys;
//   3. a transport observation (TLS 1.3 only at the exact public origin) carried inside
//      the signed statement, and
//   4. the operational conditions that are not code: verified staff identity and an
//      explicitly selected recipient-recovery policy.
// The trust roots live in security/release-trust.json. With no pinned keys the gate is
// closed, and nothing in the environment can substitute for a missing signature,
// proof, witness or observation. This module never invents success.
import {createHash,createPublicKey,verify as verifySignature,sign as createSignature} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {buildWebClosure} from '../../security/web-release-closure.mjs';

export const RELEASE_STATEMENT_SCHEMA='g28-release-statement/1';
export const RELEASE_EVIDENCE_SCHEMA='g28-release-evidence/1';
export const RECOVERY_POLICIES=Object.freeze(['no-backup','encrypted-recovery']);
const PROJECT='Galinsky-2028/Galinsky-2028';
const sha256=(bytes)=>createHash('sha256').update(bytes).digest();
const fail=(message)=>{throw Error('Release authenticity: '+message);};
const check=(condition,message)=>{if(!condition)fail(message);};

export function canonicalJson(value){
 if(Array.isArray(value))return '['+value.map(canonicalJson).join(',')+']';
 if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map((k)=>JSON.stringify(k)+':'+canonicalJson(value[k])).join(',')+'}';
 check(value===null||['string','number','boolean'].includes(typeof value),'unsupported JSON value');
 if(typeof value==='number')check(Number.isSafeInteger(value),'only safe integers are allowed');
 return JSON.stringify(value);
}
const b64=(s,label)=>{check(typeof s==='string'&&/^[A-Za-z0-9+/]+={0,2}$/.test(s),label+' must be base64');return Buffer.from(s,'base64');};

// Key identifiers are the SHA-256 of the DER SubjectPublicKeyInfo, so a pinned id cannot be
// paired with a different key.
export function publicKeyId(spkiBase64){return createHash('sha256').update(b64(spkiBase64,'public key')).digest('hex');}
function ed25519Key(entry,label){
 check(entry&&typeof entry==='object'&&typeof entry.publicKey==='string','missing '+label);
 const key=createPublicKey({key:b64(entry.publicKey,label),format:'der',type:'spki'});
 check(key.asymmetricKeyType==='ed25519',label+' must be Ed25519');
 check(entry.keyId===publicKeyId(entry.publicKey),label+' id does not match its key');
 return key;
}
function verifyEd25519(entry,label,message,signatureBase64){
 const key=ed25519Key(entry,label);
 return verifySignature(null,Buffer.from(message),key,b64(signatureBase64,label+' signature'));
}
export function signEd25519(privateKey,message){return createSignature(null,Buffer.from(message),privateKey).toString('base64');}

// ---- Trust policy -------------------------------------------------------------------
export function loadTrustPolicy(path=resolve('security/release-trust.json')){return validateTrustPolicy(JSON.parse(readFileSync(path,'utf8')));}
export function validateTrustPolicy(trust){
 check(trust&&trust.schemaVersion===1&&trust.project===PROJECT,'invalid trust policy identity');
 for(const field of ['releaseKeys','witnessKeys'])check(Array.isArray(trust[field]),field+' must be a list');
 check(trust.logKey===null||typeof trust.logKey==='object','logKey must be a key or null');
 check(Number.isSafeInteger(trust.witnessQuorum)&&trust.witnessQuorum>=2,'witness quorum must be at least two');
 check(Number.isSafeInteger(trust.minimumSequence)&&trust.minimumSequence>=0,'minimumSequence must be a non-negative integer');
 check(typeof trust.logOrigin==='string'&&trust.logOrigin.length>0,'logOrigin required');
 const all=[...trust.releaseKeys,...trust.witnessKeys,...(trust.logKey?[trust.logKey]:[])];
 all.forEach((k,i)=>ed25519Key(k,'pinned key '+i));
 const ids=all.map((k)=>k.keyId);
 check(new Set(ids).size===ids.length,'a key cannot serve two trust roles');
 return trust;
}
export function trustPolicyMissing(trust){
 const missing=[];
 if(!trust.releaseKeys.length)missing.push('no campaign release signing key is pinned');
 if(!trust.logKey)missing.push('no transparency log key is pinned');
 if(trust.witnessKeys.length<trust.witnessQuorum)missing.push(`fewer than ${trust.witnessQuorum} independent witness keys are pinned`);
 return missing;
}

// ---- RFC 9162 Merkle tree ------------------------------------------------------------
export const leafHash=(bytes)=>sha256(Buffer.concat([Buffer.from([0]),Buffer.from(bytes)]));
export const nodeHash=(left,right)=>sha256(Buffer.concat([Buffer.from([1]),left,right]));
// RFC 9162 section 2.1.3.2.
export function verifyInclusion({leaf,index,treeSize,proof,rootHash}){
 if(!(Number.isSafeInteger(index)&&Number.isSafeInteger(treeSize)&&index>=0&&index<treeSize&&Array.isArray(proof)))return false;
 let fn=index,sn=treeSize-1,r=Buffer.from(leaf);
 for(const p of proof){
  const sibling=Buffer.isBuffer(p)?p:b64(p,'proof node');
  if(sibling.length!==32||sn===0)return false;
  if((fn&1)===1||fn===sn){
   r=nodeHash(sibling,r);
   if((fn&1)===0)while((fn&1)===0&&fn!==0){fn>>=1;sn>>=1;}
  }else r=nodeHash(r,sibling);
  fn>>=1;sn>>=1;
 }
 return sn===0&&r.equals(Buffer.isBuffer(rootHash)?rootHash:b64(rootHash,'root hash'));
}
// Reference tree construction (RFC 9162 section 2.1.1); used by tests and by operators who
// need to reproduce a proof from a published log.
export function merkleRoot(leaves){
 if(leaves.length===0)return sha256(Buffer.alloc(0));
 if(leaves.length===1)return leaves[0];
 let k=1;while(k*2<leaves.length)k*=2;
 return nodeHash(merkleRoot(leaves.slice(0,k)),merkleRoot(leaves.slice(k)));
}
export function inclusionProof(leaves,index){
 if(leaves.length<=1)return [];
 let k=1;while(k*2<leaves.length)k*=2;
 return index<k?[...inclusionProof(leaves.slice(0,k),index),merkleRoot(leaves.slice(k))]
  :[...inclusionProof(leaves.slice(k),index-k),merkleRoot(leaves.slice(0,k))];
}

// A checkpoint body follows the transparency-log checkpoint convention:
// "<origin>\n<tree size>\n<base64 root hash>\n".
export function checkpointBody({origin,treeSize,rootHash}){return `${origin}\n${treeSize}\n${Buffer.isBuffer(rootHash)?rootHash.toString('base64'):rootHash}\n`;}
export function parseCheckpoint(body){
 check(typeof body==='string'&&body.endsWith('\n'),'checkpoint must be newline terminated');
 const lines=body.slice(0,-1).split('\n');
 check(lines.length===3,'checkpoint must have origin, size and root');
 check(/^(0|[1-9][0-9]{0,15})$/.test(lines[1]),'checkpoint size is invalid');
 const rootHash=b64(lines[2],'checkpoint root');check(rootHash.length===32,'checkpoint root must be 32 bytes');
 return {origin:lines[0],treeSize:Number(lines[1]),rootHash};
}

// ---- Release statement and evidence -----------------------------------------------------
export function releaseStatement({closure,sequence,issuedAt,transport}){
 return {schema:RELEASE_STATEMENT_SCHEMA,project:PROJECT,sourceCommit:closure.sourceCommit,buildRoots:closure.buildRoots,
  closureDigest:closure.closureDigest,sequence,issuedAt,transport};
}
function validateStatement(s){
 check(s&&s.schema===RELEASE_STATEMENT_SCHEMA&&s.project===PROJECT,'invalid release statement identity');
 check(/^[a-f0-9]{40}$/.test(s.sourceCommit),'release statement needs an exact source commit');
 check(/^sha256:[a-f0-9]{64}$/.test(s.closureDigest),'release statement needs a closure digest');
 check(Array.isArray(s.buildRoots)&&s.buildRoots.length>0,'release statement needs build roots');
 check(Number.isSafeInteger(s.sequence)&&s.sequence>=0,'release statement needs a sequence');
 check(typeof s.issuedAt==='string'&&!Number.isNaN(Date.parse(s.issuedAt)),'release statement needs an issue time');
 const t=s.transport;
 check(t&&typeof t.origin==='string'&&/^https:\/\/[a-z0-9.-]+$/.test(t.origin),'transport observation needs an https origin');
 check(t.tls13Only===true&&t.fallbackRefused===true,'transport observation must show TLS 1.3 only with fallback refused');
 check(typeof t.observedAt==='string'&&!Number.isNaN(Date.parse(t.observedAt)),'transport observation needs a time');
 return s;
}

// Verifies evidence against the pinned trust policy and the exact installed bytes.
// Returns {ok:true,...} or {ok:false,missing:[reasons]}; never throws for ordinary absence.
export function verifyReleaseEvidence({evidence,trust,installedClosure,publicOrigin,maxTransportAgeMs=30*24*3600*1000,now=Date.now()}){
 const missing=trustPolicyMissing(trust);
 if(missing.length)return {ok:false,missing};
 try{
  check(evidence&&evidence.schema===RELEASE_EVIDENCE_SCHEMA,'release evidence is missing or has the wrong schema');
  const statement=validateStatement(evidence.statement);
  const statementBytes=canonicalJson(statement);
  const releaseKey=trust.releaseKeys.find((k)=>k.keyId===evidence.releaseSignature?.keyId);
  check(releaseKey,'release statement is not signed by a pinned release key');
  check(verifyEd25519(releaseKey,'release key',statementBytes,evidence.releaseSignature.signature),'release signature is invalid');
  check(statement.sequence>=trust.minimumSequence,'release sequence is below the anti-rollback floor');
  check(canonicalJson(statement.buildRoots)===canonicalJson(installedClosure.buildRoots),'signed release covers different build roots');
  check(statement.sourceCommit===installedClosure.sourceCommit,'installed release was built from a different commit');
  check(statement.closureDigest===installedClosure.closureDigest,'installed bytes differ from the signed release');
  check(statement.transport.origin===publicOrigin,'transport observation is for a different origin');
  check(now-Date.parse(statement.transport.observedAt)<=maxTransportAgeMs,'transport observation is stale');
  const cp=evidence.checkpoint;check(cp&&typeof cp.body==='string'&&Array.isArray(cp.signatures),'transparency checkpoint is missing');
  const parsed=parseCheckpoint(cp.body);
  check(parsed.origin===trust.logOrigin,'checkpoint is from a different log');
  const sigs=new Map();for(const s of cp.signatures){check(s&&typeof s.keyId==='string'&&!sigs.has(s.keyId),'duplicate or malformed checkpoint signature');sigs.set(s.keyId,s.signature);}
  check(sigs.has(trust.logKey.keyId)&&verifyEd25519(trust.logKey,'log key',cp.body,sigs.get(trust.logKey.keyId)),'checkpoint is not signed by the pinned log');
  const witnesses=trust.witnessKeys.filter((k)=>sigs.has(k.keyId)&&verifyEd25519(k,'witness key',cp.body,sigs.get(k.keyId)));
  check(witnesses.length>=trust.witnessQuorum,`checkpoint has ${witnesses.length} valid independent witness cosignatures; ${trust.witnessQuorum} required`);
  const inc=evidence.inclusion;check(inc&&Array.isArray(inc.proof),'transparency inclusion proof is missing');
  const leaf=leafHash(Buffer.from(statementBytes));
  check(verifyInclusion({leaf,index:inc.index,treeSize:parsed.treeSize,proof:inc.proof,rootHash:parsed.rootHash}),'release statement is not included in the witnessed log checkpoint');
  return {ok:true,sequence:statement.sequence,closureDigest:statement.closureDigest,treeSize:parsed.treeSize,witnesses:witnesses.map((k)=>k.keyId)};
 }catch(error){return {ok:false,missing:[String(error.message).replace(/^Release authenticity: /,'')]};}
}

// The single activation decision used by the API configuration. Synchronous so startup
// refuses before any route is registered.
export function protectedActivationReadiness({env=process.env,staffIdentity,publicOrigin,root=process.cwd(),buildRoots=['dist/portal'],
 trustPath=resolve(root,'security/release-trust.json'),evidencePath=resolve(root,env.G28_RELEASE_EVIDENCE_PATH||'dist/release-evidence.json'),now=Date.now()}={}){
 const missing=[];
 if(!staffIdentity)missing.push('verified staff identity is not enabled');
 if(!RECOVERY_POLICIES.includes(env.G28_PROTECTED_RECOVERY_POLICY))missing.push('no recipient recovery policy (no-backup or encrypted-recovery) has been selected');
 let trust;
 try{trust=loadTrustPolicy(trustPath);}catch(error){missing.push('release trust policy is invalid: '+error.message);return {ready:false,missing};}
 let evidence=null,installed=null;
 try{evidence=JSON.parse(readFileSync(evidencePath,'utf8'));}catch{}
 try{const commit=env.RENDER_GIT_COMMIT||'';installed=buildWebClosure(root,commit,buildRoots);}catch(error){if(!trustPolicyMissing(trust).length)missing.push('installed release bytes cannot be inventoried: '+error.message);}
 const result=installed?verifyReleaseEvidence({evidence,trust,installedClosure:installed,publicOrigin,now}):{ok:false,missing:trustPolicyMissing(trust)};
 if(!result.ok)missing.push(...result.missing);
 return {ready:missing.length===0,missing,release:result.ok?result:null};
}
