// Operator tool for authenticated protected-reporting releases.
//
//   node security/release-evidence.mjs statement <sequence> <transport.json> > statement.json
//     Inventories the installed dist/portal bytes for the exact checked-out commit and signs the
//     release statement with the Ed25519 PKCS#8 PEM key in G28_RELEASE_SIGNING_KEY_FILE.
//     transport.json is the operator's TLS observation of the public origin:
//     {"origin":"https://...","tls13Only":true,"fallbackRefused":true,"observedAt":"<ISO time>"}.
//   node security/release-evidence.mjs assemble statement.json log-entry.json > dist/release-evidence.json
//     Combines the signed statement with the transparency log's inclusion proof and the
//     witness-cosigned checkpoint: {"index":n,"proof":[base64...],"checkpoint":{"body":"...","signatures":[{"keyId","signature"}]}}.
//   node security/release-evidence.mjs verify [dist/release-evidence.json]
//     Runs the same verification the API performs at startup and prints what is missing.
//
// The tool never fabricates a log entry, witness signature or transport observation.
import {createPrivateKey,createPublicKey} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {buildWebClosure} from './web-release-closure.mjs';
import {RELEASE_EVIDENCE_SCHEMA,canonicalJson,releaseStatement,signEd25519,publicKeyId,loadTrustPolicy,verifyReleaseEvidence} from '../packages/core/release-authenticity.mjs';

const [action,...args]=process.argv.slice(2);
const commit=()=>process.env.RENDER_GIT_COMMIT||execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
try{
 if(action==='statement'){
  const [sequence,transportPath]=args;
  if(!/^(0|[1-9][0-9]*)$/.test(sequence||'')||!transportPath)throw Error('Use: statement <sequence> <transport.json>');
  const keyFile=process.env.G28_RELEASE_SIGNING_KEY_FILE;if(!keyFile)throw Error('Set G28_RELEASE_SIGNING_KEY_FILE to the private release key (never commit it).');
  const key=createPrivateKey(readFileSync(keyFile));if(key.asymmetricKeyType!=='ed25519')throw Error('The release key must be Ed25519.');
  const publicKey=createPublicKey(key).export({format:'der',type:'spki'}).toString('base64');
  const closure=buildWebClosure(process.cwd(),commit(),['dist/portal']);
  const statement=releaseStatement({closure,sequence:Number(sequence),issuedAt:new Date().toISOString(),transport:JSON.parse(readFileSync(transportPath,'utf8'))});
  process.stdout.write(JSON.stringify({statement,closure,leaf:Buffer.from(canonicalJson(statement)).toString('base64'),releaseSignature:{keyId:publicKeyId(publicKey),signature:signEd25519(key,canonicalJson(statement))},publicKey},null,2)+'\n');
 }else if(action==='assemble'){
  const [statementPath,entryPath]=args;
  const s=JSON.parse(readFileSync(statementPath,'utf8')),e=JSON.parse(readFileSync(entryPath,'utf8'));
  process.stdout.write(JSON.stringify({schema:RELEASE_EVIDENCE_SCHEMA,statement:s.statement,closure:s.closure,releaseSignature:s.releaseSignature,inclusion:{index:e.index,proof:e.proof},checkpoint:e.checkpoint},null,2)+'\n');
 }else if(action==='verify'){
  const evidence=JSON.parse(readFileSync(args[0]||'dist/release-evidence.json','utf8'));
  const result=verifyReleaseEvidence({evidence,trust:loadTrustPolicy(),installedClosure:buildWebClosure(process.cwd(),commit(),['dist/portal']),publicOrigin:process.env.PUBLIC_ORIGIN||evidence.statement?.transport?.origin});
  process.stdout.write(JSON.stringify(result,null,2)+'\n');if(!result.ok)process.exitCode=1;
 }else throw Error('Use statement, assemble or verify.');
}catch(error){console.error('Release evidence: '+error.message);process.exitCode=1;}
