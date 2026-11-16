import {readFile,stat} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve,extname} from 'node:path';

// The portal build carries exactly one inline import map (apps/portal/release-integrity.mjs)
// whose integrity table covers every JavaScript chunk. The HTML response's policy allows
// that exact inline script by its SHA-256 hash and nothing else inline.
export const PORTAL_CSP_BASE="default-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
export function portalDocumentPolicy(html){
 const maps=[...String(html).matchAll(/<script type="importmap">([\s\S]*?)<\/script>/g)];
 const inline=[...String(html).matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>/g)];
 if(maps.length>1||inline.length!==maps.length)throw Error('Portal document has an unexpected inline script.');
 const sources=["'self'"];
 if(maps.length===1)sources.push(`'sha256-${createHash('sha256').update(maps[0][1],'utf8').digest('base64')}'`);
 return `${PORTAL_CSP_BASE}; script-src ${sources.join(' ')}`;
}
export function registerPortal(app,portalOrigin,buildDirectory=resolve('dist/portal'),evidencePath=resolve(buildDirectory,'..','release-evidence.json')){
 const portal=resolve(buildDirectory);
 // Published protected-release evidence for outside verifiers. It is untrusted data:
 // verifiers check it against their own pinned keys (tools/release-verifier).
 app.get('/.well-known/g28-release.json',async(req,reply)=>{
  try{const bytes=await readFile(evidencePath);JSON.parse(bytes.toString('utf8'));return reply.type('application/json').send(bytes);}
  catch{return reply.code(404).type('application/json').send({error:'release_evidence_not_published'});}
 });
 let documentCache=null;
 async function portalDocument(){
  if(documentCache)return documentCache;
  const html=await readFile(resolve(portal,'index.html'));
  documentCache={html,policy:portalDocumentPolicy(html.toString('utf8'))};
  return documentCache;
 }
 app.get('/*',async(req,reply)=>{
  if(req.url.startsWith('/api/'))return reply.code(404).send({error:'not_found'});
  const url=new URL(req.url,portalOrigin);const path=resolve(portal,'.'+decodeURIComponent(url.pathname));
  if(path!==portal&&!path.startsWith(portal+'/'))return reply.code(404).send('Not found');
  try{if((await stat(path)).isFile()&&path!==resolve(portal,'index.html')){const mime={'.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'};return reply.type(mime[extname(path)]||'application/octet-stream').send(await readFile(path));}}catch{}
  if(extname(path)&&path!==resolve(portal,'index.html'))return reply.code(404).type('text/plain').send('Not found');
  let doc;try{doc=await portalDocument();}catch{return reply.code(503).type('text/plain').send('The volunteer application build is not installed.');}
  return reply.header('Content-Security-Policy',doc.policy).type('text/html; charset=utf-8').send(doc.html);
 });
}
