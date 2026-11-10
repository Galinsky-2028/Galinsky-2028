// Updates only observed GitHub PR facts; never infers completed work packages.
// A private-repo GitHub token is required. The default is read-only dry run.
// Execute from an isolated operator/CI context, not a public web request.
import {readFile,writeFile,rename} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
const REPO='Galinsky-2028/Galinsky-2028';
const PATH='registry/prs.json';
const validISO=s=>typeof s==='string'&&!Number.isNaN(Date.parse(s))&&
 /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(s);
const required=(value,message)=>{if(!value)throw new Error(message);};

export function withObservedPullRequests(previous,source,observedAt){
 required(previous?.repository===REPO&&previous.schemaVersion===1&&previous.roadmapVersion>0,
  'Unrecognized canonical PR registry.');
 required(Array.isArray(previous.units)&&previous.units.length===previous.plannedPrCount&&previous.planVerified===true,
  'Roadmap scope is not a verified complete plan.');
 required(Array.isArray(source)&&source.length>0&&source.length<=2500,'No complete GitHub snapshot was received.');
 required(validISO(observedAt),'The observation time must be UTC ISO.');
 const seen=new Set();
 const pullRequests=source.map(pr=>{
  required(Number.isSafeInteger(pr.id)&&pr.id>0&&Number.isSafeInteger(pr.number)&&pr.number>0,
   'GitHub returned an invalid PR identity.');
  required(!seen.has(pr.number),'GitHub returned a duplicate PR number.');
  seen.add(pr.number);
  required(typeof pr.title==='string'&&pr.title.trim()&&['open','closed'].includes(pr.state)&&
   typeof pr.draft==='boolean'&&validISO(pr.created_at)&&validISO(pr.updated_at),
   'GitHub returned an invalid PR record.');
  required((pr.closed_at===null||validISO(pr.closed_at))&&(pr.merged_at===null||validISO(pr.merged_at)),
   'GitHub returned an invalid PR closure timestamp.');
  required(pr.state!=='open'||(pr.closed_at===null&&pr.merged_at===null),
   'GitHub returned an inconsistent open PR.');
  required(pr.state!=='closed'||pr.closed_at!==null,
   'GitHub returned an inconsistent closed PR.');
  required(pr.merged_at===null||pr.state==='closed',
   'Merged PR must be closed.');
  required(!pr.merged_at||Date.parse(pr.merged_at)<=Date.parse(observedAt)+300000,
   'A merged PR has a future timestamp.');
  required(typeof pr.html_url==='string'&&pr.html_url===
   'https://github.com/'+REPO+'/pull/'+pr.number,'GitHub returned the wrong PR URL.');
  return {id:pr.id,number:pr.number,title:pr.title,url:pr.html_url,
   state:pr.state,draft:pr.draft,createdAt:pr.created_at,updatedAt:pr.updated_at,
   closedAt:pr.closed_at,mergedAt:pr.merged_at,
   headSha:pr.head?.sha||null,baseRef:pr.base?.ref||null,
   mergeCommitSha:pr.merge_commit_sha||null};
 }).sort((a,b)=>b.number-a.number);
 for(const unit of previous.units){
  required(Array.isArray(unit.prs),'Invalid existing explicit PR-to-package mapping.');
  required(unit.prs.every(n=>seen.has(n)),'An accepted explicit work-unit reference is missing from GitHub.');
 }
 // Preserve the immutable 60-unit roadmap and any independently approved
 // associations byte-for-byte; a merge is not full work-package acceptance.
 return {...previous,observedAt,pullRequests};
}
export async function fetchObservedPullRequests({token,fetchImpl=fetch}={}){
 required(typeof token==='string'&&token.length>10,'A GitHub read token is required for the private repository.');
 const all=[];
 for(let page=1;page<=25;page++){
  const url='https://api.github.com/repos/'+REPO+'/pulls?state=all&per_page=100&page='+page;
  const response=await fetchImpl(url,{headers:{Accept:'application/vnd.github+json',
   Authorization:'Bearer '+token,'X-GitHub-Api-Version':'2022-11-28'}});
  if(!response?.ok)throw new Error('Cannot refresh PR register from GitHub (HTTP '+response?.status+').');
  const items=await response.json();
  required(Array.isArray(items),'GitHub did not return the expected pull-request page.');
  all.push(...items);
  if(items.length<100)return all;
 }
 throw new Error('GitHub pagination exceeded a safe bound; refusing incomplete snapshot.');
}
async function main(){
 const args=process.argv.slice(2);
 if(args.some(x=>x!=='--write')||args.filter(x=>x==='--write').length>1)
  throw new Error('Usage: node scripts/refresh-pr-snapshot.mjs [--write]');
 const token=process.env.GITHUB_READ_TOKEN||process.env.GITHUB_TOKEN;
 const original=JSON.parse(await readFile(PATH,'utf8'));
 const items=await fetchObservedPullRequests({token});
 const doc=withObservedPullRequests(original,items,new Date().toISOString());
 const output=JSON.stringify(doc,null,2)+'\n';
 if(args.includes('--write')){
  const tmp=PATH+'.next-'+process.pid;
  await writeFile(tmp,output,{mode:0o600});
  await rename(tmp,PATH);
 }
 console.log(JSON.stringify({snapshot:args.includes('--write')?'written':'dry_run',
  repository:REPO,units:doc.units.length,observed:doc.pullRequests.length,
  merged:doc.pullRequests.filter(x=>x.mergedAt).length,
  explicitMappings:doc.units.filter(x=>x.prs.length).length,
  note:'Do not infer completed work-package acceptance from raw merge count.'}));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
 main().catch(e=>{console.error(e.message);process.exitCode=1;});
