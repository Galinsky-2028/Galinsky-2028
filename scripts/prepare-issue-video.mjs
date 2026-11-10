#!/usr/bin/env node
// Editorial helper only. Does not deploy, confer approval, or activate other features.
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {isIP} from 'node:net';
import {fileURLToPath} from 'node:url';
import {parseYouTubeId} from '../packages/core/video.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));

export function validatedWebsite(value){
 if(typeof value!=='string'||value.length>2048)throw Error('Website address is missing or too long.');
 let u;try{u=new URL(value);}catch{throw Error('Provide a complete HTTPS issue website URL.');}
 if(u.protocol!=='https:'||u.username||u.password||u.port||!u.hostname.includes('.')||u.hostname==='localhost'||u.hostname.endsWith('.local')||isIP(u.hostname.replace(/^\[|\]$/g,'')))throw Error('Issue websites must be public HTTPS addresses without credentials or custom ports.');
 return u.toString();
}

export function prepare(config,options){
 if(!config||typeof config!=='object'||!config.issues||!['kirk-evers','garden','cornerstone'].includes(options.issue))throw Error('Choose one configured issue: kirk-evers, garden, cornerstone.');
 if(!Object.hasOwn(config.issues,options.issue))throw Error('Issue is not configured.');
 const next=structuredClone(config);
 const issue=next.issues[options.issue];
 let changed=0;
 if(options.youtube!==undefined){issue.youtubeId=parseYouTubeId(options.youtube);if(!issue.youtubeId)throw Error('A real video ID is required.');issue.temporaryLocalVideo=null;issue.temporaryLabel=null;changed++;}
 if(options.website!==undefined){issue.websiteUrl=validatedWebsite(options.website);changed++;}
 if(options.transcript!==undefined){
  const bytes=readFileSync(resolve(options.transcript));
  if(bytes.length>200000)throw Error('Transcript exceeds 200 KB.');
  const contents=bytes.toString('utf8').replace(/\r\n?/g,'\n').trim();
  if(!contents||contents.includes('\uFFFD')||contents.includes('\0'))throw Error('Transcript must contain valid, nonempty UTF-8 text.');
  issue.transcript=contents;changed++;
 }
 if(changed===0)throw Error('Supply at least one of --youtube, --website or --transcript.');
 if(next.mode!==config.mode||next.donations.enabled!==config.donations.enabled)throw Error('Issue changes cannot modify release mode or donations.');
 return {config:next,changed};
}

export function parseArgs(argv){
 const args={write:false};const allowed=new Set(['--issue','--youtube','--website','--transcript','--config']);
 for(let i=0;i<argv.length;i++){
  const key=argv[i];if(key==='--write'){if(args.write)throw Error('Duplicate --write');args.write=true;continue;}
  if(!allowed.has(key)||argv[i+1]===undefined||argv[i+1].startsWith('--'))throw Error('Unknown or incomplete option: '+key);
  const name=key.slice(2);if(Object.hasOwn(args,name))throw Error('Duplicate option: '+key);args[name]=argv[++i];
 }
 return args;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const opts=parseArgs(process.argv.slice(2));
  const path=resolve(opts.config||root+'content/public/site.json');
  const original=JSON.parse(readFileSync(path,'utf8'));
  const {config,changed}=prepare(original,opts);
  if(opts.write)writeFileSync(path,JSON.stringify(config,null,2)+'\n','utf8');
  console.log((opts.write?'UPDATED CONFIGURATION':'VALID DRY RUN')+': '+opts.issue+' ('+changed+' editorial fields).');
  console.log('No video was uploaded, reviewed, published or deployed. Commit and review the config diff before release.');
 }catch(e){console.error('Issue configuration rejected: '+e.message);process.exitCode=1;}
}
