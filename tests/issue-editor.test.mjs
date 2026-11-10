import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {prepare,parseArgs,validatedWebsite} from '../scripts/prepare-issue-video.mjs';
import {videoPanel} from '../packages/core/video.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const original=JSON.parse(readFileSync(join(root,'content/public/site.json'),'utf8'));
const video='https://youtu.be/AbcdefG123_';
test('config preparation writes only selected issue fields',()=>{
 const {config,changed}=prepare(original,{issue:'garden',youtube:video,website:'https://example.org/garden'});
 assert.equal(changed,2);
 assert.equal(config.issues.garden.youtubeId,'AbcdefG123_');
 assert.equal(config.issues.garden.temporaryLocalVideo,null,'Published issue-specific video replaces shared temporary media.');
 assert.equal(config.issues.garden.websiteUrl,'https://example.org/garden');
 assert.deepEqual(config.issues.cornerstone,original.issues.cornerstone);
 assert.deepEqual(config.issues['kirk-evers'],original.issues['kirk-evers']);
 assert.equal(config.mode,original.mode);
 assert.equal(config.donations.enabled,false);
 assert.equal(original.issues.garden.youtubeId,'dpQulJS-R50');
 assert.equal(config.issues.garden.temporaryLabel,null,'A final issue-specific video clears its temporary label.');
 assert.match(videoPanel('garden',config.issues.garden),/data-video="AbcdefG123_"/);
});
for(const url of ['http://example.org','https://localhost/','https://user@example.org','https://example.org:444/','javascript:alert(1)','https://127.0.0.1/'])test('invalid outbound issue URL '+url,()=>assert.throws(()=>validatedWebsite(url)));
for(const issue of ['other','','../kirk-evers',null])test('invalid issue '+String(issue),()=>assert.throws(()=>prepare(original,{issue,youtube:video})));
test('cannot fake video ID or silently mutate donation/release gates',()=>{
 assert.throws(()=>prepare(original,{issue:'garden',youtube:'https://evil.example/watch?v=AbcdefG123_'}));
 assert.throws(()=>prepare(original,{issue:'garden'}));
 assert.throws(()=>parseArgs(['--issue','garden','--issue','cornerstone']));
});
test('CLI dry run has no file mutation; --write updates only copied config',()=>{
 const temp=mkdtempSync(join(tmpdir(),'g28-video-editor-'));
 try{
  const configPath=join(temp,'site.json');writeFileSync(configPath,JSON.stringify(original));
  const cli=join(root,'scripts/prepare-issue-video.mjs');
  let p=spawnSync(process.execPath,[cli,'--issue','garden','--youtube',video,'--config',configPath],{encoding:'utf8'});
  assert.equal(p.status,0,p.stderr);assert.deepEqual(JSON.parse(readFileSync(configPath,'utf8')),original);
  p=spawnSync(process.execPath,[cli,'--issue','garden','--youtube',video,'--config',configPath,'--write'],{encoding:'utf8'});
  assert.equal(p.status,0,p.stderr);assert.equal(JSON.parse(readFileSync(configPath,'utf8')).issues.garden.youtubeId,'AbcdefG123_');
 }finally{rmSync(temp,{force:true,recursive:true});}
});
