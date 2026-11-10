import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {existsSync,readFileSync} from 'node:fs';
import {join} from 'node:path';
import {videoPanel} from '../packages/core/video.mjs';
import {renderPage,site,root} from '../scripts/public-renderer.mjs';

test('the owner-selected temporary YouTube video is consent-gated and labeled on all three issues',()=>{
 for(const issue of ['kirk-evers','garden','cornerstone']){
  assert.equal(site.issues[issue].youtubeId,'dpQulJS-R50');
  assert.equal(site.issues[issue].temporaryLocalVideo,undefined);
  const html=renderPage(issue);
  assert(html.includes('data-video="dpQulJS-R50"'));
  assert(html.includes('TEMPORARY VIDEO PREVIEW'));
  assert(html.includes('aria-label="Play temporary video for '));
  assert(html.includes('not the final issue-specific presentation'));
  assert(html.includes('Choosing Play connects to YouTube'));
  assert(!html.includes('<iframe'));
  assert(!html.includes('<video controls'));
 }
});

test('either render exact campaign-uploaded MP4 on all three preview pages or fall back safely',()=>{
 const asset=join(root,'apps/web/public/assets/issue-video-placeholder.mp4');
 const available=existsSync(asset);
 if(available){
  const bytes=readFileSync(asset);
  assert(bytes.length>100000&&bytes.length<=12000000,'Unexpected uploaded video size');
  assert.equal(bytes.toString('ascii',4,8),'ftyp','An MP4 container is required');
  const hash=createHash('sha256').update(bytes).digest('hex');
  const allowed=new Set([
   '8714bdde5cfced03ec49d90e26e7b83b08131f6f0312a1fd7228427b15ea16a7',
   'bab062faf1ed9b647daf73a40dbbeebf63ae04d8dfe669c43605697e56a20f5f'
  ]);
  assert(allowed.has(hash),'Uploaded video does not match either owner-supplied original or reviewed optimized edition');
 }
 const local={...site.issues.garden,youtubeId:null,temporaryLocalVideo:'/assets/issue-video-placeholder.mp4'};
 const html=videoPanel('garden',local,{localAssetExists:available});
 assert.equal(html.includes('<video controls'),available);
 if(available)assert(html.includes('TEMPORARY VIDEO PLACEHOLDER'));
 else assert(html.includes("Phillip's video introduction is coming soon."));
});
test('temporary unrelated illustrative video cannot silently become an official production issue video',()=>{
 const prod={...site,mode:'production',canonicalOrigin:'https://campaign.example.test'};
 for(const issue of ['kirk-evers','garden','cornerstone']){
  const html=renderPage(issue,{site:prod});
  assert(!html.includes('<video controls'),'Only an approved issue-specific final video may be published');
  assert(html.includes("Phillip's video introduction is coming soon."));
 }
});

test('unreviewed external URLs and simultaneous YouTube/temporary sources are rejected',()=>{
 const cfg={...site.issues.garden,youtubeId:null,temporaryLocalVideo:'/assets/issue-video-placeholder.mp4'};
 assert.throws(()=>videoPanel('garden',{...cfg,temporaryLocalVideo:'http://example.test/evil.mp4'},{localAssetExists:true}),/reviewed temporary/);
 assert.throws(()=>videoPanel('garden',{...cfg,youtubeId:'AbcdefG123_'},{localAssetExists:true}),/either the temporary/);
 assert(!videoPanel('garden',{...cfg,temporaryLocalVideo:null},{localAssetExists:true}).includes('<video'));
});
