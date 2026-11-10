import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,readdirSync} from 'node:fs';
test('historical source metadata remains unreviewed; only the explicit reviewed reading release is current',()=>{
 const manifest=JSON.parse(readFileSync('content/materials/archive-manifest.json','utf8'));
 const current=JSON.parse(readFileSync('content/materials/current.json','utf8'));
 const copies=readdirSync('content/materials/source-edition-1').filter(n=>/^\d\d_.+\.md$/.test(n));
 assert.equal(manifest.length,36);
 assert.equal(copies.length,35);
 assert(!copies.some(n=>n.startsWith('35_')),'Do not duplicate the compiled manual');
 for(const x of manifest){
  assert.equal(x.status,'unreviewed');
  assert.equal(x.review,null);
  if(!x.compiled)assert(copies.includes(x.source.filename));
 }
 assert.equal(current.length,19);
 for(const m of current){
  assert.equal(m.publication.mode,'owner-authorized-ai-reviewed');
  assert.equal(m.review.method,'ai-editorial-review');
  assert(m.provenance.every(p=>! /\/(?:00_|(?:1[6-9]|2[0-9]|30|34|35)_)/.test(p.path)),'Internal/reference-only and unrelated policy kits must not become current');
 }
});
