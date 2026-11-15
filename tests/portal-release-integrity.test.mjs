import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import Fastify from 'fastify';
import {releaseIntegrity} from '../apps/portal/release-integrity.mjs';
import {portalDocumentPolicy,registerPortal} from '../apps/api/src/static.mjs';

const sri=(s)=>'sha384-'+createHash('sha384').update(s).digest('base64');
const html='<!doctype html><html><head><meta charset="UTF-8"><title>x</title>  <script type="module" crossorigin src="/assets/index-a.js"></script>\n  <link rel="modulepreload" crossorigin href="/assets/runtime-b.js">\n  <link rel="stylesheet" crossorigin href="/assets/index-c.css">\n</head><body></body></html>';
function bundle(source=html){
 return {
  'assets/index-a.js':{type:'chunk',fileName:'assets/index-a.js',code:'import("./lazy-d.js")'},
  'assets/runtime-b.js':{type:'chunk',fileName:'assets/runtime-b.js',code:'export{}'},
  'assets/lazy-d.js':{type:'chunk',fileName:'assets/lazy-d.js',code:'export const lazy=1'},
  'assets/index-c.css':{type:'asset',fileName:'assets/index-c.css',source:'body{}'},
  'index.html':{type:'asset',fileName:'index.html',source},
 };
}
const run=(b)=>{releaseIntegrity().generateBundle.handler({},b);return String(b['index.html'].source);};

test('every emitted chunk, including lazily imported ones, is bound by import-map integrity',()=>{
 const out=run(bundle());
 const map=JSON.parse(out.match(/<script type="importmap">(.*?)<\/script>/)[1]);
 assert.deepEqual(map.integrity,{'/assets/index-a.js':sri('import("./lazy-d.js")'),'/assets/lazy-d.js':sri('export const lazy=1'),'/assets/runtime-b.js':sri('export{}')});
 assert.match(out,/src="\/assets\/index-a\.js" integrity="sha384-[^"]+"/);
 assert.match(out,/href="\/assets\/runtime-b\.js" integrity="sha384-[^"]+"/);
 assert.match(out,new RegExp('href="/assets/index-c\\.css" integrity="'+sri('body{}').replace(/[+/]/g,'\\$&')+'"'));
 assert.ok(out.indexOf('importmap')<out.indexOf('type="module"'),'import map must precede module scripts');
});

test('unbound references and missing documents fail the build instead of shipping without integrity',()=>{
 assert.throws(()=>run(bundle(html.replace('/assets/index-c.css','/assets/other.css'))),/unhashed reference/);
 const b=bundle();delete b['index.html'];
 assert.throws(()=>releaseIntegrity().generateBundle.handler({},b),/index.html was not emitted/);
 assert.throws(()=>run(bundle(html.replace('<meta charset="UTF-8">',''))),/charset meta/);
});

test('the document policy allows only the exact import map by hash',()=>{
 const out=run(bundle());
 const map=out.match(/<script type="importmap">(.*?)<\/script>/)[1];
 const policy=portalDocumentPolicy(out);
 assert.match(policy,/script-src 'self' 'sha256-[A-Za-z0-9+/=]+'$/);
 assert.ok(policy.includes(createHash('sha256').update(map).digest('base64')));
 assert.doesNotMatch(policy,/unsafe-inline|unsafe-eval/);
 assert.throws(()=>portalDocumentPolicy(out.replace('</head>','<script>alert(1)</script></head>')),/unexpected inline script/);
 assert.equal(portalDocumentPolicy('<html><script type="module" src="/a.js"></script></html>').endsWith("script-src 'self'"),true);
});

test('the portal server sends the hash-bound policy with the document and serves assets unchanged',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'g28-portal-'));
 try{
  const out=run(bundle());await mkdir(join(dir,'assets'));
  await writeFile(join(dir,'index.html'),out);await writeFile(join(dir,'assets','lazy-d.js'),'export const lazy=1');
  const app=Fastify();registerPortal(app,'http://127.0.0.1',dir);
  for(const url of ['/','/tasks','/index.html']){
   const r=await app.inject({url});
   assert.equal(r.statusCode,200,url);assert.equal(r.headers['content-security-policy'],portalDocumentPolicy(out));
   assert.equal(r.body,out);
  }
  const asset=await app.inject({url:'/assets/lazy-d.js'});
  assert.equal(asset.statusCode,200);assert.equal(asset.body,'export const lazy=1');
  await writeFile(join(dir,'index.html'),out.replace('</head>','<script>alert(1)</script></head>'));
  const app2=Fastify();registerPortal(app2,'http://127.0.0.1',dir);
  assert.equal((await app2.inject({url:'/'})).statusCode,503,'a tampered document is refused');
  await app.close();await app2.close();
 }finally{await rm(dir,{recursive:true,force:true});}
});
