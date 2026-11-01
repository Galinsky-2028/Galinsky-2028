import {chromium,firefox,webkit} from 'playwright';
import {checkNavigation} from './navigation-checks.mjs';
import {createServer} from 'node:http';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import assert from 'node:assert/strict';
import {videoPanel} from '../../packages/core/video.mjs';
const root=resolve('dist/web'),origin='http://127.0.0.1:4441';
const server=createServer(async(req,res)=>{
 try{
  const url=new URL(req.url,origin);
  if(url.pathname==='/synthetic-video'){
   res.setHeader('Content-Type','text/html');res.end('<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Synthetic video test</title><link rel="stylesheet" href="/assets/site.css"></head><body>'+videoPanel('synthetic',{youtubeId:'abcDEF123_-',title:'Synthetic introduction',poster:'/assets/garden.svg'})+'<script src="/assets/public.js"></script></body></html>');return;
  }
  let path=resolve(root,'.'+url.pathname);assert(path===root||path.startsWith(root+'/'));if(!extname(path))path=resolve(path,'index.html');
  const types={'.html':'text/html','.css':'text/css','.js':'text/javascript','.svg':'image/svg+xml','.webp':'image/webp'};
  res.setHeader('Content-Type',types[extname(path)]||'application/octet-stream');res.end(await readFile(path));
 }catch{res.writeHead(404);res.end('Not found');}
});
await new Promise(r=>server.listen(4441,'127.0.0.1',r));await mkdir('test-results/public-interactions',{recursive:true});const evidence=[];
try{
 for(const [name,engine]of Object.entries({chromium,firefox,webkit})){
  const browser=await engine.launch({headless:true});
  try{
   const navigation=await checkNavigation(browser,origin,`test-results/public-interactions/${name}`);
   const context=await browser.newContext({viewport:{width:390,height:844}}),page=await context.newPage(),external=[];
   page.on('request',r=>{if(r.url().startsWith('https://'))external.push(r.url());});
   await page.route('https://www.youtube-nocookie.com/**',route=>route.fulfill({contentType:'text/html',body:'<html><body>Synthetic embedded player; no external provider contacted.</body></html>'}));
   await page.goto(origin+'/synthetic-video');assert.equal(external.length,0);assert.equal(await page.locator('iframe').count(),0);
   const play=page.getByRole('button',{name:'Play Synthetic introduction on YouTube'});await play.click();
   const stop=page.getByRole('button',{name:'Stop video and disconnect YouTube'});await stop.waitFor();assert.equal(await page.locator('iframe').count(),1);
   assert.equal(await stop.evaluate(el=>el===document.activeElement),true);
   await stop.click();assert.equal(await page.locator('iframe').count(),0);assert.equal(await play.evaluate(el=>el===document.activeElement),true);
   await play.click();assert.equal(await page.locator('iframe').count(),1);await stop.click();
   const nojs=await browser.newContext({javaScriptEnabled:false,viewport:{width:390,height:844}}),still=await nojs.newPage();
   await still.goto(origin+'/');const bg=await still.locator('.flag-canvas').evaluate(el=>getComputedStyle(el).backgroundImage);assert(bg.includes('/assets/network-flag.svg'));
   const response=await nojs.request.get(origin+'/assets/network-flag.svg');assert.equal(response.status(),200);assert.match(await response.text(),/<svg/);
   await still.screenshot({path:`test-results/public-interactions/${name}-nojs-home.png`,fullPage:true});
   const animated=await context.newPage();
   await animated.goto(origin+'/');
   const motionControl=animated.getByRole('button',{name:'Pause flag animation'});
   await motionControl.waitFor();
   assert.equal(await motionControl.getAttribute('aria-pressed'),'false');
   await motionControl.click();
   const resume=animated.getByRole('button',{name:'Resume flag animation'});
   assert.equal(await resume.getAttribute('aria-pressed'),'true');
   assert.equal(await animated.evaluate(()=>localStorage.getItem('g28-hero-motion-paused')),'true');
   await animated.reload();
   assert.equal(await animated.getByRole('button',{name:'Resume flag animation'}).getAttribute('aria-pressed'),'true');
   await animated.getByRole('button',{name:'Resume flag animation'}).click();
   assert.equal(await animated.getByRole('button',{name:'Pause flag animation'}).getAttribute('aria-pressed'),'false');
   await animated.close();
   evidence.push({browser:name,...navigation,noRequestBeforePlay:true,disconnectAndReplay:true,focusRestored:true,staticFlagWithoutJavaScript:true,persistentMotionControl:true});
  }finally{await browser.close();}
 }
}finally{await new Promise(r=>server.close(r));await writeFile('test-results/public-interactions/results.json',JSON.stringify(evidence,null,2));}
console.log(JSON.stringify(evidence,null,2));
