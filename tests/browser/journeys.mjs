// Isolated test server. Synthetic material and mail transport do not ship in the app.
import {chromium,firefox,webkit} from 'playwright';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {resolve,extname} from 'node:path';
import {createApp} from '../../apps/api/src/app.mjs';
import {MemoryStore} from '../../apps/api/src/memory-store.mjs';
import {loadConfig} from '../../apps/api/src/config.mjs';
import {registerPortal} from '../../apps/api/src/static.mjs';
import {openDelivery} from '../../packages/core/auth.mjs';
const publicOrigin='http://127.0.0.1:4421',portalOrigin='http://127.0.0.1:4422';
const cfg=loadConfig({NODE_ENV:'test',PUBLIC_ORIGIN:publicOrigin,PORTAL_ORIGIN:portalOrigin,SIGNUP_ENABLED:'true',G28_HELP_REQUESTS_ENABLED:'true',MAIL_PROVIDER:'resend',RESEND_API_KEY:'synthetic-test-only',MAIL_FROM:'test@example.test',DELIVERY_KEY:randomBytes(32).toString('base64'),LOGIN_PEPPER:randomBytes(32).toString('hex')});
const store=new MemoryStore({materials:[{id:'synthetic-guide',title:'Synthetic test guide',description:'This fixture is not campaign guidance.',category:'start',revision:1,status:'published',audience:'volunteer',body:'# Synthetic test guide\n\nOnly used to verify the application.\n\n## Getting started\n\nUseful synthetic content.\n\n## A second section\n\n| Stage | Value |\n| --- | --- |\n| Prepared | Yes |',author:'fixture-author',review:{approvedBy:'test-fixture',revision:1,at:'2026-10-10'}}]});
const app=createApp({store,config:cfg});registerPortal(app,portalOrigin);
const root=resolve('dist/web');const web=createServer(async(req,res)=>{
 try{const u=new URL(req.url,publicOrigin);let p=resolve(root,'.'+decodeURIComponent(u.pathname));if(p!==root&&!p.startsWith(root+'/'))throw Error('Invalid path');if(!extname(p))p=resolve(p,'index.html');const bytes=await readFile(p);const mime={'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.webp':'image/webp','.txt':'text/plain'};res.setHeader('Content-Type',mime[extname(p)]||'application/octet-stream');res.end(bytes);}catch{res.writeHead(404);res.end('Not found');}
});
await app.listen({host:'127.0.0.1',port:4422});await new Promise(r=>web.listen(4421,'127.0.0.1',r));await mkdir('test-results/browser',{recursive:true});const evidence=[];
try{
 for(const [name,engine]of Object.entries({chromium,firefox,webkit})){
  const browser=await engine.launch({headless:true});const context=await browser.newContext({reducedMotion:'reduce'});const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
  const outside=[];page.on('request',r=>{if(/^https?:/.test(r.url())&&!r.url().startsWith(publicOrigin)&&!r.url().startsWith(portalOrigin))outside.push(r.url());});
  for(const width of [320,390,768,1440]){
   await page.setViewportSize({width,height:900});
   for(const path of ['/','/issues/','/issues/kirk-evers/','/issues/garden/','/issues/cornerstone/','/volunteer/','/donate/','/notices/']){
    const response=await page.goto(publicOrigin+path);assert.equal(response.status(),200);await page.locator('h1').waitFor();assert.equal(await page.locator('h1').count(),1);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,path+' at '+width);
   }
  }
  // The public landing page must NOT impersonate a live volunteer account.
  // Its twelve role paths must point to the actual React/API portal.
  await page.goto(publicOrigin+'/volunteer/');
  assert.equal(await page.locator('#preview-workspace').count(),0);
  assert.equal(await page.locator('#preview-download').count(),0);
  assert.equal(await page.locator('.role-grid a[data-role-id]').count(),12);
  assert.equal(await page.locator('.role-tile').first().evaluate(card=>getComputedStyle(card.querySelector('a'),'::after').position),'absolute',
    'Public role tile must be clickable across the whole card, not just link text');
  assert.equal(await page.locator('.role-grid a[data-role-id="13"]').getAttribute('href'),
    'https://galinsky2028-volunteers.onrender.com/roles?role=skills');
  await page.locator('#role-pref').selectOption('skills');
  assert.equal(await page.locator('#role-result').innerText(),'Skills & Operations Volunteer');
  assert.match(await page.locator('#role-open').getAttribute('href'),/\/roles\?role=skills$/);
  await page.locator('#role-training').selectOption('no');
  await page.locator('#role-pref').selectOption('ballot');
  assert.equal(await page.locator('#role-result').innerText(),'Personal Network Organizer');
  assert.match(await page.locator('#role-open').getAttribute('href'),/\/roles\?role=network$/);
  // Verify the SAME role link reaches the canonical live-application component
  // in the isolated test server; no call to the live Render host is required.
  await page.goto(portalOrigin+'/roles?role=skills');
  assert.equal(await page.getByLabel('What would you enjoy?').inputValue(),'skills');
  await page.goto(portalOrigin+'/roles?role=ballot');
  assert.equal(await page.getByLabel('What would you enjoy?').inputValue(),'ballot');
  await page.getByText('Authorization required before the activity.').waitFor();
  // A click on card padding (not the text link) must navigate to a real role detail route.
  await page.locator('article.role-card').filter({has:page.getByRole('heading',{name:'Skills and Operations'})}).click({position:{x:8,y:8}});
  assert.match(page.url(),/\/roles\/skills$/);
  await page.getByRole('heading',{name:'Skills and Operations',exact:true}).waitFor();
  await page.getByRole('link',{name:/Join the team/}).waitFor();
  await page.goto(portalOrigin+'/roles');
  await page.locator('article.role-card').filter({has:page.getByRole('heading',{name:'Ballot-Access Petition Volunteer'})}).click({position:{x:8,y:8}});
  assert.match(page.url(),/\/roles\/ballot$/);
  await page.getByText('requires current, activity-specific authorization').waitFor();
  const roleResponse=await context.request.get(portalOrigin+'/api/roles');
  assert.equal(roleResponse.status(),200);
  assert.equal((await roleResponse.json()).roles.length,12);
  assert.equal(outside.length,0,'No third-party request before activation');
  await page.goto(publicOrigin+'/');await page.setViewportSize({width:390,height:844});await page.locator('#menu-toggle').click();assert.equal(await page.locator('#menu-toggle').getAttribute('aria-expanded'),'true');
  await page.screenshot({path:`test-results/browser/${name}-home-mobile.png`,fullPage:true});
  await page.goto(portalOrigin+'/join');await page.getByLabel('Email address').fill(name+'@example.test');await page.getByRole('checkbox').first().check();await page.getByRole('button',{name:/Email my sign-in link/}).click();await page.getByText(/When delivery is available/).waitFor();
  const queued=store.outbox.findLast(job=>job.kind==='account_login'&&openDelivery(job.envelope,cfg.deliveryKey).email===name+'@example.test');assert(queued,'The accepted request queued its login message');const mail=openDelivery(queued.envelope,cfg.deliveryKey);assert.equal(mail.email,name+'@example.test');await page.goto(mail.url);await page.getByRole('button',{name:'Continue to my workspace'}).click();await page.getByRole('button',{name:'Sign out'}).waitFor();
  // Real role preferences are saved behind the volunteer session and persist.
  await page.goto(portalOrigin+'/roles');
  await page.locator('article.role-card').filter({has:page.getByRole('heading',{name:'Digital Ambassador'})}).click({position:{x:8,y:8}});
  assert.match(page.url(),/\/roles\/digital$/);
  await page.getByRole('link',{name:/Start orientation/}).waitFor();
  await page.getByRole('link',{name:/Read approved guides/}).waitFor();
  await page.goto(portalOrigin+'/roles');
  await page.getByLabel('What would you enjoy?').selectOption('skills');
  await page.getByRole('button',{name:'Save role preference'}).click();
  await page.getByText(/were saved to your account/).waitFor();
  await page.reload();
  await page.waitForFunction(()=>document.querySelector('.chooser select')?.value==='skills',undefined,{timeout:10000});
  assert.equal(await page.getByLabel('What would you enjoy?').inputValue(),'skills');
  const prefs=await context.request.get(portalOrigin+'/api/account/role-preferences');
  assert.equal(prefs.status(),200);
  assert.equal((await prefs.json()).preferences.roleId,'skills');
  // New help workflow: structured metadata only, private status, mobile
  // reflow and actual saved/withdrawn states in all three browser engines.
  await page.goto(portalOrigin+'/help');
  await page.getByRole('heading',{name:'Help and corrections.'}).waitFor();
  assert.equal(await page.locator('.help-form textarea, .help-form input[type="file"]').count(),0,
    'Structured help intake must not accept sensitive incident narratives or uploads');
  await page.getByLabel('What do you need help with?').selectOption('material_correction');
  await page.getByLabel('Which area is affected?').selectOption('issues');
  await page.getByRole('button',{name:'Save structured request'}).click();
  await page.getByText(/Your structured request was stored/).waitFor();
  let privateHelp=await context.request.get(portalOrigin+'/api/help/requests');
  assert.equal(privateHelp.status(),200);
  assert.equal((await privateHelp.json()).requests.length,1);
  await page.reload();
  await page.getByText('Received (not yet acknowledged)').waitFor();
  await page.setViewportSize({width:320,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,
    'Help page should reflow without horizontal scrolling at 320px');
  await page.screenshot({path:`test-results/browser/${name}-structured-help-mobile.png`,fullPage:true});
  await page.getByRole('button',{name:'Withdraw'}).click();
  await page.getByText('The request was withdrawn.').waitFor();
  privateHelp=await context.request.get(portalOrigin+'/api/help/requests');
  assert.equal((await privateHelp.json()).requests[0].status,'withdrawn');
  await page.setViewportSize({width:390,height:844});
  // Account-only checklist persists across reloads without certifying fieldwork.
  // SPA route changes must announce a new page and move keyboard/screen-reader focus.
  await page.getByRole('link',{name:'Available actions'}).click();
  await page.waitForFunction(()=>document.activeElement?.id==='main');
  assert.equal(await page.title(),'Available actions | Galinsky 2028');
  await page.goto(portalOrigin+'/tasks');
  await page.getByRole('button',{name:'Mark complete'}).first().waitFor();
  assert.equal(await page.getByRole('button',{name:'Mark complete'}).count(),3,'No restricted actions may be self-certified');
  await page.getByRole('button',{name:'Mark complete'}).first().click();
  await page.getByText('Your first steps: 1 of 3 marked complete. You can change these at any time.').waitFor();
  await page.reload();
  await page.getByRole('button',{name:'Completed - undo'}).first().waitFor();
  await page.getByRole('button',{name:'Completed - undo'}).first().click();
  await page.getByText('Your first steps: 0 of 3 marked complete. You can change these at any time.').waitFor();
  await page.goto(portalOrigin+'/materials');await page.getByLabel('Search the library').fill('Synthetic');await page.getByRole('heading',{name:'Synthetic test guide'}).waitFor();await page.getByRole('link',{name:/Read the guide/}).click();await page.getByRole('heading',{name:'Synthetic test guide'}).first().waitFor();const contents=page.getByRole('navigation',{name:'On this page'});await contents.getByRole('link',{name:'Getting started'}).click();assert.equal(await page.locator('#getting-started').count(),1);assert.equal(await page.getByRole('table').count(),1);await page.getByRole('button',{name:'Bookmark to my account'}).click();
  await page.getByRole('button',{name:'Saved to my account'}).waitFor();
  await page.reload();
  await page.getByRole('button',{name:'Saved to my account'}).waitFor();
  const bookmarks=await context.request.get(portalOrigin+'/api/account/bookmarks');
  assert.equal(bookmarks.status(),200);
  assert.deepEqual((await bookmarks.json()).materialIds,['synthetic-guide']);
  // A saved guide must be discoverable in the actual materials library,
  // including after a fresh browser navigation and reload.
  await page.goto(portalOrigin+'/materials');
  await page.getByRole('checkbox',{name:/Saved guides only/}).check();
  await page.getByRole('heading',{name:'Synthetic test guide'}).waitFor();
  assert.equal(await page.getByRole('heading',{name:'Synthetic test guide'}).count(),1);
  await page.reload();
  await page.getByRole('checkbox',{name:/Saved guides only/}).check();
  await page.getByRole('heading',{name:'Synthetic test guide'}).waitFor();
  await page.goto(portalOrigin+'/materials/synthetic-guide');
  await page.getByRole('button',{name:'Saved to my account'}).waitFor();
  await page.getByRole('button',{name:'Saved to my account'}).click();
  await page.getByRole('button',{name:'Bookmark to my account'}).waitFor();
  await page.getByRole('button',{name:'I have read this version'}).click();
  await page.getByText('Reading acknowledgment saved to your private account. You can undo it.').waitFor();
  await page.reload();
  await page.getByRole('button',{name:'Read this version - undo'}).waitFor();
  await page.getByRole('button',{name:'Read this version - undo'}).click();
  await page.getByRole('button',{name:'I have read this version'}).waitFor();
  
  await page.goto(portalOrigin+'/forms/action-card');await page.getByLabel('One action I can complete').fill('Read the approved policy summary');const downloadPromise=page.waitForEvent('download');await page.getByRole('button',{name:'Download my worksheet'}).click();const download=await downloadPromise;assert.equal(download.suggestedFilename(),'action-card-planning.md');
  await page.goto(portalOrigin+'/settings');
  const accountExportDownload=page.waitForEvent('download');
  await page.getByRole('button',{name:'Download my account data'}).click();
  assert.equal((await accountExportDownload).suggestedFilename(),'galinsky-volunteer-account.json');
  await page.getByText('Your account activity export was downloaded directly to your device.').waitFor();
  await page.getByRole('button',{name:'Sign out everywhere'}).click();
  await page.getByRole('button',{name:/Email my sign-in link/}).waitFor();
  assert.equal((await context.request.get(portalOrigin+'/api/session')).status(),401);
  // Restore a verified session to exercise the ordinary sign-out button too.
  await page.getByLabel('Email address').fill(name+'-again@example.test');
  await page.getByRole('checkbox').first().check();
  const acceptedLogin=page.waitForResponse(response=>response.url()===portalOrigin+'/api/auth/request'&&response.request().method()==='POST');
  await page.getByRole('button',{name:/Email my sign-in link/}).click();
  assert.equal((await acceptedLogin).status(),202);await page.getByText(/When delivery is available/).waitFor();
  const job2=store.outbox.findLast(job=>job.kind==='account_login'&&openDelivery(job.envelope,cfg.deliveryKey).email===name+'-again@example.test');assert(job2,'The accepted request queued the new login message');
  await page.goto(openDelivery(job2.envelope,cfg.deliveryKey).url);
  await page.getByRole('button',{name:'Continue to my workspace'}).click();
  await page.getByRole('button',{name:'Sign out'}).waitFor();
  await page.goto(portalOrigin+'/');await page.screenshot({path:`test-results/browser/${name}-workspace-mobile.png`,fullPage:true});await page.getByRole('button',{name:'Sign out'}).click();await page.getByRole('button',{name:/Email my sign-in link/}).waitFor();
  const unauthorized=await context.request.get(portalOrigin+'/api/materials');assert.equal(unauthorized.status(),401);assert.equal(errors.length,0,errors.join('\n'));
  evidence.push({browser:name,publicLayouts:32,emailVerification:true,authenticatedLibrary:true,worksheetDownload:true,logoutRevocation:true,thirdPartyRequestsBeforeActivation:outside.length});await browser.close();
 }
}finally{await app.close();await new Promise(r=>web.close(r));await writeFile('test-results/browser/results.json',JSON.stringify(evidence,null,2));}
console.log(JSON.stringify(evidence,null,2));
