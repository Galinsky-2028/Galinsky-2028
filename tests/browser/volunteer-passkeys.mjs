// Real Chromium WebAuthn ceremony using a virtual platform authenticator.
// Synthetic data only; no live accounts, email, or external website calls.
import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {createApp} from '../../apps/api/src/app.mjs';
import {MemoryStore} from '../../apps/api/src/memory-store.mjs';
import {loadConfig} from '../../apps/api/src/config.mjs';
import {registerPortal} from '../../apps/api/src/static.mjs';

const portalOrigin='http://127.0.0.1:4456';
const publicOrigin='http://127.0.0.1:4455';
const config=loadConfig({NODE_ENV:'test',PORTAL_ORIGIN:portalOrigin,PUBLIC_ORIGIN:publicOrigin,
 VOLUNTEER_PASSKEYS_ENABLED:'true',SIGNUP_ENABLED:'false'});
const store=new MemoryStore();
const app=createApp({store,config});registerPortal(app,portalOrigin);
let browser;
try{
 await app.listen({host:'127.0.0.1',port:4456});
 browser=await chromium.launch({headless:true});
 const context=await browser.newContext({baseURL:portalOrigin});
 const page=await context.newPage();
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const cdp=await context.newCDPSession(page);
 await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{
  protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,
  isUserVerified:true,automaticPresenceSimulation:true
 }});
 await page.goto('/join');
 await page.locator('.passkey-entry').waitFor();
 await page.locator('.passkey-entry input[type=checkbox]').check();
 await page.getByRole('button',{name:'Create volunteer account'}).click();
 try{await page.getByRole('button',{name:'Sign out',exact:true}).waitFor({timeout:10000});}catch(e){
  console.error('VOLUNTEER_PASSKEY_BROWSER_DIAGNOSTIC',JSON.stringify({url:page.url(),text:(await page.locator('main').innerText()).slice(0,2800),errors}));throw e;
 }
 assert.equal(store.accounts.size,1,'one genuine passkey-created volunteer account');
 const originalAccount=(await (await page.request.get('/api/session')).json()).account.id;
 assert.equal((await (await page.request.get('/api/session')).json()).account.role,'volunteer');
 await page.goto('/roles');
 await page.getByLabel('What would you enjoy?').selectOption('skills');
 await page.getByRole('button',{name:'Save role preference'}).click();
 await page.getByText(/were saved to your account/).waitFor();
 await page.goto('/settings');
 await page.getByRole('button',{name:'Add another passkey'}).click();
 await page.getByText('Another passkey is now registered on this account.').waitFor({timeout:20000});
 assert.equal((await (await page.request.get('/api/passkeys')).json()).credentials.length,2);
 await page.getByRole('button',{name:'Sign out',exact:true}).click();
 await page.getByRole('button',{name:'Sign in with passkey'}).click();
 await page.getByRole('button',{name:'Sign out',exact:true}).waitFor({timeout:20000});
 const returned=(await (await page.request.get('/api/session')).json()).account.id;
 assert.equal(returned,originalAccount,'authenticator returns to original account');
 await page.goto('/roles');
 await page.waitForFunction(()=>document.querySelector('.chooser select')?.value==='skills');
 assert.deepEqual(errors,[],'no client-side application errors');
 await context.close();
 console.log(JSON.stringify({realWebAuthnBrowser:true,registeredCredentials:2,accountRoundTrip:true}));
}finally{if(browser)await browser.close();await app.close();await store.close();}
