// A one-time hosted acceptance against the existing PASSWORD-PROTECTED
// staging portal, with a synthetic passkey account deleted at the end.
// No live fundraising, real volunteer information or public launch.
import assert from 'node:assert/strict';
import {chromium} from 'playwright';

const origin='https://galinsky-2028-volunteer-portal.onrender.com';
const password=process.env.G28_PREVIEW_ACCESS_PASSWORD||'';
assert(password.length>=24,'The required protected preview secret is unavailable.');
const browser=await chromium.launch({headless:true});
const context=await browser.newContext({
 baseURL:origin,
 httpCredentials:{username:process.env.G28_PREVIEW_ACCESS_USER||'preview',password},
});
const page=await context.newPage();
const errors=[];page.on('pageerror',e=>errors.push(e.message));
page.on('response',async response=>{
 const path=new URL(response.url()).pathname;
 if(!path.startsWith('/api/passkeys/'))return;
 console.log('PASSKEY_HOSTED_HTTP',path,response.status());
 if(response.status()>=400){
  try{const body=await response.json();console.log('PASSKEY_HOSTED_ERROR',path,body.error,body.message);}catch{}
 }
});
let created=false,accountId='';
try{
 const cdp=await context.newCDPSession(page);
 await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{
  protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,
  isUserVerified:true,automaticPresenceSimulation:true
 }});
 const cfgResponse=await context.request.get(origin+'/api/config',{timeout:90000});
 assert.equal(cfgResponse.status(),200,'Private portal API must authorize protected test connection');
 const cfg=await cfgResponse.json();
 assert.equal(cfg.passkeyEnabled,true,'Live portal does not report passkey registration enabled');
 await page.goto('/join',{timeout:90000});
 await page.locator('.passkey-entry').waitFor({timeout:30000});
 await page.locator('.passkey-entry input[type=checkbox]').check();
 await page.getByRole('button',{name:'Create volunteer account'}).click();
 try{await page.getByRole('button',{name:'Sign out',exact:true}).waitFor({timeout:30000});}
 catch(e){console.error('Live signup failed:',(await page.locator('main').innerText()).slice(-1800));throw e;}
 created=true;
 const sessionResponse=await context.request.get(origin+'/api/session');
 assert.equal(sessionResponse.status(),200,'New synthetic volunteer session');
 let session=await sessionResponse.json();accountId=session.account.id;
 assert.equal(session.account.role,'volunteer');
 await page.goto('/roles');
 await page.getByLabel('What would you enjoy?').selectOption('skills');
 await page.getByRole('button',{name:'Save role preference'}).click();
 await page.getByText(/were saved to your account/).waitFor({timeout:20000});
 await page.goto('/orientation');
 await page.getByRole('heading',{name:/responsible participation/}).waitFor({timeout:30000});
 await page.goto('/settings');
 await page.getByRole('button',{name:'Add another passkey'}).click();
 await page.getByText('Another passkey is now registered on this account.').waitFor({timeout:30000});
 let devices=await context.request.get(origin+'/api/passkeys');
 assert.equal(devices.status(),200);assert.equal((await devices.json()).credentials.length,2);
 await page.getByRole('button',{name:'Sign out',exact:true}).click();
 await page.getByRole('button',{name:'Sign in with passkey'}).click();
 await page.getByRole('button',{name:'Sign out',exact:true}).waitFor({timeout:30000});
 session=await(await context.request.get(origin+'/api/session')).json();
 assert.equal(session.account.id,accountId,'Return passkey sign-in must use same account');
 const preferences=await context.request.get(origin+'/api/account/role-preferences');
 assert.equal(preferences.status(),200);assert.equal((await preferences.json()).preferences.roleId,'skills');
 assert.deepEqual(errors,[],'No browser script failures');
 console.log(JSON.stringify({origin,hostedWebAuthnAccount:true,backupPasskey:true,returnSignIn:true,
  persistedVolunteerRole:true,protectedPreview:true,syntheticOnly:true}));
}finally{
 let cleanupError=null;
 if(created){
  try{
   const response=await context.request.get(origin+'/api/session',{timeout:15000});
   if(response.status()===200){
    const session=await response.json();
    const close=await context.request.post(origin+'/api/account/close',{
     data:{confirm:'close my account'},
     headers:{Origin:origin,'x-csrf-token':session.csrf},
     timeout:15000
    });
    assert.equal(close.status(),200,'Synthetic account must be deleted after live acceptance');
    const revoked=await context.request.get(origin+'/api/session');
    assert.equal(revoked.status(),401,'Closed account session must be invalidated');
   }
  }catch(e){cleanupError=e;console.error('Synthetic account cleanup failed:',e.message);}
 }
 await context.close();await browser.close();
 if(cleanupError)throw cleanupError;
}
