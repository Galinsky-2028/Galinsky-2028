// Browser encryption against real, isolated PostgreSQL; no live participants.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile,readdir,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {chromium} from 'playwright';
import {createApp} from '../../apps/api/src/app.mjs';
import {PostgresStore,databasePool} from '../../apps/api/src/postgres-store.mjs';
import {registerPortal} from '../../apps/api/src/static.mjs';
import {randomToken,tokenHash} from '../../packages/core/auth.mjs';
import {newProtectedKey,publicProtectedKey} from '../../packages/core/protected-crypto.mjs';
const url=process.env.TEST_DATABASE_URL;
if(!url){console.log('Protected browser journey needs the isolated TEST_DATABASE_URL.');process.exit(0);}
assert(['localhost','127.0.0.1'].includes(new URL(url).hostname));
const pool=databasePool(url),store=new PostgresStore(pool),account=randomUUID(),staff=randomUUID(),staffDevice=randomUUID(),origin='http://localhost:4468',token=randomToken(),csrf=randomToken(),ownerKey=tokenHash(staff),dir=await mkdtemp(join(tmpdir(),'g28-protected-browser-'));
const config={protectedContent:true,staffIdentity:true,adminLoginReady:true,adminOwnerEmailKey:ownerKey,portalOrigin:origin,publicOrigin:'http://localhost:4467'},app=createApp({store,config});registerPortal(app,origin);
let browser;
try{
 for(const name of (await readdir('db/migrations')).filter(x=>x.endsWith('.sql')).sort())await pool.query(await readFile('db/migrations/'+name,'utf8'));
 for(const [id,key]of [[account,tokenHash(account)],[staff,ownerKey]])await pool.query("INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'synthetic',now(),'synthetic')",[id,key]);
 await pool.query('INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',[tokenHash(token),account,csrf,new Date(Date.now()+86400000)]);
 const staffPair=await newProtectedKey(staff,'synthetic browser staff recovery phrase'),info=await publicProtectedKey(staffPair.publicKey);
 await pool.query("INSERT INTO g28.protected_devices(id,account_id,fingerprint,public_key,label,state,scope,approved_by,generation) VALUES($1,$2,$3,$4,'Named safety recipient','approved','incident',$2,1)",[staffDevice,staff,info.fingerprint,staffPair.publicKey]);
 await app.listen({host:'localhost',port:4468});browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH?{executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,args:['--no-sandbox']}:{})});
 const context=await browser.newContext({baseURL:origin,acceptDownloads:true});await context.addCookies([{name:'g28-local',value:token,url:origin,httpOnly:true,sameSite:'Lax'}]);const page=await context.newPage(),errors=[],external=[];page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(new URL(r.url()).origin!==origin)external.push(r.url());});
 await page.goto('/protected');await page.getByRole('heading',{name:'Protected messages.',exact:true}).waitFor();
 await page.getByLabel('Recovery passphrase (16 characters minimum)').fill('synthetic browser recovery phrase');
 const downloadPromise=page.waitForEvent('download');await page.getByRole('button',{name:'Create device & download encrypted recovery key'}).click();const download=await downloadPromise,file=join(dir,'recovery.asc');await download.saveAs(file);
 await page.getByText(/Device enrolled. Save the encrypted recovery/).waitFor();const own=(await pool.query('SELECT fingerprint FROM g28.protected_devices WHERE account_id=$1',[account])).rows[0];
 await page.getByLabel('Named staff recipient').selectOption(staffDevice);await page.getByLabel('Fingerprint confirmed through your separate trusted channel').fill(info.fingerprint);
 await page.getByLabel('Message',{exact:true}).fill('BROWSER_PRIVATE_CANARY_4791');await page.getByLabel('Optional private attachment (150 KB maximum)').setInputFiles({name:'quarantined.html',mimeType:'text/html',buffer:Buffer.from('<script>throw Error("must never execute")</script>')});await page.getByRole('button',{name:'Encrypt & submit'}).click();await page.getByText(/Encrypted submission received/).waitFor();
 const stored=(await pool.query('SELECT document FROM g28.protected_records WHERE author_id=$1',[account])).rows[0].document;assert(!JSON.stringify(stored).includes('BROWSER_PRIVATE_CANARY_4791'));assert(!JSON.stringify(stored).includes('must never execute'));
 await page.getByRole('button',{name:'Lock device',exact:true}).click();await page.getByLabel('Or select your encrypted recovery key').setInputFiles(file);await page.getByLabel('Recovery passphrase (16 characters minimum)').fill('synthetic browser recovery phrase');await page.getByRole('button',{name:'Unlock recovery key on this device'}).click();await page.getByText(/Device unlocked locally/).waitFor();
 await page.getByRole('button',{name:new RegExp(stored.id)}).click();await page.getByLabel('Verified sender fingerprints, separated by spaces').fill(own.fingerprint);await page.getByRole('button',{name:'Verify & decrypt locally'}).click();await page.getByText('BROWSER_PRIVATE_CANARY_4791',{exact:true}).waitFor();
 assert.equal(await page.locator('iframe').count(),0);assert.equal(await page.getByRole('button',{name:'Download attachment for local review'}).count(),1);
 const exportPromise=page.waitForEvent('download');await page.getByRole('button',{name:'Export this exact encrypted record'}).click();const exported=await exportPromise,exportFile=join(dir,'record.json');await exported.saveAs(exportFile);assert(!(await readFile(exportFile,'utf8')).includes('BROWSER_PRIVATE_CANARY_4791'));
 await page.setViewportSize({width:360,height:800});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));assert.deepEqual(errors,[]);assert.deepEqual(external,[]);console.log('Protected browser: key recovery, fingerprints, encrypted attachment, local decryption, scoped ciphertext export, mobile and zero external egress passed.');
}finally{
 await browser?.close();await app.close();await pool.query('DELETE FROM g28.protected_records WHERE author_id=$1',[account]);await pool.query('DELETE FROM g28.protected_lifecycle_events WHERE actor_id=ANY($1::text[])',[[account,staff]]);await pool.query('DELETE FROM g28.protected_devices WHERE account_id=ANY($1::uuid[])',[[account,staff]]);await pool.query('DELETE FROM g28.accounts WHERE id=ANY($1::uuid[])',[[account,staff]]);await store.close();await rm(dir,{recursive:true,force:true});
}
