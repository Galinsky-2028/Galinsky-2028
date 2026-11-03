import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {randomUUID,randomBytes} from 'node:crypto';
import {createApp} from '../../apps/api/src/app.mjs';
import {PostgresStore,databasePool} from '../../apps/api/src/postgres-store.mjs';

const database=process.env.TEST_DATABASE_URL;
const origin='http://localhost:4322';
const cfg={portalOrigin:origin,publicOrigin:'http://localhost:4321',
 production:false,signup:false,adminLoginReady:false,volunteerPasskeys:true,
 pepper:randomBytes(32).toString('hex')};
const mock={
 async generateRegistrationOptions(){return {challenge:'synthetic-registration-challenge'};},
 async generateAuthenticationOptions(){return {challenge:'synthetic-authentication-challenge'};},
 async verifyRegistrationResponse({response,expectedChallenge,expectedOrigin,expectedRPID}){
  if(response.challenge!==expectedChallenge||expectedOrigin!==origin||expectedRPID!=='localhost')throw Error('incorrect proof');
  return {verified:true,registrationInfo:{userVerified:true,credential:{id:response.id,publicKey:Buffer.from('synthetic-public-key'),counter:0,transports:[]}}};
 },
 async verifyAuthenticationResponse({response,expectedChallenge,expectedOrigin,credential}){
  if(response.challenge!==expectedChallenge||expectedOrigin!==origin||credential.id!==response.id)throw Error('incorrect proof');
  return {verified:true,authenticationInfo:{userVerified:true,newCounter:credential.counter+1}};
 }
};
const cookie=(reply,name)=>{
 const values=reply.headers['set-cookie'];const items=Array.isArray(values)?values:[values];
 return items.find(v=>typeof v==='string'&&v.startsWith(name+'='))?.split(';')[0];
};
const post=(app,url,payload,extra={})=>app.inject({method:'POST',url,payload,
 headers:{origin,'content-type':'application/json',...extra}});
test('database-backed passkey account, backup device and returning sign-in survive new app instances',{skip:!database},async()=>{
 assert(['localhost','127.0.0.1'].includes(new URL(database).hostname),'never use nonlocal database');
 const pool=databasePool(database),store=new PostgresStore(pool);
 const firstId='synthetic-primary-'+randomUUID(),backupId='synthetic-backup-'+randomUUID();
 let accountId=null;
 try{
  await pool.query(await readFile('db/migrations/001_foundation.sql','utf8'));
  await pool.query(await readFile('db/migrations/021_volunteer_passkeys.sql','utf8'));
  const app=createApp({store,config:cfg,webauthn:mock});
  try{
   const reg=await post(app,'/api/passkeys/register/options',{});
   assert.equal(reg.statusCode,200,reg.body);
   const pending=cookie(reg,'g28-local-passkey-challenge');
   const created=await post(app,'/api/passkeys/register/verify',
    {termsAccepted:true,response:{id:firstId,challenge:reg.json().options.challenge}},{cookie:pending});
   assert.equal(created.statusCode,200,created.body);
   const auth=cookie(created,'g28-local');
   const session=await app.inject({url:'/api/session',headers:{cookie:auth}});
   assert.equal(session.statusCode,200,session.body);
   accountId=session.json().account.id;
   assert.equal(session.json().account.role,'volunteer','credential alone never grants staff roles');
   const csrf=session.json().csrf;
   const add=await post(app,'/api/passkeys/add/options',{},
    {cookie:auth,'x-csrf-token':csrf});
   assert.equal(add.statusCode,200,add.body);
   const added=await post(app,'/api/passkeys/add/verify',
    {response:{id:backupId,challenge:add.json().options.challenge}},
    {cookie:auth+'; '+cookie(add,'g28-local-passkey-challenge'),'x-csrf-token':csrf});
   assert.equal(added.statusCode,200,added.body);
   const devices=await app.inject({url:'/api/passkeys',headers:{cookie:auth}});
   assert.equal(devices.statusCode,200);assert.equal(devices.json().credentials.length,2);
   const row=await pool.query('SELECT email_key,delivery_envelope FROM g28.accounts WHERE id=$1',[accountId]);
   assert(row.rows[0].email_key.startsWith('passkey:'),'no invented email ownership');
   assert.equal(row.rows[0].delivery_envelope,'passkey-only');
   assert.equal((await post(app,'/api/passkeys/add/verify',{response:{id:backupId,challenge:add.json().options.challenge}},
    {cookie:auth+'; '+cookie(add,'g28-local-passkey-challenge'),'x-csrf-token':csrf})).statusCode,403);
  }finally{await app.close();}
  const newApp=createApp({store,config:cfg,webauthn:mock});
  try{
   const start=await post(newApp,'/api/passkeys/authenticate/options',{});
   const token=cookie(start,'g28-local-passkey-challenge');
   const signedIn=await post(newApp,'/api/passkeys/authenticate/verify',
    {response:{id:backupId,challenge:start.json().options.challenge}},{cookie:token});
   assert.equal(signedIn.statusCode,200,signedIn.body);
   const session=await newApp.inject({url:'/api/session',headers:{cookie:cookie(signedIn,'g28-local')}});
   assert.equal(session.json().account.id,accountId,'backup passkey opens the original account');
  }finally{await newApp.close();}
 }finally{
  if(accountId)await pool.query('DELETE FROM g28.accounts WHERE id=$1',[accountId]);
  // A failed pre-account enrollment can leave a single short-lived challenge;
  // do not wipe unrelated database state in the shared integration runner.
  await pool.query("DELETE FROM g28.volunteer_passkey_challenges WHERE challenge IN ('synthetic-registration-challenge','synthetic-authentication-challenge')");
  await store.close();
 }
});
