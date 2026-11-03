import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createApp} from '../apps/api/src/app.mjs';
import {MemoryStore} from '../apps/api/src/memory-store.mjs';

const origin='http://localhost:4322';
const cfg={portalOrigin:origin,publicOrigin:'http://localhost:4321',production:false,
 signup:false,adminLoginReady:false,volunteerPasskeys:true,pepper:randomBytes(32).toString('hex')};
const cookie=(response,name)=>response.headers['set-cookie']?.find?.(v=>v.startsWith(name+'='))?.split(';')[0]
 || (typeof response.headers['set-cookie']==='string'?response.headers['set-cookie'].split(';')[0]:null);
const stub={
 async generateRegistrationOptions(){return {challenge:'register-challenge'};},
 async verifyRegistrationResponse({response,expectedChallenge,expectedOrigin,expectedRPID}){
  if(response.challenge!==expectedChallenge||expectedOrigin!==origin||expectedRPID!=='localhost')throw Error('bad proof');
  return {verified:true,registrationInfo:{userVerified:true,credential:{id:response.id,publicKey:Buffer.from('test-credential'),counter:0,transports:['internal']}}};
 },
 async generateAuthenticationOptions(){return {challenge:'login-challenge'};},
 async verifyAuthenticationResponse({response,expectedChallenge,credential,expectedOrigin}){
  if(response.challenge!==expectedChallenge||credential.id!==response.id||expectedOrigin!==origin)throw Error('bad proof');
  return {verified:true,authenticationInfo:{userVerified:true,newCounter:credential.counter+1}};
 }
};
const post=(app,url,body,session='')=>app.inject({method:'POST',url,payload:body,headers:{origin,'content-type':'application/json',...(session?{cookie:session}:{})}});

test('a volunteer can create a durable account with a verified discoverable passkey, use their workspace and sign in again',async()=>{
 const store=new MemoryStore(),app=createApp({store,config:cfg,webauthn:stub});
 try{
  const options=await post(app,'/api/passkeys/register/options',{});
  assert.equal(options.statusCode,200);
  const pending=cookie(options,'g28-local-passkey-challenge');
  assert(pending,'registration uses a short-lived HttpOnly cookie');
  const id='test-passkey-credential';
  const verify=await post(app,'/api/passkeys/register/verify',{termsAccepted:true,response:{id,challenge:options.json().options.challenge}},pending);
  assert.equal(verify.statusCode,200,verify.body);
  const auth=cookie(verify,'g28-local');
  assert(auth,'account session cookie returned');
  const session=await app.inject({url:'/api/session',headers:{cookie:auth}});
  assert.equal(session.statusCode,200,session.body);
  assert.equal(session.json().account.role,'volunteer');
  assert.equal(store.accounts.size,1);
  const csrf=session.json().csrf;
  const role=await app.inject({method:'POST',url:'/api/account/role-preferences',
   headers:{cookie:auth,origin,'content-type':'application/json','x-csrf-token':csrf},
   payload:{roleId:'skills',minutes:30,willingToTrain:true}});
  assert.equal(role.statusCode,200,role.body);
  const persisted=await app.inject({url:'/api/account/role-preferences',headers:{cookie:auth}});
  assert.equal(persisted.json().preferences.roleId,'skills');
  const replay=await post(app,'/api/passkeys/register/verify',{termsAccepted:true,response:{id,challenge:options.json().options.challenge}},pending);
  assert.equal(replay.statusCode,403,'single-use registration challenge is consumed');
  const logout=await app.inject({method:'POST',url:'/api/auth/logout',
   headers:{cookie:auth,origin,'content-type':'application/json','x-csrf-token':csrf},payload:{}});
  assert.equal(logout.statusCode,200);
  const loginOptions=await post(app,'/api/passkeys/authenticate/options',{});
  assert.equal(loginOptions.statusCode,200);
  const loginPending=cookie(loginOptions,'g28-local-passkey-challenge');
  const login=await post(app,'/api/passkeys/authenticate/verify',{response:{id,challenge:loginOptions.json().options.challenge}},loginPending);
  assert.equal(login.statusCode,200,login.body);
  const secondSession=cookie(login,'g28-local');
  const preferences=await app.inject({url:'/api/account/role-preferences',headers:{cookie:secondSession}});
  assert.equal(preferences.json().preferences.roleId,'skills','same account after returning passkey sign-in');
 }finally{await app.close();}
});

test('passkeys fail closed when disabled, unverified, missing terms or on cross-origin requests',async()=>{
 const store=new MemoryStore(),app=createApp({store,config:cfg,webauthn:stub});
 try{
  assert.equal((await post(app,'/api/passkeys/register/verify',{response:{id:'forged'},termsAccepted:true})).statusCode,403);
  assert.equal((await post(app,'/api/passkeys/register/verify',{response:{id:'forged'},termsAccepted:false})).statusCode,400);
  const start=await post(app,'/api/passkeys/register/options',{});
  const pending=cookie(start,'g28-local-passkey-challenge');
  const forged=await post(app,'/api/passkeys/register/verify',{termsAccepted:true,response:{id:'forged',challenge:'wrong'}},pending);
  assert.equal(forged.statusCode,403);
  assert.equal(store.accounts.size,0);
  const cross=await app.inject({method:'POST',url:'/api/passkeys/register/options',headers:{origin:'https://attacker.test','content-type':'application/json'},payload:{}});
  assert.equal(cross.statusCode,403);
  const disabled=createApp({store:new MemoryStore(),config:{...cfg,volunteerPasskeys:false},webauthn:stub});
  try{assert.equal((await post(disabled,'/api/passkeys/register/options',{})).statusCode,503);}
  finally{await disabled.close();}
 }finally{await app.close();}
});
