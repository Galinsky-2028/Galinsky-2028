import {randomUUID,randomBytes} from 'node:crypto';
import {generateRegistrationOptions,verifyRegistrationResponse,generateAuthenticationOptions,verifyAuthenticationResponse} from '@simplewebauthn/server';
import {assert,exactKeys} from '../../../packages/core/validation.mjs';
import {tokenHash,randomToken,readCookie,sessionCookie} from '../../../packages/core/auth.mjs';

// Account passkeys use the existing server-side volunteer session. No email,
// password, third-party identity service, or self-appointed staff role.
const COOKIE_PROD='__Host-g28-passkey-challenge',COOKIE_DEV='g28-local-passkey-challenge';
const nowIso=ms=>new Date(ms).toISOString();
const pendingMap=new WeakMap();
const identitiesMap=new WeakMap();
function memory(store){
 if(!pendingMap.has(store))pendingMap.set(store,new Map());
 if(!identitiesMap.has(store))identitiesMap.set(store,new Map());
 return {pending:pendingMap.get(store),identities:identitiesMap.get(store)};
}
function cookie(name,value,production,age=300){
 return `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${production?'; Secure':''}`;
}
function byteUserId(id){return new TextEncoder().encode(id);}
const challengeTTL=300000;
async function saveChallenge(store,record){
 if(store.pool){
  await store.pool.query('INSERT INTO g28.volunteer_passkey_challenges(token_hash,kind,challenge,account_id,expires_at) VALUES($1,$2,$3,$4,$5)',
   [record.tokenHash,record.kind,record.challenge,record.accountId,nowIso(record.expires)]);
 }else memory(store).pending.set(record.tokenHash,record);
}
async function consumeChallenge(store,hash,kind,now){
 if(store.pool){
  const r=await store.pool.query('DELETE FROM g28.volunteer_passkey_challenges WHERE token_hash=$1 AND kind=$2 AND expires_at>$3 RETURNING *',
   [hash,kind,nowIso(now)]);
  return r.rows[0]?{kind:r.rows[0].kind,challenge:r.rows[0].challenge,accountId:r.rows[0].account_id}:null;
 }
 const m=memory(store).pending,r=m.get(hash);m.delete(hash);
 return r&&r.kind===kind&&r.expires>now?r:null;
}
async function createPasskeyAccount(store,{accountId,credential,session,now}){
 const pk={id:credential.id,publicKey:Buffer.from(credential.publicKey).toString('base64url'),counter:credential.counter,transports:credential.transports||[]};
 if(store.pool){
  const client=await store.pool.connect();
  try{
   await client.query('BEGIN');
   // This opaque key is not an email address and can never match an invited administrator.
   await client.query("INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'passkey-only',now(),'2026-10-10')",
    [accountId,'passkey:'+accountId]);
   await client.query('INSERT INTO g28.volunteer_passkeys(credential_id,account_id,public_key,counter,transports) VALUES($1,$2,$3,$4,$5)',
    [pk.id,accountId,pk.publicKey,pk.counter,JSON.stringify(pk.transports)]);
   await client.query('INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',
    [session.hash,accountId,session.csrf,nowIso(session.expires)]);
   await client.query('COMMIT');
  }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
 }else{
  const m=memory(store);
  assert(!m.identities.has(pk.id),'duplicate_passkey','This passkey is already registered.',409);
  store.accounts.set(accountId,{id:accountId,emailKey:'passkey:'+accountId,deliveryEnvelope:'passkey-only',verified:true,marketing:false,termsVersion:'2026-10-10'});
  m.identities.set(pk.id,{...pk,accountId});
  store.sessions.set(session.hash,{...session,accountId});
 }
}
async function signInWithPasskey(store,{response,challenge,origin,rpID,verify,session,now}){
 if(store.pool){
  const client=await store.pool.connect();
  try{
   await client.query('BEGIN');
   const q=await client.query('SELECT * FROM g28.volunteer_passkeys WHERE credential_id=$1 FOR UPDATE',[response.id]);
   assert(q.rowCount===1,'unknown_passkey','This passkey is not registered.',403);
   const credential=q.rows[0];
   let verified;
   try{verified=await verify({response,expectedChallenge:challenge,expectedOrigin:origin,expectedRPID:rpID,
    requireUserVerification:true,credential:{id:credential.credential_id,publicKey:new Uint8Array(Buffer.from(credential.public_key,'base64url')),counter:Number(credential.counter),transports:credential.transports}});}
   catch{assert(false,'passkey_rejected','Passkey verification failed. Try again.',403);}
   assert(verified?.verified&&verified.authenticationInfo?.userVerified,'passkey_rejected','A verified passkey is required.',403);
   await client.query('UPDATE g28.volunteer_passkeys SET counter=$2,last_used_at=now() WHERE credential_id=$1',
    [credential.credential_id,verified.authenticationInfo.newCounter]);
   await client.query('INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',
    [session.hash,credential.account_id,session.csrf,nowIso(session.expires)]);
   await client.query('COMMIT');return credential.account_id;
  }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
 }
 const m=memory(store),credential=m.identities.get(response.id);
 assert(credential,'unknown_passkey','This passkey is not registered.',403);
 let verified;
 try{verified=await verify({response,expectedChallenge:challenge,expectedOrigin:origin,expectedRPID:rpID,
  requireUserVerification:true,credential:{id:credential.id,publicKey:new Uint8Array(Buffer.from(credential.publicKey,'base64url')),counter:credential.counter,transports:credential.transports}});}
 catch{assert(false,'passkey_rejected','Passkey verification failed. Try again.',403);}
 assert(verified?.verified&&verified.authenticationInfo?.userVerified,'passkey_rejected','A verified passkey is required.',403);
 credential.counter=verified.authenticationInfo.newCounter;
 store.sessions.set(session.hash,{...session,accountId:credential.accountId});
 return credential.accountId;
}
export function registerVolunteerPasskeys(app,{store,config,clock=()=>Date.now(),webauthn={}}){
 const engine={
  generateRegistrationOptions:webauthn.generateRegistrationOptions||generateRegistrationOptions,
  verifyRegistrationResponse:webauthn.verifyRegistrationResponse||verifyRegistrationResponse,
  generateAuthenticationOptions:webauthn.generateAuthenticationOptions||generateAuthenticationOptions,
  verifyAuthenticationResponse:webauthn.verifyAuthenticationResponse||verifyAuthenticationResponse
 };
 const origin=config.portalOrigin,rpID=new URL(origin).hostname,name=config.production?COOKIE_PROD:COOKIE_DEV;
 const enabled=()=>assert(config.volunteerPasskeys===true,'passkeys_unavailable','Passkey sign-in is not enabled yet.',503);
 const rate=async(key,limit)=>assert(await store.rate('passkeys:'+key,limit,clock()+900000),'rate_limited','Please try again later.',429);
 function pending(req,kind){
  const token=readCookie(req.headers.cookie,name);
  assert(typeof token==='string'&&/^[A-Za-z0-9_-]{43}$/.test(token),'passkey_expired','The passkey request expired. Start again.',403);
  return consumeChallenge(store,tokenHash(token),kind,clock());
 }
 async function fresh(kind,challenge,accountId,reply){
  const token=randomToken();
  await saveChallenge(store,{tokenHash:tokenHash(token),kind,challenge,accountId,expires:clock()+challengeTTL});
  reply.header('Set-Cookie',cookie(name,token,config.production));
 }
 function clear(reply){reply.header('Set-Cookie',cookie(name,'',config.production,0));}
 function session(){
  const token=randomToken();
  return {token,hash:tokenHash(token),csrf:randomToken(),expires:clock()+86400000};
 }
 app.post('/api/passkeys/register/options',async(req,reply)=>{
  enabled();exactKeys(req.body,[]);
  await rate('create:'+req.ip,8);
  const accountId=randomUUID();
  const options=await engine.generateRegistrationOptions({
   rpName:'Galinsky 2028 Volunteer',rpID,userName:'Volunteer '+accountId.slice(0,8),
   userID:byteUserId(accountId),attestationType:'none',supportedAlgorithmIDs:[-7,-257],
   authenticatorSelection:{residentKey:'required',userVerification:'required'},timeout:challengeTTL
  });
  await fresh('register',options.challenge,accountId,reply);return {options};
 });
 app.post('/api/passkeys/register/verify',async(req,reply)=>{
  enabled();const b=exactKeys(req.body,['response','termsAccepted']);
  assert(b.termsAccepted===true,'terms_required','Accept the participation terms and privacy notice.');
  await rate('verify:'+req.ip,12);
  const r=await pending(req,'register');clear(reply);
  assert(r,'passkey_expired','The passkey request expired or was already used. Start again.',403);
  let proof;try{proof=await engine.verifyRegistrationResponse({response:b.response,expectedChallenge:r.challenge,
   expectedOrigin:origin,expectedRPID:rpID,requireUserVerification:true});}
  catch{assert(false,'passkey_rejected','Passkey verification failed. Start again.',403);}
  assert(proof?.verified&&proof.registrationInfo?.userVerified&&proof.registrationInfo.credential,
   'passkey_rejected','An authenticator with user verification is required.',403);
  const s=session();
  await createPasskeyAccount(store,{accountId:r.accountId,credential:proof.registrationInfo.credential,session:s,now:clock()});
  reply.header('Set-Cookie',sessionCookie(s.token,{secure:config.production}));return {verified:true};
 });
 app.post('/api/passkeys/authenticate/options',async(req,reply)=>{
  enabled();exactKeys(req.body,[]);await rate('login:'+req.ip,20);
  const options=await engine.generateAuthenticationOptions({
   rpID,userVerification:'required',allowCredentials:[],timeout:challengeTTL
  });
  await fresh('authenticate',options.challenge,null,reply);return {options};
 });
 app.post('/api/passkeys/authenticate/verify',async(req,reply)=>{
  enabled();const b=exactKeys(req.body,['response']);await rate('loginverify:'+req.ip,25);
  const r=await pending(req,'authenticate');clear(reply);
  assert(r,'passkey_expired','The passkey request expired or was already used. Start again.',403);
  const s=session();
  await signInWithPasskey(store,{response:b.response,challenge:r.challenge,origin,rpID,
   verify:engine.verifyAuthenticationResponse,session:s,now:clock()});
  reply.header('Set-Cookie',sessionCookie(s.token,{secure:config.production}));return {verified:true};
 });
}
