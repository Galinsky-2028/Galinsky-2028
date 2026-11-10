import {randomBytes,randomUUID} from 'node:crypto';

// Opt-in, one-deployment HTTP acceptance against the actual HTTPS preview.
// All credentials stay in process memory. No supporter/staff records or mail.
export async function verifyReviewLive({auth,pool,origin,portalOrigin,commit,transport=fetch}){
 if(new URL(origin).origin!==origin||new URL(origin).protocol!=='https:')throw Error('HTTPS preview required.');
 if(portalOrigin!=='https://galinsky2028-volunteers.onrender.com')throw Error('Unexpected portal origin.');
 const request=(base,path,options={})=>transport(base+path,{...options,redirect:'manual',signal:AbortSignal.timeout(8000)});
 let serving=false;
 for(let attempt=0;attempt<40;attempt++){
  try{const r=await request(origin,'/preview/api/status');if(r.ok&&(await r.json()).commit===commit){serving=true;break;}}catch{}
  await new Promise(r=>setTimeout(r,2000));
 }
 if(!serving)throw Error('Tested release is not serving the public preview origin.');
 const username='live.'+randomUUID().replaceAll('-',''),initial=randomBytes(32).toString('base64url'),chosen=randomBytes(32).toString('base64url');
 let id,cookie='';
 async function call(path,body,headers={}){
  const r=await request(origin,path,{method:body?'POST':'GET',headers:{Cookie:cookie,...(body?{Origin:origin,'Content-Type':'application/json'}:{}),...headers},body:body?JSON.stringify(body):undefined});
  const cookies=r.headers.getSetCookie();if(cookies.length)cookie=cookies.map(c=>c.split(';')[0]).join('; ');
  return r;
 }
 const expect=(r,status)=>{if(r.status!==status)throw Error('Preview HTTP acceptance failed.');return r;};
 const pages=['/','/issues/','/issues/kirk-evers/','/issues/garden/','/issues/cornerstone/','/assets/candidate.webp'];
 try{
  for(const path of pages)expect(await request(origin,path),401);
  expect(await request(origin,'/',{headers:{Authorization:'Basic '+Buffer.from('incorrect:incorrect').toString('base64')}}),401);
  const user=await auth.api.createUser({body:{email:randomUUID()+'@checks.preview.invalid',name:'Disposable live verification',password:initial,role:'user',data:{username,previewPasswordChangeRequired:true,previewExpiresAt:new Date(Date.now()+300000)}}});id=user.user.id;
  const login=expect(await call('/preview/auth/sign-in/username',{username,password:initial}),200);
  if(!cookie||!login.headers.getSetCookie().every(c=>/HttpOnly/i.test(c)&&/Secure/i.test(c)&&/SameSite=Lax/i.test(c)&&!/[; ]Domain=/i.test(c)))throw Error('Session cookie attributes failed.');
  expect(await call('/'),303);
  expect(await call('/preview/auth/change-password',{currentPassword:initial,newPassword:chosen}),200);
  for(const path of pages)expect(await call(path),200);
  for(const path of ['/preview/api/users','/api/admin/settings','/admin','/healthz','/donate/stripe','/donate/continue'])expect(await call(path),403);
  expect(await request(origin,'/preview/api/users',{method:'POST',headers:{Cookie:cookie,Origin:origin,'Content-Type':'application/json'},body:JSON.stringify({name:'Forbidden',username:'forbidden',password:initial,role:'admin'})}),403);
  for(const path of ['/api/materials','/api/admin/settings','/api/protected/records','/api/payments/ledger','/api/config'])expect(await request(portalOrigin,path,{headers:{Cookie:cookie}}),401);
  await pool.query('UPDATE g28_review_user SET banned=true WHERE id=$1',[id]);
  expect(await call('/issues/garden/'),401);
  expect(await call('/preview/auth/sign-in/username',{username,password:chosen}),403);
  return {commit,httpsOrigin:origin,policyPages:true,secureHostOnlyCookie:true,initialPasswordChange:true,ownerControlsDenied:true,financialRoutesDenied:true,portalAccessDenied:true,immediateRevocation:true,anonymousAccessDenied:true,disposableIdentityRemoved:true};
 }finally{if(id)await pool.query('DELETE FROM g28_review_user WHERE id=$1',[id]);}
}
