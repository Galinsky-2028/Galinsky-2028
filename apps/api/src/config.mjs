import {PROTECTED_PROFILE} from '../../../packages/core/protected-crypto.mjs';
import {origin,assert} from '../../../packages/core/validation.mjs';
import {loadPreviewGate} from '../../../packages/core/preview-gate.mjs';
import {safeReleaseCommit} from '../../../packages/core/release-id.mjs';
import {emailKey} from '../../../packages/core/auth.mjs';
import {email} from '../../../packages/core/validation.mjs';
import {treasuryVaultKey} from '../../../packages/core/treasury-vault.mjs';
export function loadConfig(env=process.env){
 const production=env.NODE_ENV==='production';
 assert(env.RENDER!=='true'||production,'production_runtime','Render API deployments require NODE_ENV=production.',503);
 const previewGate=production||env.RENDER==='true'?loadPreviewGate(env):null;
 const publicOrigin=origin(env.PUBLIC_ORIGIN||'http://localhost:4321',!production);
 const portalOrigin=origin(env.PORTAL_ORIGIN||'http://localhost:4322',!production);
 assert(!production||publicOrigin!==portalOrigin,'origin_separation','Public and protected applications require separate origins.',503);
 const deliveryKey=env.DELIVERY_KEY||'';const pepper=env.LOGIN_PEPPER||'';
 const mailReady=env.MAIL_PROVIDER==='resend'&&Boolean(env.RESEND_API_KEY&&env.MAIL_FROM&&/^[^\r\n]+@[^\r\n]+$/.test(env.MAIL_FROM));
 const staffIdentity=env.STAFF_IDENTITY_ENABLED==='true';
 const coordination=env.COORDINATION_ENABLED==='true';
 const helpRequests=env.G28_HELP_REQUESTS_ENABLED==='true';
 assert(!production||!helpRequests||staffIdentity,'help_release_unavailable','Live support intake requires the pending staff MFA and support operations release.',503);
 assert(!production||!coordination||staffIdentity,'coordination_unavailable','Production team coordination requires the pending staff identity release.',503);
 const signup=env.SIGNUP_ENABLED==='true';
 const volunteerPasskeys=env.VOLUNTEER_PASSKEYS_ENABLED==='true';
 const mailDeliveryMode=env.MAIL_DELIVERY_MODE||'disabled';
 const adminLoginReady=env.G28_ADMIN_LOGIN_ENABLED==='true';
 const campaignEditorEnabled=adminLoginReady&&env.G28_CAMPAIGN_EDITOR_ENABLED==='true'&&Boolean(env.DATABASE_URL);
 // Never bootstrap by password knowledge alone: actual mailbox ownership and
 // dedicated email one-time link must be proven before any admin role is issued.
 const adminOwnerEmailKey=adminLoginReady?emailKey(email(env.G28_OWNER_ADMIN_EMAIL),pepper):null;
 const treasuryKey=env.G28_TREASURY_VAULT_KEY||'';

 assert(['disabled','inline','external'].includes(mailDeliveryMode),'invalid_mail_delivery','Select disabled, inline or external mail delivery.',503);
 if(adminLoginReady){
  assert(pepper.length>=32&&deliveryKey&&Buffer.from(deliveryKey,'base64').length===32&&mailReady,
   'admin_signin_unready','Verified email delivery and secure login keys are required for administrator sign-in.',503);
  treasuryVaultKey(treasuryKey);
 }
 if(production&&adminLoginReady){
  assert((mailDeliveryMode==='inline'||mailDeliveryMode==='external')&&env.MAIL_WORKER_OPERATIONAL_APPROVED==='true',
   'admin_mail_unavailable','Administrator login cannot open without an operational verified mail worker.',503);
 }
 if(production&&signup){
  assert((mailDeliveryMode==='inline'||mailDeliveryMode==='external')&&env.MAIL_WORKER_OPERATIONAL_APPROVED==='true',
   'mail_worker_unavailable','Production sign-in cannot open without a configured, operational mail delivery worker.',503);
 }
 if(signup){assert(deliveryKey&&Buffer.from(deliveryKey,'base64').length===32&&pepper.length>=32&&mailReady,'signup_unready','Account delivery and authentication configuration are incomplete.',503);}
 // These flags may not bypass missing reviewed adapters or release evidence.
 const protectedContent=env.PROTECTED_CONTENT_ENABLED==='true';
 assert(!protectedContent||(staffIdentity&&adminLoginReady&&Boolean(env.DATABASE_URL)&&env.G28_PROTECTED_PROFILE===PROTECTED_PROFILE),'protected_unavailable','Protected reporting requires current staff identity, database and exact reviewed protocol profile.',503);
 assert(!staffIdentity||adminLoginReady,'staff_unavailable','Staff passkeys require configured verified-email staff access.',503);
 assert(env.DONATIONS_ENABLED!=='true','fundraising_unavailable','A production fundraising adapter and release evidence are not installed.',503);
 if(production)assert(env.DATABASE_URL,'database_required','Production requires the assigned database.',503);
 return {protectedContent,staffIdentity,coordination,helpRequests,campaignEditorEnabled,volunteerPasskeys,production,previewGate,publicOrigin,portalOrigin,deliveryKey,pepper,signup,adminLoginReady,adminOwnerEmailKey,treasuryKey,mailReady,mailDeliveryMode,mailKey:env.RESEND_API_KEY,mailWebhookSecret:env.RESEND_WEBHOOK_SECRET,mailFrom:env.MAIL_FROM,databaseUrl:env.DATABASE_URL,port:Number(env.PORT||4322),host:env.HOST||(production?'0.0.0.0':'127.0.0.1'),commit:safeReleaseCommit(env.RENDER_GIT_COMMIT),termsVersion:'2026-10-10'};
}
