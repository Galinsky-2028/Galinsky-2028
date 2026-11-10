import {runtimeProbe} from '../../packages/core/runtime-probe.mjs';
import {createServer} from 'node:http';
import {DONOR_COOKIE,donorCapability,donorAuthority,donorCookie,donorCsrf,validDonorCsrf,stripeDonorRecord,stripeDonorPortal,donorManagementHtml} from '../../packages/core/stripe-donor-service.mjs';
import {readCookie} from '../../packages/core/auth.mjs';
import {validDonationOrigin} from '../../packages/core/stripe-web-checkout.mjs';
import {readFile,realpath,stat} from 'node:fs/promises';
import {realpathSync,statSync} from 'node:fs';
import {extname,resolve,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {loadPreviewGate,previewAuthorized,PREVIEW_REALM,PREVIEW_ROBOTS} from '../../packages/core/preview-gate.mjs';
import {safeReleaseCommit} from '../../packages/core/release-id.mjs';
import {livePolicyIndex,livePolicyBytes,policyIndexHtml} from '../../packages/core/live-policy-library.mjs';
import {approvedDonationRoutes} from '../../packages/core/donation-provider.mjs';
import {DonationRotationStore} from './donation-rotation-store.mjs';
import {databasePool} from '../api/src/postgres-store.mjs';
import {randomUUID} from 'node:crypto';
import {stripeSettings,checkoutNonceKey,openStripeSession,stripeDonationHtml,parseCheckoutForm,checkCheckoutToken} from '../../packages/core/stripe-web-checkout.mjs';
import {StripeCampaignStore} from './stripe-campaign-store.mjs';
import {contributionTermsHtml,CONTRIBUTION_TERMS_PATH} from '../../packages/core/contribution-terms.mjs';
import {createCampaignRuntime} from './campaign-runtime.mjs';
import {createVisitorCollector} from './visitor-analytics.mjs';

const mime={
 '.html':'text/html; charset=utf-8',
 '.css':'text/css; charset=utf-8',
 '.js':'application/javascript; charset=utf-8',
 '.mjs':'application/javascript; charset=utf-8',
 '.json':'application/json; charset=utf-8',
 '.svg':'image/svg+xml',
 '.png':'image/png',
 '.jpg':'image/jpeg',
 '.jpeg':'image/jpeg',
 '.webp':'image/webp',
 '.avif':'image/avif',
 '.ico':'image/x-icon',
 '.txt':'text/plain; charset=utf-8',
 '.xml':'application/xml; charset=utf-8',
 '.woff':'font/woff',
 '.woff2':'font/woff2',
 '.pdf':'application/pdf',
 '.mp4':'video/mp4'
};
function send(res,status,body){
 res.statusCode=status;res.setHeader('Content-Type','text/plain; charset=utf-8');
 res.end(body);
}
function checkoutErrorPage(res,status,stage){
 // Give a useful recovery path; never display Stripe errors, donor details,
 // card data, session URLs, internal exception strings, or secrets.
 const message=stage==='token'?'This form was opened before a recent update or has expired. Reload the contribution form and try again.':
  stage==='origin'?'The checkout security check did not match this website. Reload the contribution form and try again.':
  stage==='form'?'The contribution form was incomplete or invalid. Return to the form and check the amount and agreement.':
  'Secure card checkout could not be started. Please return to the form and try again. No payment has been confirmed.';
 const html='<!doctype html><html lang="en"><head><meta charset="utf-8">'+
  '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">'+
  '<title>Checkout not started | Galinsky 2028</title><link rel="stylesheet" href="/assets/design.css">'+
  '<link rel="stylesheet" href="/assets/site.css"></head><body><main class="wrap" style="max-width:720px;padding:54px 20px">'+
  '<h1 style="font-size:clamp(34px,6vw,58px)">Checkout was not started</h1><p style="margin:20px 0">'+message+'</p>'+
  '<a class="btn blue" href="/donate/stripe">Return to contribution form</a>'+
  '<p class="tiny" style="margin-top:18px">Card details are entered on the secure Stripe-hosted page, only after this website redirects you there.</p>'+
  '</main></body></html>';
 res.statusCode=status;res.setHeader('Content-Type','text/html; charset=utf-8');
 res.setHeader('Content-Security-Policy',"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'");
 res.setHeader('Content-Length',Buffer.byteLength(html));res.end(html);
}
function requestedPath(raw){
 if(typeof raw!=='string'||raw.length>4096)return null;
 let pathname;try{pathname=decodeURIComponent(raw.split('?')[0].split('#')[0]);}catch{return null;}
 if(!pathname.startsWith('/')||pathname.includes('\\')||pathname.includes('\0')||pathname.includes('//'))return null;
 if(pathname.split('/').some(s=>s==='.'||s==='..'||s.startsWith('.')))return null;
 return pathname;
}

// Unlike a static CDN, this Node service authenticates BEFORE reading any file.
// Use only this web-service entry point for preview hosting.
export function createPrivatePreviewServer({directory=resolve('dist/web'),env=process.env,rotationStore=null,stripeTransport=fetch,stripeStore=null,reviewController=null,campaignRuntime=null,analyticsStore=null}={}){
 const credentials=loadPreviewGate(env);
 if(env.G28_REVIEW_ACCOUNTS_ENABLED==='true'&&!reviewController)throw Error('Private review accounts require a persistent authentication controller.');
 if(env.G28_CAMPAIGN_PUBLIC_ENABLED==='true'&&!campaignRuntime)throw Error('Published campaign rendering requires its verified runtime.');
 const collector=createVisitorCollector({env,store:analyticsStore});
 const root=realpathSync(directory);
 if(!statSync(root).isDirectory())throw Error('The public preview build directory does not exist.');
 // Release flags and provider approvals are checked independently of the database.
 // Preview mode always fails closed; tests may inject an in-memory routing store.
 const donationRoutes=env.G28_PUBLIC_MODE==='production'?approvedDonationRoutes(env,'production'):[];
 if(donationRoutes.length && !rotationStore && !env.DATABASE_URL)
  throw Error('Activated donation routing requires a verified persistent DATABASE_URL');
 const rotationPool=donationRoutes.length && !rotationStore?databasePool(env.DATABASE_URL):null;
 const liveRotationStore=rotationStore||(rotationPool?new DonationRotationStore(rotationPool):null);
 const stripeConfig=stripeSettings(env);
 const stripeNonce=checkoutNonceKey(stripeConfig?.secretKey);
 const stripePool=stripeConfig&&env.DATABASE_URL&&!rotationPool&&!stripeStore?databasePool(env.DATABASE_URL):null;
 const liveStripeStore=stripeStore||(stripeConfig&&env.DATABASE_URL?new StripeCampaignStore(rotationPool||stripePool):null);
 const server=createServer(async(req,res)=>{
  res.setHeader('Cache-Control','private, no-store, max-age=0');
  res.setHeader('X-Robots-Tag',PREVIEW_ROBOTS);
  res.setHeader('Vary',reviewController?'Authorization, Cookie':'Authorization');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('X-Frame-Options','DENY');
  if(env.NODE_ENV==='production')res.setHeader('Strict-Transport-Security','max-age=31536000');
  const pathname=requestedPath(req.url);
  if(pathname!==null&&reviewController&&await reviewController.handle(req,res,pathname))return;
  const legacy=previewAuthorized(req.headers.authorization,credentials);
  let review=null;
  if(!legacy&&reviewController){try{review=await reviewController.session(req);}catch{return send(res,503,'Private review access is temporarily unavailable.');}}
  // Both preview roles have website permissions only. This explicit allowlist
  // protects future financial/admin routes as well as today's operations.
  if(review){
   const pages=new Set(['/','/issues','/issues/','/issues/kirk-evers','/issues/kirk-evers/','/issues/garden','/issues/garden/','/issues/cornerstone','/issues/cornerstone/','/volunteer','/volunteer/','/donate','/donate/','/donate/terms','/notices','/notices/']);
   const allowed=pages.has(pathname)||pathname==='/favicon.svg'||/^\/(?:assets|_astro)\/[A-Za-z0-9_./-]+$/.test(pathname)||/^\/campaign-media\/[0-9a-f-]{36}\.png$/.test(pathname)||/^\/policy-library\/(?:kirk-evers|garden|cornerstone)(?:\/?|\/download\/[0-9a-f]{40})$/.test(pathname);
   if(!(allowed&&['GET','HEAD'].includes(req.method)||pathname==='/api/visitor-analytics'&&req.method==='POST'))return send(res,403,'This account has website review access only.');
   if(review.user.previewPasswordChangeRequired){res.writeHead(303,{Location:'/preview/','Content-Length':'0'});res.end();return;}
  }
  // Stripe alone may POST a signed webhook without shared preview credentials.
  // No unverified event can alter the campaign's financial ledger.
  if(req.url?.split('?')[0]==='/donate/stripe/webhook'){
   if(req.method!=='POST'){res.setHeader('Allow','POST');return send(res,405,'Method not allowed.');}
   if(!stripeConfig||!liveStripeStore||!/^whsec_[A-Za-z0-9_]{10,}$/.test(env.STRIPE_WEBHOOK_SECRET||''))
    return send(res,503,'Stripe webhooks are not configured.');
   if(!/^application\/json(?:;|$)/i.test(req.headers['content-type']||''))
    return send(res,415,'Expected JSON.');
   let parts=[],size=0;
   for await(const chunk of req){
    size+=chunk.length;if(size>1024*1024)return send(res,413,'Request too large.');
    parts.push(chunk);
   }
   try{
    const outcome=await liveStripeStore.receiveSignedWebhook({
     raw:Buffer.concat(parts),header:req.headers['stripe-signature'],
     secret:env.STRIPE_WEBHOOK_SECRET,sandbox:stripeConfig.sandbox
    });
    if(outcome.status!==200)console.error(JSON.stringify({event:'stripe_webhook_rejected',reason:outcome.outcome}));
    return send(res,outcome.status,outcome.status===200?'Acknowledged.':'Webhook was not accepted.');
   }catch{
    console.error(JSON.stringify({event:'stripe_webhook_store_error'}));
    return send(res,503,'Verified event cannot be reconciled right now.');
   }
  }
  if(!legacy&&!review){
   if(reviewController){
    // Keep the pre-existing shared Basic preview credential usable even when
    // optional individual reviewer accounts are enabled. Without the challenge
    // browsers never open their native username/password dialog, stranding
    // operators whose working credentials were issued before reviewer accounts.
    // This does not grant an individual reviewer or campaign administration role.
    res.setHeader('WWW-Authenticate',PREVIEW_REALM);
    const html='<!doctype html><html lang="en"><meta charset="utf-8"><title>Private preview sign-in</title><h1>Private preview</h1><p><a href="/preview/">Sign in with your individual reviewer account</a>, or use your existing shared preview username and password in the browser sign-in dialog.</p></html>';
    res.writeHead(401,{'Content-Type':'text/html; charset=utf-8','Content-Length':Buffer.byteLength(html)});res.end(req.method==='HEAD'?undefined:html);return;
   }
   res.setHeader('WWW-Authenticate',PREVIEW_REALM);
   return send(res,401,'Private preview. Enter your access credentials.');
  }
  if(pathname===null)return send(res,404,'Not found.');
  // Editorial rendering never runs before the existing preview/reviewer checks.
  if(await collector.handle(req,res,pathname))return;
  if(campaignRuntime&&await campaignRuntime.handle(req,res,pathname,{authorized:Boolean(legacy||review)}))return;
  // The same versioned contribution terms linked beside the one consent
  // checkbox must be accessible before Stripe checkout, even in preview mode.
  if(pathname===CONTRIBUTION_TERMS_PATH){
   if(req.method!=='GET'&&req.method!=='HEAD'){
    res.setHeader('Allow','GET, HEAD');return send(res,405,'Method not allowed.');
   }
   const html=contributionTermsHtml();
   res.statusCode=200;
   res.setHeader('Content-Type','text/html; charset=utf-8');
   res.setHeader('Content-Security-Policy',"default-src 'self'; style-src 'self'; script-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'");
   res.setHeader('Content-Length',Buffer.byteLength(html));
   res.end(req.method==='HEAD'?undefined:html);return;
  }
  // Stripe's real Checkout checkout is generated server-side only.
  // Payment details are always entered on Stripe; POST data here is only
  // amount, election and eligibility certifications (never card/PII).
  if(pathname==='/donate/manage'||pathname==='/donate/manage/portal'||pathname==='/donate/manage/forget'){
   if(!stripeConfig||!liveStripeStore)return send(res,503,'Donor management is not configured. Use your processor-issued receipt or management link.');
   const capability=readCookie(req.headers.cookie,DONOR_COOKIE),authority=donorAuthority(stripeNonce,capability);
   try{
    if(pathname==='/donate/manage/portal'||pathname==='/donate/manage/forget'){
     if(req.method!=='POST'){res.setHeader('Allow','POST');return send(res,405,'Method not allowed.');}
     if(!authority||!validDonationOrigin(req,stripeConfig))return send(res,403,'Contribution session or request origin could not be verified.');
     if(!/^application\/x-www-form-urlencoded(?:;|$)/i.test(req.headers['content-type']||''))return send(res,415,'Use the donor management form.');
     let raw='';for await(const chunk of req){raw+=chunk.toString('utf8');if(raw.length>1024)return send(res,413,'Form is too large.');}
     const form=new URLSearchParams(raw);if([...form.keys()].length!==1||form.getAll('form_token').length!==1||!validDonorCsrf(stripeNonce,capability,form.get('form_token')))return send(res,403,'Reload donor management before continuing.');
     if(pathname==='/donate/manage/forget'){res.writeHead(303,{'Set-Cookie':DONOR_COOKIE+'=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',Location:'/donate/manage','Content-Length':'0'});res.end();return;}
     const destination=await stripeDonorPortal({settings:stripeConfig,authority,store:liveStripeStore,transport:stripeTransport,configuration:env.G28_STRIPE_DONOR_PORTAL_CONFIGURATION});res.writeHead(303,{Location:destination,'Content-Length':'0'});res.end();return;
    }
    if(!['GET','HEAD'].includes(req.method)){res.setHeader('Allow','GET, HEAD');return send(res,405,'Method not allowed.');}
    const record=authority?await stripeDonorRecord({settings:stripeConfig,authority,store:liveStripeStore,transport:stripeTransport}):null;
    const html=donorManagementHtml({record,csrf:authority?donorCsrf(stripeNonce,capability):'',loginUrl:env.G28_STRIPE_DONOR_PORTAL_LOGIN_URL,available:Boolean(env.G28_STRIPE_DONOR_PORTAL_CONFIGURATION),sandbox:stripeConfig.sandbox});res.statusCode=200;res.setHeader('Content-Type','text/html; charset=utf-8');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline'; form-action 'self' https://billing.stripe.com; base-uri 'none'; frame-ancestors 'none'");res.end(req.method==='HEAD'?undefined:html);return;
   }catch(e){return send(res,[403,409,503].includes(e.status)?e.status:503,'The processor could not verify or open this contribution. No new payment or subscription was created. Try again later or use the link sent by Stripe.');}
  }
  if(pathname==='/donate/stripe'||pathname==='/donate/stripe/checkout'){
   if(!stripeConfig)return send(res,503,'Stripe Checkout is not configured. No payment was attempted.');
   if(!liveStripeStore)return send(res,503,'The Stripe ledger is not configured. No payment was attempted.');
   if(!stripeConfig.sandbox){
    if(!liveRotationStore)return send(res,503,'Donation routing is unavailable.');
    try{
     const status=await liveRotationStore.statuses();
     if(!status.some(x=>x.provider_id==='stripe'&&x.status==='active'))
      return send(res,503,'This processor is temporarily unavailable. No payment was attempted.');
    }catch{return send(res,503,'Donation routing is unavailable. No payment was attempted.');}
   }
   if(pathname==='/donate/stripe'){
    if(req.method!=='GET'&&req.method!=='HEAD'){res.setHeader('Allow','GET, HEAD');return send(res,405,'Method not allowed.');}
    const html=stripeDonationHtml(stripeConfig,stripeNonce,new URL(req.url,'https://localhost').searchParams.get('amount')||'25');
    res.statusCode=200;res.setHeader('Content-Type','text/html; charset=utf-8');
    res.setHeader('Content-Security-Policy',"default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; script-src 'none'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'");
    res.setHeader('Content-Length',Buffer.byteLength(html));res.end(req.method==='HEAD'?undefined:html);return;
   }
   if(req.method!=='POST'){res.setHeader('Allow','POST');return send(res,405,'Method not allowed.');}
   if(!/^application\/x-www-form-urlencoded(?:;|$)/i.test(req.headers['content-type']||'')){
    return send(res,415,'Expected URL-encoded contribution form.');}
   let body='',stage='body';
   try{
    for await(const chunk of req){
     body+=chunk.toString('utf8');
     if(body.length>4096)return send(res,413,'Contribution form exceeds the allowed size.');
    }
    const created=await openStripeSession({raw:body,settings:stripeConfig,nonceKey:stripeNonce,
     request:req,transport:stripeTransport,onStage:s=>{stage=s;}});
    stage='ledger';
    await liveStripeStore.recordSession({clientRef:created.clientRef,sessionId:created.sessionId,
     amountCents:created.amountCents,election:created.election,livemode:stripeConfig.live,
     termsVersion:created.termsVersion});
    stage='redirect';
    res.setHeader('Set-Cookie',donorCookie(donorCapability(stripeNonce,created)));
    res.statusCode=303;res.setHeader('Location',created.hostedCheckoutUrl);
    res.setHeader('Content-Length','0');res.end();return;
   }catch(e){
    // Only genuine, validated gateway failures should affect processor health.
    // Missing/stale form tokens, invalid origins and database errors are not
    // evidence that the payment processor is unhealthy.
    if(stripeConfig.live && stage==='stripe_api' && e?.code==='checkout_unavailable' && liveRotationStore){
     try{
      const parsed=parseCheckoutForm(body);
      const attempt=checkCheckoutToken(stripeNonce,parsed.formToken);
      if(attempt)await liveRotationStore.observe('stripe',{
       eventId:'stripe-fail-'+randomUUID(),attemptRef:attempt,signal:'gateway_error'});
     }catch{
      console.error(JSON.stringify({event:'stripe_outage_observation_failed'}));
     }
    }
    const known=new Set(['body','configuration','origin','form','token','plan','stripe_api','stripe_created','ledger','redirect']);
    const safeStage=known.has(stage)?stage:'unknown';
    console.error(JSON.stringify({event:'stripe_checkout_refused',stage:safeStage,
     code:e?.code==='checkout_unavailable'?'checkout_unavailable':'input_or_provider_failure'}));
    const unavailable=safeStage==='ledger'||safeStage==='stripe_created'||safeStage==='redirect'||
     safeStage==='stripe_api'&&e?.code==='checkout_unavailable';
    return checkoutErrorPage(res,unavailable?503:400,safeStage);
   }
  }
  if(req.method!=='GET'&&req.method!=='HEAD'){
   res.setHeader('Allow','GET, HEAD');
   return send(res,405,'Method not allowed.');
  }
  if(pathname==='/healthz'){
   const result=JSON.stringify({ok:true,service:'galinsky-2028-web',
    mode:env.G28_PUBLIC_MODE==='production'?'production':'preview',
    commit:safeReleaseCommit(env.RENDER_GIT_COMMIT)});
   res.statusCode=200;
   res.setHeader('Content-Type','application/json; charset=utf-8');
   res.setHeader('Content-Length',Buffer.byteLength(result));
   res.end(req.method==='HEAD'?undefined:result);
   return;
  }
  // Authorized source files are served from private repos only AFTER the preview password check.
  // Never accept a caller-chosen repository, path, GitHub API URL or branch.
  if(pathname.startsWith('/policy-library/')){
   const listing=/^\/policy-library\/(kirk-evers|garden|cornerstone)\/?$/.exec(pathname);
   const download=/^\/policy-library\/(kirk-evers|garden|cornerstone)\/download\/([0-9a-f]{40})$/.exec(pathname);
   if(!listing&&!download)return send(res,404,'Policy document not found.');
   const slug=(listing||download)[1];
   try{
    const token=env.G28_POLICY_READ_TOKEN||env.GITHUB_READ_TOKEN;
    const index=await livePolicyIndex(slug,{token});
    if(listing){
     const html=policyIndexHtml(slug,index);
     res.statusCode=200;
     res.setHeader('Content-Type','text/html; charset=utf-8');
     res.setHeader('Content-Security-Policy',"default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
     res.setHeader('Content-Length',Buffer.byteLength(html));
     res.end(req.method==='HEAD'?undefined:html);return;
    }
    const selected=index.files.find(f=>f.sha===download[2]);
    if(!selected)return send(res,404,'Document not found in current branch.');
    let responseBytes;
    if(req.method==='GET')responseBytes=await livePolicyBytes(slug,download[2],{token,index});
    const filename=selected.name.replace(/[^A-Za-z0-9_.-]/g,'_');
    res.statusCode=200;
    res.setHeader('Content-Type',responseBytes?.mime||'application/octet-stream');
    res.setHeader('Content-Disposition','attachment; filename="'+filename+'"');
    res.setHeader('Content-Security-Policy',"default-src 'none'; sandbox");
    res.setHeader('Content-Length',selected.size);
    res.end(req.method==='HEAD'?undefined:responseBytes.bytes);return;
   }catch{
    console.error(JSON.stringify({event:'policy_library_unavailable',slug}));
    return send(res,503,'Policy documents are temporarily unavailable. No private repository details were disclosed.');
   }
  }
  if(pathname==='/donate/continue'){
   if(req.method!=='GET'){res.setHeader('Allow','GET');return send(res,405,'Method not allowed.');}
   if(!donationRoutes.length || !liveRotationStore)
    return send(res,503,'Online contributions are not available. No payment was attempted.');
   try{
    const selection=await liveRotationStore.selectRoute(donationRoutes);
    if(!selection)return send(res,503,'Online contributions are temporarily unavailable. No payment was attempted.');
    const configured=donationRoutes.find(route=>route.id===selection.providerId);
    if(!configured||configured.url!==selection.url)throw Error('Invalid rotation selection');
    res.statusCode=303;
    const chosenAmount=new URL(req.url,'https://localhost').searchParams.get('amount');
    const amt=chosenAmount&&/^[1-9]\\d{0,6}(?:\\.\\d{1,2})?$/.test(chosenAmount)?'?amount='+encodeURIComponent(chosenAmount):'';
    res.setHeader('Location',configured.kind==='stripe'?'/donate/stripe'+amt:configured.url);
    res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('Content-Length','0');
    res.end();return;
   }catch{
    console.error(JSON.stringify({event:'donation_route_unavailable'}));
    return send(res,503,'Online contributions are temporarily unavailable. No payment was attempted.');
   }
  }
  try{
   let candidate=resolve(root,'.'+pathname);
   if(candidate!==root&&!candidate.startsWith(root+sep))return send(res,404,'Not found.');
   let info=await stat(candidate);
   if(info.isDirectory()){
    candidate=resolve(candidate,'index.html');
    info=await stat(candidate);
   }
   const actual=await realpath(candidate);
   if((actual!==root&&!actual.startsWith(root+sep))||!info.isFile())return send(res,404,'Not found.');
   const ext=extname(actual).toLowerCase();
   if(!Object.hasOwn(mime,ext))return send(res,404,'Not found.');
   const content=await readFile(actual);
   res.statusCode=200;
   res.setHeader('Content-Type',mime[ext]);
   if(ext==='.mp4'){
    // HTML5 video players use single byte-range requests. Authenticate first,
    // reject malformed/multiple ranges, and never serve path traversals.
    res.setHeader('Accept-Ranges','bytes');
    const range=req.headers.range;
    if(range){
     const match=/^bytes=(\d*)-(\d*)$/.exec(range);
     let from,to;
     if(match&&(match[1]!==''||match[2]!=='')){
      if(match[1]===''){
       const suffix=Number(match[2]);
       if(Number.isSafeInteger(suffix)&&suffix>0){from=Math.max(0,content.length-suffix);to=content.length-1;}
      }else{
       from=Number(match[1]);
       to=match[2]===''?content.length-1:Number(match[2]);
      }
     }
     if(from===undefined||to===undefined||!Number.isSafeInteger(from)||!Number.isSafeInteger(to)||from<0||from>=content.length||to<from){
      res.statusCode=416;
      res.setHeader('Content-Range','bytes */'+content.length);
      res.setHeader('Content-Length','0');
      res.end();return;
     }
     to=Math.min(to,content.length-1);
     const slice=content.subarray(from,to+1);
     res.statusCode=206;
     res.setHeader('Content-Range','bytes '+from+'-'+to+'/'+content.length);
     res.setHeader('Content-Length',slice.length);
     res.end(req.method==='HEAD'?undefined:slice);
     return;
    }
   }
   res.setHeader('Content-Length',content.length);
   res.end(req.method==='HEAD'?undefined:content);
  }catch{
   send(res,404,'Not found.');
  }
 });
 if(rotationPool)server.on('close',()=>{void rotationPool.end().catch(()=>{});});
 if(stripePool)server.on('close',()=>{void stripePool.end().catch(()=>{});});
 if(campaignRuntime)server.on('close',()=>{void campaignRuntime.close().catch(()=>{});});
 if(collector.enabled)server.on('close',()=>{void collector.close().catch(()=>{});});
 return server;
}
const entry=process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url);
if(entry){
 try{
  const port=Number(process.env.PORT||10000);
  if(!Number.isSafeInteger(port)||port<1||port>65535)throw Error('Invalid listening port');
  let reviewController=null,reviewPool=null,reviewAuth=null;
  if(process.env.G28_REVIEW_ACCOUNTS_ENABLED==='true'){
   if(process.env.G28_PUBLIC_MODE==='production')throw Error('Reviewer accounts are limited to the private preview.');
   if(!process.env.G28_REVIEW_DATABASE_URL)throw Error('Reviewer accounts need their restricted database credential.');
   const {createReviewAuth,createReviewController}=await import('./review-auth.mjs');
   reviewPool=databasePool(process.env.G28_REVIEW_DATABASE_URL);
   await reviewPool.query('SELECT id FROM g28_review_setup WHERE id=1');
   const origin=process.env.G28_REVIEW_ORIGIN;
   reviewAuth=createReviewAuth({database:reviewPool,secret:process.env.G28_REVIEW_AUTH_SECRET,origin});
   const {verifyReviewRuntime}=await import('./review-runtime-check.mjs');
   console.log(JSON.stringify({event:'private_review_runtime_verified',...await verifyReviewRuntime({auth:reviewAuth,pool:reviewPool,origin,secret:process.env.G28_REVIEW_AUTH_SECRET})}));
   reviewController=createReviewController({auth:reviewAuth,pool:reviewPool,origin,setupKey:process.env.G28_REVIEW_SETUP_KEY,commit:process.env.RENDER_GIT_COMMIT});
  }
  const campaignRuntime=createCampaignRuntime();
  if(campaignRuntime){try{await campaignRuntime.ready();}catch{await campaignRuntime.close().catch(()=>{});throw Error('Campaign runtime failed safe startup checks.');}}
  const server=createPrivatePreviewServer({reviewController,campaignRuntime});
  server.listen(port,process.env.HOST||'0.0.0.0',async()=>{
   console.log(JSON.stringify({event:'private_preview_listening',port}));
   if(process.env.RENDER==='true'){try{console.log(JSON.stringify(await runtimeProbe({port,kind:'web'})));}catch{console.error(JSON.stringify({event:'runtime_application_verification_failed',kind:'web'}));server.close();process.exitCode=1;return;}}
   // An owner-authorized, explicitly flagged integration acceptance run.
   // It never accepts live keys, charges a card or logs sensitive account data.
   // Independent, READ-ONLY inventory of the owner-configured TEST webhook
   // destination. Checks mode, event subscriptions and emitted test events;
   // never logs a URL, account name, session ID, secret or donor record.
   if(process.env.G28_STRIPE_DIAGNOSE_WEBHOOKS_ON_BOOT==='true'){
    void (async()=>{
     let diagnosticsPool;
     try{
      await new Promise(resolve=>setTimeout(resolve,8000));
      if(process.env.DATABASE_URL)diagnosticsPool=databasePool(process.env.DATABASE_URL);
      const {diagnoseStripeTestWebhooks}=await import('./stripe-webhook-diagnostics.mjs');
      const result=await diagnoseStripeTestWebhooks({env:process.env,pool:diagnosticsPool});
      console.log(JSON.stringify({event:'stripe_test_webhook_diagnostics',...result}));
     }catch{
      console.error(JSON.stringify({event:'stripe_test_webhook_diagnostics',status:'failed',stage:'unexpected'}));
     }finally{if(diagnosticsPool)await diagnosticsPool.end().catch(()=>{});}
    })();
   }
   if(process.env.G28_STRIPE_SMOKE_ON_BOOT==='true'){
    void (async()=>{
     let acceptancePool;
     try{
      // Wait until Render can route external Stripe webhooks to this instance.
      await new Promise(resolve=>setTimeout(resolve,15000));
      if(process.env.DATABASE_URL)acceptancePool=databasePool(process.env.DATABASE_URL);
      const {runStripeSandboxAcceptance}=await import('./stripe-sandbox-acceptance.mjs');
      const result=await runStripeSandboxAcceptance({env:process.env,pool:acceptancePool});
      console.log(JSON.stringify({event:'stripe_sandbox_acceptance',...result}));
     }catch{
      console.error(JSON.stringify({event:'stripe_sandbox_acceptance',stage:'unexpected',status:'failed'}));
     }finally{
      if(acceptancePool)await acceptancePool.end().catch(()=>{});
     }
    })();
   }
   if(reviewController&&process.env.G28_REVIEW_LIVE_CHECK==='true'){
    try{
     const {verifyReviewLive}=await import('./review-live-check.mjs');
     const result=await verifyReviewLive({auth:reviewAuth,pool:reviewPool,origin:process.env.G28_REVIEW_ORIGIN,portalOrigin:process.env.G28_REVIEW_PORTAL_ORIGIN,commit:process.env.RENDER_GIT_COMMIT});
     console.log(JSON.stringify({event:'private_review_live_verified',...result}));
    }catch{console.error(JSON.stringify({event:'private_review_live_failed'}));}
   }
  });
  for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>server.close(async()=>{if(reviewPool)await reviewPool.end();process.exit(0);}));
 }catch(e){console.error('Private preview refused to start: '+e.message);process.exitCode=1;}
}
