import {readFileSync,existsSync} from 'node:fs';
import {isIP} from 'node:net';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
import {escapeHtml,origin} from '../packages/core/validation.mjs';
import {videoPanel} from '../packages/core/video.mjs';
import {policyDocumentSection} from '../packages/core/policy-documents.mjs';
import {publicRelease} from '../packages/core/indexing.mjs';
import {approvedDonationRoutes} from '../packages/core/donation-provider.mjs';
export const root=process.env.G28_SOURCE_ROOT||fileURLToPath(new URL('../',import.meta.url));
export const pages=JSON.parse(readFileSync(join(root,'content/public/pages.json'),'utf8'));
export const site=JSON.parse(readFileSync(join(root,'content/public/site.json'),'utf8'));
export function renderPage(key, options={}) {
 const page=pages.find(p=>p.key===key) || (key==='404'?{key:'404',path:'/404/',title:'Page Not Found | Galinsky 2028',description:'This campaign page could not be found. Return to the Galinsky 2028 homepage or explore the campaign priorities.'}:null);
 if(!page)throw new Error('Unknown page');
 const cfg=options.site||site;
 const {mode,canonical}=publicRelease(cfg);
 const portal=process.env.PORTAL_ORIGIN||cfg.portalOrigin;
 if(portal)origin(portal,process.env.NODE_ENV!=='production');
 const portalPath=portal||'/volunteer/#join';
 let body=readFileSync(join(root,`content/public/pages/${page.key}.html`),'utf8');
 body=body.replace('<main id="main"','<main id="main" tabindex="-1"');
 body=body.replace(/\{\{VIDEO:([a-z-]+)\}\}/g,(_,slug)=>{
  const configured=cfg.issues[slug];
  const video=mode==='production'&&configured?.temporaryLabel?{...configured,youtubeId:null,temporaryLocalVideo:null}:configured;
  const path=video?.temporaryLocalVideo;
  return videoPanel(slug,video,{localAssetExists:Boolean(mode==='preview'&&path&&existsSync(join(root,'apps/web/public',path.slice(1))))});
 });
 body=body.replace(/\{\{DOCUMENTS:([a-z-]+)\}\}/g,(_,slug)=>policyDocumentSection(slug,cfg.issues[slug]?.documents||[],join(root,'apps/web/public')));
 // Source URLs never expose private GitHub tokens. The password-gated Render
 // server queries the designated repositories' current branch on each visit.
 if(['kirk-evers','garden','cornerstone'].includes(page.key)){
  const text='<div class="resource" data-live-policy-source="'+page.key+'">'+
   '<a class="textlink" href="/policy-library/'+page.key+'/">Download the current source documents &rarr;</a>'+
   '<small>Updates in the authoritative repository appear automatically. Private source access is required.</small></div>';
  body=body.replace('<section id="documents">','<section id="documents">'+text);
 }

 body=body.replace(/<a\b([^>]*\bdata-destination="([a-z-]+)"[^>]*)>([\s\S]*?)<\/a>/g,(whole,attrs,slug,inside)=>{
   const marker='href="{{DESTINATION:'+slug+'}}"';
   if(!attrs.includes(marker))return whole;
   const url=cfg.issues[slug]?.websiteUrl;
   if(!url)return '<span class="pending-destination" role="note" data-pending-issue="'+slug+'">Full issue site link pending verification</span>';
   if(typeof url!=='string'||url.length>2048)throw new Error('Invalid policy destination');
   const u=new URL(url);
   if(u.protocol!=='https:'||u.username||u.password||u.port||!u.hostname.includes('.')||u.hostname==='localhost'||u.hostname.endsWith('.local')||isIP(u.hostname))throw new Error('Invalid policy destination');
   return '<a'+attrs.replace(marker,'href="'+escapeHtml(u.toString())+'" rel="noopener noreferrer"')+'>'+inside+'</a>';
 });

 // Sharing uses only verified production canonical page URLs. The private
 // password-gated preview never emits copy/share controls or its protected URL.
 if(mode==='production'&&canonical&&['kirk-evers','garden','cornerstone'].includes(page.key)){
  const shareUrl=canonical+page.path;
  const tools='<section class="issue-share" aria-label="Page sharing" data-share-url="'+escapeHtml(shareUrl)+'">'+
   '<div class="wrap"><h2>Share this proposal</h2><div class="issue-share-actions">'+
   '<button class="btn outline" type="button" data-share-action="copy">Copy page link</button>'+
   '<button class="btn outline" type="button" data-share-action="native">Share page</button>'+
   '<button class="btn outline" type="button" data-share-action="qr" aria-controls="issue-share-qr" aria-expanded="false">Show QR code</button></div>'+
   '<div class="issue-share-qr" id="issue-share-qr" hidden>'+
   '<div class="issue-share-qr-canvas" role="img" aria-label="QR code linking to this issue page"></div>'+
   '<p class="small">Scan this code to open the official issue page. It contains no tracking parameters.</p></div>'+
   '<p class="small" role="status" aria-live="polite"></p><button class="btn outline" type="button" data-sharing-assets="'+key+'" aria-controls="approved-sharing-assets" aria-expanded="false">Approved images and print cards</button><div id="approved-sharing-assets" hidden></div></div></section>';
  body=body.replace('</main>',tools+'</main>');
 }
 if(body.includes('{{DESTINATION:'))throw new Error('Unresolved policy destination token');
 if(page.key==='donate'){
  const routes=approvedDonationRoutes(process.env,mode);
  // Staging-only test checkout link. Never describes this as a real donation.
  if(mode==='preview'&&process.env.G28_STRIPE_TEST_ENABLED==='true'&&
     /^sk_test_[A-Za-z0-9_]{12,}$/.test(process.env.STRIPE_SECRET_KEY||'')){
   body=body.replace('Online contributions are not open yet. No payment or donor details are collected on this page.',
    'Online contributions are not open yet. You can try a test checkout with a Stripe test card; it moves no real money.');
   body=body.replace('<button class="btn blue" disabled="" style="width:100%" type="submit">Contributions opening later</button>',
    '<a class="btn blue" style="width:100%" href="/donate/stripe">Try Stripe test checkout — no real charges</a>');
  }
  if(routes.length){
   const original=body.match(/<form class="donate-form" id="donation-details">[\s\S]*?<\/form>/);
   const disclosure=body.match(/<p class="reporting-notice">[\s\S]*?<\/p>/);
   const eligibility=body.match(/<div class="eligibility">[\s\S]*?<\/div>/);
   if(!original||!disclosure||!eligibility)throw new Error('Donation template changed: refusing partial activation');
   const copy='<section class="donate-form" id="donation-details">'+
     '<div class="formsteps"><span class="active">01 REVIEW</span><span>02 SECURE CHECKOUT</span></div>'+
     '<h2 id="donate-summary" data-external-checkout="true">Secure campaign contribution</h2>'+
     '<p class="service-notice">One button takes you to a randomly selected, independently approved secure payment processor. This site never accepts your card number.</p>'+
     disclosure[0]+eligibility[0]+
     '<p class="tiny">Choose the final amount and any recurring option on the selected processor checkout. No preselected recurring gift is permitted. The provider page must display the approved committee disclosure and collect required eligibility and reporting information.</p>'+
     '<a class="btn blue" style="display:block;text-align:center;width:100%;margin-top:16px" href="/donate/continue">Continue to secure contribution</a>'+
     '<p class="tiny" style="margin-top:14px">If this processor is unavailable, return here to begin a new attempt. Never submit the same gift twice while a prior payment is uncertain.</p>'+
     '</section>';
   body=body.replace(original[0],copy);
  }
 }
 const replacePortal=text=>text.replace(/\{\{PORTAL\}\}[^"\s<]*/g,match=>portal?match.replace('{{PORTAL}}',portal):portalPath);
 body=replacePortal(body);
 let header=replacePortal(readFileSync(join(root,'content/public/header.html'),'utf8'));
 header=header.replace(/<a class="(?:current)?" href="([^"]+)">/g,(_,url)=>`<a class="${url===page.path||(url==='/issues/'&&page.path.startsWith('/issues/'))?'current':''}" href="${url}"${url===page.path||(url==='/issues/'&&page.path.startsWith('/issues/'))?' aria-current="page"':''}>`);
 const footer=readFileSync(join(root,'content/public/footer.html'),'utf8');
 const status=mode==='production'?'':`<div class="build-status" role="note">Campaign website preview &bull; Accounts and payments are not open.</div>`;
 const description=escapeHtml(page.description);
 const robots=key==='404'||mode!=='production'?'noindex,nofollow':'index,follow';
 const pageCanonical=key==='404'?null:canonical&&canonical+page.path;
 const csp="default-src 'self'; script-src 'self' https://www.youtube.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self'; font-src 'self'; connect-src 'self'; frame-src https://www.youtube-nocookie.com; object-src 'none'; base-uri 'none'; form-action 'none'";
 return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="${csp}"><meta name="referrer" content="strict-origin-when-cross-origin"><meta name="robots" content="${robots}"><title>${escapeHtml(page.title)}</title><meta name="description" content="${description}">${pageCanonical?`<link rel="canonical" href="${pageCanonical}">`:''}<meta property="og:title" content="${escapeHtml(page.title)}"><meta property="og:description" content="${description}"><meta property="og:type" content="website"><meta property="og:site_name" content="Galinsky 2028"><meta name="twitter:card" content="summary_large_image">${pageCanonical?`<meta property="og:url" content="${pageCanonical}">`:''}${canonical?`<meta property="og:image" content="${canonical}/assets/candidate.webp">`:''}<meta name="theme-color" content="#0a3161"><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/assets/design.css"><link rel="stylesheet" href="/assets/site.css"><link rel="stylesheet" href="/assets/eternal-liberty.css"></head><body data-page="${key}">${header}${body}${footer}${status}<script src="/assets/public.js" defer></script><script src="/assets/visitor-analytics.js" defer></script><script src="/assets/visitor-insights.js" defer></script>${key==='index'?'<script src="/assets/motion.js" defer></script>':''}</body></html>`;
}
