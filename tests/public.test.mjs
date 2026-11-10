import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,readdirSync,statSync,existsSync} from 'node:fs';
import {join} from 'node:path';
import {pages,site,root,renderPage} from '../scripts/public-renderer.mjs';
import {policySources} from '../packages/core/live-policy-library.mjs';
const rendered=new Map(pages.map(p=>[p.path,renderPage(p.key)]));
const protectedPolicyRoutes=new Set(Object.keys(policySources()).map(slug=>`/policy-library/${slug}/`));
test('all live policy links resolve to explicitly registered protected server routes',()=>{
 assert.deepEqual([...protectedPolicyRoutes].sort(),['/policy-library/cornerstone/','/policy-library/garden/','/policy-library/kirk-evers/']);
 for(const slug of Object.keys(policySources()))assert(renderPage(slug).includes(`href="/policy-library/${slug}/"`),`Missing registered source link: ${slug}`);
});
for(const p of pages)test('public contract: '+p.key,()=>{
 const html=rendered.get(p.path);assert.equal((html.match(/<h1\b/g)||[]).length,1);assert(html.includes('id="main"'));assert(!html.includes('{{'));assert(!html.includes('data-notice'));assert(!html.includes('materials.js'));assert(!html.includes('signup-preview'));assert(!html.includes('workspace.html'));assert(!html.includes('review.html'));assert(!html.includes('src="https://'));
 for(const match of html.matchAll(/href="(\/[^" ]*)"/g)){
  const u=new URL(match[1],'https://site.test');if(u.pathname.startsWith('/assets/')||u.pathname==='/favicon.svg')continue;
  // A policy-library URL is a dynamic, authenticated server route, NOT a
  // static page. Only explicitly registered URLs can bypass static lookup;
  // the server's 401/503 behavior is exercised in live-policy-library.test.mjs.
  if(protectedPolicyRoutes.has(u.pathname)||u.pathname==='/donate/manage')continue;
  assert(rendered.has(u.pathname),`${p.key}: broken local link ${match[1]}`);
  if(u.hash){const target=rendered.get(u.pathname);const anchor=u.hash.slice(1);assert(target.includes(`id="${anchor}"`),`${p.key}: missing anchor ${match[1]}`);}
 }
});
test('issue video is above original policy hero on all three pages',()=>{for(const slug of Object.keys(site.issues)){const html=renderPage(slug);assert(html.indexOf('issue-video-section')<html.indexOf('policy-hero'));assert(html.includes('aspect-ratio')===false);assert(html.includes('data-video="'+site.issues[slug].youtubeId+'"'));assert(!html.includes('<iframe'));const uploaded=Boolean(site.issues[slug].temporaryLocalVideo&&existsSync(join(root,'apps/web/public/assets/issue-video-placeholder.mp4')));if(uploaded)assert(html.includes('<video controls playsinline'), 'The verified local source must render its actual video player.');else assert(!html.includes('<video'), 'Without the uploaded binary, never render a broken player.');}});
test('homepage preserves actual portrait and approved design',()=>{const html=renderPage('index');assert(html.includes('/assets/candidate.webp'));assert(html.includes('JUSTICE'));assert(html.includes('debt of injustice'));assert(html.includes('class="brand"'));assert(html.includes('id="menu-toggle"'));});
test('donor eligibility wording is present in both views',()=>{for(const p of ['index','donate']){const h=renderPage(p);for(const fragment of ['Are a U.S. citizen or lawfully admitted permanent resident','Contribute from your own funds.','Are at least 18 years old.','Are not a federal contractor.','personal credit card','national banks, FARA registrants, or foreign nationals.','not deductible as charitable contributions for federal income tax purposes.'])assert(h.includes(fragment),`${p}: missing ${fragment}`);}});
test('all donor input fields are disabled before release',()=>{const h=renderPage('donate');for(const tag of h.match(/<(?:input|select)\b[^>]*>/g)||[])assert(tag.includes('disabled'),tag);assert(h.includes('Online contributions are not open yet'));});
test('canonical source excludes archive from browser code',()=>{
 const files=[];function walk(p){for(const name of readdirSync(p)){const f=join(p,name);if(statSync(f).isDirectory())walk(f);else files.push(f);}}walk(join(root,'apps/web/public'));walk(join(root,'apps/portal/src'));
 for(const path of files.filter(f=>/\.(js|ts|tsx|html|css)$/.test(f))){const text=readFileSync(path,'utf8');assert(!text.includes('content/materials/archive'));assert(!text.includes('window.MATERIALS'));assert(!/sk_live_|re_[a-zA-Z0-9]{30,}/.test(text));}
});
test('the complete original plan and all sixty IDs are preserved',()=>{const p=readFileSync(join(root,'docs/DEVELOPMENT_PLAN.md'),'utf8');assert(p.length>100000);for(let n=1;n<=60;n++)assert(p.includes('G28-'+String(n).padStart(2,'0')));});

test('hero keeps the pointing photo while Meet Phillip uses its own square portrait',()=>{
 const html=renderPage('index');
 assert(html.includes('class="candidate" fetchpriority="high" src="/assets/candidate.webp"'));
 const section=html.split('id="meet-phillip"')[1]?.split('class="story-copy"')[0];
 assert(section,'Meet Phillip portrait section must exist');
 assert(section.includes('src="/assets/meet-phillip.webp"'));
 assert(!section.includes('src="/assets/candidate.webp"'));
 assert(section.includes('width="800" height="800"'));
 assert(existsSync(join(root,'apps/web/public/assets/meet-phillip.webp')));
 const css=readFileSync(join(root,'apps/web/public/assets/site.css'),'utf8');
 assert.match(css,/#meet-phillip \.portrait-detail img\{[^}]*object-fit:cover/);
});
