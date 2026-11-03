import test from 'node:test';
import assert from 'node:assert/strict';
import {renderPage,site} from '../scripts/public-renderer.mjs';

const live={...site,mode:'production',canonicalOrigin:'https://example.org'};
test('production public copy never describes launch pages as design previews',()=>{
 for(const key of ['volunteer','donate','notices']){
  const html=renderPage(key,{site:live});
  assert.ok(!/design preview:|this preview has no|public preview creates/i.test(html),key);
  assert.ok(html.includes('index,follow'),key);
 }
});
test('volunteer access and fundraising are described precisely without implying activation',()=>{
 const volunteer=renderPage('volunteer',{site:live});
 assert.match(volunteer,/Passkey account creation is available inside the secure volunteer portal/);
 assert.match(volunteer,/No information is collected on this public page/);
 const donate=renderPage('donate',{site:live});
 assert.match(donate,/This page has no card fields and cannot accept money/);
 assert.match(donate,/Online contributions are not open yet/);
 const notices=renderPage('notices',{site:live});
 assert.match(notices,/No form on this public website creates an account/);
});
