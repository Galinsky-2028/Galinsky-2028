import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {renderPage,root} from '../scripts/public-renderer.mjs';
import {join} from 'node:path';

test('hero flag animates colliding dots including fifty white dot stars',()=>{
 const h=renderPage('index');
 const motion=readFileSync(join(root,'apps/web/public/assets/motion.js'),'utf8');
 assert(h.includes('class="flag-canvas"'));
 assert(h.includes('/assets/motion.js'));
 assert(!h.includes('Pause animation'));
 assert(h.includes('id="flag-motion-toggle"'));
 assert(motion.includes('g28-hero-motion-paused'));
 assert(motion.includes('prefers-reduced-motion: reduce'));
 assert(motion.includes("const count = row % 2 === 0 ? 6 : 5"));
 assert(motion.includes('for (let row = 0; row < 9; row++)'));
 assert(motion.includes("addParticle(u + Math.cos(angle)"));
 assert(motion.includes("'#ffffff'"));
 assert(motion.includes('const buckets = new Map()'));
});

test('the public volunteer site links to the REAL deployed volunteer application',()=>{
 const h=renderPage('volunteer');
 const url='https://galinsky-2028-volunteer-portal.onrender.com/roles';
 assert(h.includes(url));
 assert.equal((h.match(/href="https:\/\/galinsky-2028-volunteer-portal\.onrender\.com\/roles\?role=/g)||[]).length,14);
 assert(h.includes(url+'?role=skills'));
 assert(h.includes('data-role-id="13"'));
 assert(h.includes('Passkey account creation is available inside the secure volunteer portal'));
 assert(!h.includes('id="preview-workspace"'));
 assert(!h.includes('id="preview-role-select"'));
 assert(!h.includes('id="preview-download"'));
 assert(!h.includes('volunteer-preview.js'));
 assert(!h.includes('volunteer-preview.css'));
 assert(!h.includes('#preview-workspace'));
 const header=renderPage('index');
 assert(header.includes(url));
});
