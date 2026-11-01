import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';import {join} from 'node:path';import {createHash} from 'node:crypto';
import {publishedPolicyDocuments,policyDocumentSection} from '../packages/core/policy-documents.mjs';
import {renderSafePolicyHtml} from '../packages/core/safe-policy-document.mjs';
import {renderPage,site} from '../scripts/public-renderer.mjs';
function fixture(fn){
 const dir=mkdtempSync(join(tmpdir(),'g28-policy-assets-'));mkdirSync(join(dir,'documents'));
 const content=Buffer.from('%PDF-1.6\n%Synthetic bytes for tests only.');
 const path='/documents/kirk-evers-bill-v1.pdf';writeFileSync(join(dir,'documents','kirk-evers-bill-v1.pdf'),content);
 const record={id:'kirk-evers-bill-1',kind:'bill',label:'The reviewed Kirk–Evers bill',description:'Synthetic fixture only',path,revision:1,author:'editor_a',sha256:createHash('sha256').update(content).digest('hex'),review:{approvedBy:'reviewer_b',revision:1,at:'2026-10-11T10:00:00Z'},status:'published'};
 try{return fn({dir,record});}finally{rmSync(dir,{force:true,recursive:true});}
}
test('no local reviewed bill published at launch; placeholders are clearly not downloads',()=>{
 const html=renderPage('kirk-evers');
 assert.match(html,/AWAITING<br>APPROVED FILE/);
 assert.match(html,/Only approved publication editions appear/);
 assert.ok(!html.includes('{{DOCUMENTS:'));
 assert.ok(!html.includes('href="/documents/'));
});
test('reviewed, integrity-matching PDF link replaces only its own placeholder slot',()=>fixture(({dir,record})=>{
 const html=policyDocumentSection('kirk-evers',[record],dir);
 assert(html.includes('href="/documents/kirk-evers-bill-v1.pdf"'));
 assert.match(html,/The reviewed Kirk–Evers bill/);
 assert.equal((html.match(/class="resource resource-link"/g)||[]).length,1);
 assert.equal((html.match(/AWAITING<br>APPROVED FILE/g)||[]).length,2);
 assert.equal(publishedPolicyDocuments('kirk-evers',[record],dir).length,1);
}));
test('drafts are not advertised, and HTML-like labels are escaped',()=>fixture(({dir,record})=>{
 const draft={...record,status:'draft'};assert(!policyDocumentSection('kirk-evers',[draft],dir).includes('href="/documents/'));
 const html=policyDocumentSection('kirk-evers',[{...record,label:'Reviewed <script> record'}],dir);
 assert(html.includes('Reviewed &lt;script&gt; record'));assert(!html.includes('Reviewed <script> record'));
}));
test('asset hashes, independent review and safe paths are mandatory',()=>fixture(({dir,record})=>{
 const variants=[
 {...record,sha256:'0'.repeat(64)},
 {...record,review:{...record.review,approvedBy:record.author}},
 {...record,review:{...record.review,revision:2}},
 {...record,review:null},
 {...record,path:'/../../internal.pdf'},
 {...record,path:'/documents/other.pdf'},
 {...record,revision:0}
 ];
 for(const v of variants)assert.throws(()=>publishedPolicyDocuments('kirk-evers',[v],dir));
 assert.throws(()=>publishedPolicyDocuments('garden',[record],dir));
 assert.throws(()=>publishedPolicyDocuments('kirk-evers',[record,record],dir));
}));
test('only safe generated standalone HTML files can be linked',()=>fixture(({dir,record})=>{
 const htmlPath='/documents/kirk-evers-summary-v1.html';
 const file=join(dir,'documents','kirk-evers-summary-v1.html');
 const safe=renderSafePolicyHtml({title:'Summary',source:'# Summary\n\nSynthetic reviewed content.'});
 writeFileSync(file,safe);
 const item={...record,id:'summary-1',kind:'summary',path:htmlPath,sha256:createHash('sha256').update(safe).digest('hex')};
 assert.equal(publishedPolicyDocuments('kirk-evers',[item],dir).length,1);
 writeFileSync(file,safe.replace('<h1>Summary</h1>','<script>alert(1)</script>'));
 assert.throws(()=>publishedPolicyDocuments('kirk-evers',[{...item,sha256:createHash('sha256').update(safe.replace('<h1>Summary</h1>','<script>alert(1)</script>')).digest('hex')}],dir));
}));
test('production social sharing has exactly one OG image, not duplicates',()=>{
 const page=renderPage('kirk-evers',{site:{...site,mode:'production',canonicalOrigin:'https://campaign.example'}});
 assert.equal((page.match(/<meta property="og:image"/g)||[]).length,1);
});

