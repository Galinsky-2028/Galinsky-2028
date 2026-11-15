// Subresource Integrity for the volunteer portal build.
//
// Every emitted JavaScript and CSS file is hashed with SHA-384 after its final
// bytes are known. index.html then carries:
//  - an inline import map whose `integrity` table covers EVERY JavaScript chunk,
//    including chunks loaded later through dynamic import(), so a substituted or
//    altered chunk is refused by browsers that enforce import-map integrity;
//  - `integrity` attributes on the entry script, module preloads and stylesheets.
// The portal server hashes the inline import map and allows exactly that hash in
// its Content-Security-Policy (apps/api/src/static.mjs); no other inline script runs.
import {createHash} from 'node:crypto';

const sri=(bytes)=>'sha384-'+createHash('sha384').update(bytes).digest('base64');
const escapeJson=(value)=>JSON.stringify(value).replace(/</g,'\\u003c');

export function releaseIntegrity(){
 return {
  name:'g28-release-integrity',
  apply:'build',
  enforce:'post',
  generateBundle:{order:'post',handler(_options,bundle){
   const hashes=new Map();
   for(const file of Object.values(bundle)){
    if(file.type==='chunk')hashes.set('/'+file.fileName,sri(file.code));
    else if(/\.css$/.test(file.fileName))hashes.set('/'+file.fileName,sri(file.source));
   }
   const html=bundle['index.html'];
   if(!html||html.type!=='asset')throw Error('Portal release integrity: index.html was not emitted.');
   let text=String(html.source);
   const integrity={};
   for(const [url,hash] of [...hashes].sort(([a],[b])=>a.localeCompare(b)))if(url.endsWith('.js'))integrity[url]=hash;
   if(!Object.keys(integrity).length)throw Error('Portal release integrity: no JavaScript chunks were emitted.');
   // Add integrity to every tag that references an emitted file; fail on any reference we cannot bind.
   text=text.replace(/<(script|link)\b([^>]*?)\s(src|href)="(\/assets\/[^"]+)"([^>]*)>/g,(tag,name,before,attr,url,after)=>{
    const hash=hashes.get(url);
    if(!hash)throw Error('Portal release integrity: unhashed reference '+url);
    if(/\sintegrity=/.test(tag))throw Error('Portal release integrity: duplicate integrity for '+url);
    return `<${name}${before} ${attr}="${url}" integrity="${hash}"${after}>`;
   });
   const importMap=`<script type="importmap">${escapeJson({integrity})}</script>`;
   if(!/<meta charset="UTF-8">/i.test(text))throw Error('Portal release integrity: charset meta not found.');
   text=text.replace(/(<meta charset="UTF-8">)/i,`$1${importMap}`);
   if((text.match(/<script type="importmap">/g)||[]).length!==1)throw Error('Portal release integrity: expected exactly one import map.');
   html.source=text;
  }},
 };
}
