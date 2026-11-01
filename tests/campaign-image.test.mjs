import test from 'node:test';
import assert from 'node:assert/strict';
import {deflateSync} from 'node:zlib';
import {normalizeCampaignPng,pngChunk,pngCrc,decodeCampaignUpload} from '../packages/core/campaign-image.mjs';
const sig=Buffer.from([137,80,78,71,13,10,26,10]);
function png({width=1,height=1,depth=8,type=6,interlace=0,raw=Buffer.from([0,40,60,80,255]),extra=[],trailing=Buffer.alloc(0),zextra=Buffer.alloc(0)}={}){
 const header=Buffer.alloc(13);header.writeUInt32BE(width);header.writeUInt32BE(height,4);header[8]=depth;header[9]=type;header[12]=interlace;
 return Buffer.concat([sig,pngChunk('IHDR',header),...extra,pngChunk('IDAT',Buffer.concat([deflateSync(raw),zextra])),pngChunk('IEND',Buffer.alloc(0)),trailing]);
}
const rejects=async b=>assert.rejects(normalizeCampaignPng(b),e=>e.code==='invalid_image');
test('valid static raster is normalized and round trips idempotently',async()=>{const a=await normalizeCampaignPng(png());assert.equal(a.width,1);assert.equal(a.height,1);assert.deepEqual((await normalizeCampaignPng(a.bytes)).bytes,a.bytes);});
test('ancillary metadata stripped, not exposed in output',async()=>{const a=await normalizeCampaignPng(png({extra:[pngChunk('tEXt',Buffer.from('private metadata'))]}));assert.ok(!a.bytes.includes(Buffer.from('private metadata')));});
test('non-ASCII chunk names cannot alias valid critical names through ASCII masking',async()=>{
 const bytes=png();bytes[12]|=0x80;bytes.writeUInt32BE(pngCrc(bytes.subarray(12,29)),29);
 await rejects(bytes);
});
test('invalid reserved chunk-type bit is rejected even with a correct checksum',async()=>{
 await rejects(png({extra:[pngChunk('text',Buffer.from('invalid reserved-bit chunk'))]}));
});
test('trailing polyglots and extra compressed payload refused',async()=>{await rejects(png({trailing:Buffer.from('<script>bad</script>')}));await rejects(png({zextra:Buffer.from('trailing')}));});
test('invalid checksums and chunk lengths refused',async()=>{const a=png();a[30]^=1;await rejects(a);const b=png();b.writeUInt32BE(0x7fffffff,8);await rejects(b);});
test('unsupported palette/interlace/depth/animation rejected',async()=>{await rejects(png({type:3}));await rejects(png({interlace:1}));await rejects(png({depth:16}));await rejects(png({extra:[pngChunk('acTL',Buffer.alloc(8))]}));});
test('oversized dimensions and decompression expansion are bounded',async()=>{await rejects(png({width:5000}));await rejects(png({width:4096,height:4096}));await rejects(png({raw:Buffer.alloc(1000000)}));});
test('missing pixels, invalid filters, SVG and bogus signatures rejected',async()=>{await rejects(png({raw:Buffer.from([0])}));await rejects(png({raw:Buffer.from([5,1,2,3,4])}));await rejects(Buffer.from('<svg onload="bad"/>'));await rejects(Buffer.alloc(70));});
test('only canonical bounded base64 accepted',()=>{const a=png();assert.deepEqual(decodeCampaignUpload(a.toString('base64')),a);for(const b of ['AA==\n','data:image/png,abc','a===','____',null])assert.throws(()=>decodeCampaignUpload(b));});
