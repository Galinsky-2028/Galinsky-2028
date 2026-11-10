#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {validateConfiguredMaterialRelease,OWNER_REVIEW_MODE} from '../packages/core/owner-material-release.mjs';
try{
 const records=JSON.parse(readFileSync('content/materials/current.json','utf8'));
 const registry=JSON.parse(readFileSync('content/materials/staff-keys.json','utf8'));
 const ownerRelease=JSON.parse(readFileSync('content/materials/owner-release.json','utf8'));
 validateConfiguredMaterialRelease(records,{staffRegistry:registry,ownerRelease});
 console.log('VERIFIED '+records.length+' current volunteer-material revisions; approval: '+(records.every(m=>m.publication?.mode===OWNER_REVIEW_MODE)?OWNER_REVIEW_MODE:'two-party staff signatures'));
}catch(e){console.error('Publication denied: '+e.message);process.exitCode=1;}
