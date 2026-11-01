import test from 'node:test';import assert from 'node:assert/strict';
import {readableVersion,matchesReading} from '../packages/core/material-reading.mjs';
const account={verified:true,id:'synthetic-account'};
const current={id:'guide-one',status:'published',audience:'volunteer',author:'fixture-author',revision:2,body:'Only reviewed text.',review:{approvedBy:'external-reviewer',revision:2,at:'2026-10-10T00:00:00Z'}};
test('reading acknowledgement binds exactly the reviewed revision and body bytes',()=>{
 const v=readableVersion(current,account);
 assert.match(v.contentSha256,/^[0-9a-f]{64}$/);
 assert(matchesReading(current,account,v));
 assert(!matchesReading({...current,body:'Updated and reviewed'},account,v));
 assert(!matchesReading({...current,revision:3,review:{...current.review,revision:3}},account,v));
 assert(!matchesReading(current,account,{...v,materialId:'other-guide'}));
});
test('reading status cannot bypass review, publication or verified account',()=>{
 assert.throws(()=>readableVersion({...current,status:'draft'},account));
 assert.throws(()=>readableVersion({...current,review:{...current.review,revision:1}},account));
 assert.throws(()=>readableVersion(current,{verified:false}));
 assert(!matchesReading(current,{verified:false},readableVersion(current,account)));
 assert.throws(()=>readableVersion({...current,body:{html:'<script>'}},account));
});
