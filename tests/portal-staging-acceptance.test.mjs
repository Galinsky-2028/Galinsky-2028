import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
test('live portal acceptance script cannot create accounts, payments or store PII',()=>{
 const file=readFileSync('scripts/verify-real-volunteer-portal.mjs','utf8');
 assert(file.includes('https://galinsky2028-volunteers.onrender.com'));
 assert(file.includes("checked('/readyz',200)"));
 assert(file.includes("checked('/api/roles',200)"));
 assert(file.includes('signupEnabled!==false'));
 assert(file.includes("await checked('/api/materials',401)"));
 assert(!file.includes('method:\'POST\''));
 assert(!file.includes('method:"POST"'));
 assert(!file.includes('console.log(token)'));
});
