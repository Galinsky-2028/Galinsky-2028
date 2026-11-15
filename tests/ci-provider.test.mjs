import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync,readFileSync} from 'node:fs';

test('public Galinsky 2028 repository uses GitHub Actions, not CircleCI',()=>{
 assert.equal(existsSync('.circleci/config.yml'),false,'CircleCI configuration must not be reintroduced');
 const workflow=readFileSync('.github/workflows/ci.yml','utf8');
 // Standard no-charge GitHub-hosted Ubuntu runners only (a pinned version label is still standard).
 const runners=[...workflow.matchAll(/runs-on:\s*(\S+)/g)].map((m)=>m[1]);
 assert.ok(runners.length>0);
 for(const runner of runners)assert.match(runner,/^ubuntu-(?:latest|2[0-9]\.04)$/,'only standard GitHub-hosted runners');
 assert.match(workflow,/pull_request:/);
 assert.match(workflow,/npm run test:api/);
 assert.match(workflow,/npm run test:browser/);
 assert.match(workflow,/npm run secrets:check/);
});
