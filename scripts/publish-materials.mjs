import {readFile} from 'node:fs/promises';
import {databasePool} from '../apps/api/src/postgres-store.mjs';
import {materialDigest} from '../packages/core/staff-review.mjs';
import {validateConfiguredMaterialRelease,ownerMaterialDigest,OWNER_REVIEW_MODE} from '../packages/core/owner-material-release.mjs';
import {randomUUID} from 'node:crypto';
if(!process.env.DATABASE_URL)throw new Error('DATABASE_URL is required.');
const records=validateConfiguredMaterialRelease(JSON.parse(await readFile('content/materials/current.json','utf8')),{staffRegistry:JSON.parse(await readFile('content/materials/staff-keys.json','utf8')),ownerRelease:JSON.parse(await readFile('content/materials/owner-release.json','utf8'))});
const pool=databasePool(process.env.DATABASE_URL),c=await pool.connect();
try{
 await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock(282029)');
 for(const m of records){
  const q=await c.query('SELECT revision FROM g28.materials WHERE id=$1 FOR UPDATE',[m.id]);
  if(q.rows[0]&&q.rows[0].revision>=m.revision)throw new Error('Publication requires a strictly newer revision: '+m.id);
  await c.query(`INSERT INTO g28.materials(id,revision,status,audience,record) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET revision=EXCLUDED.revision,status=EXCLUDED.status,audience=EXCLUDED.audience,record=EXCLUDED.record,updated_at=now()`,[m.id,m.revision,m.status,m.audience,m]);
  await c.query('INSERT INTO g28.audit_events(id,actor_subject,action,object_id,result) VALUES($1,$2,$3,$4,$5)',[randomUUID(),m.author+' -> '+m.review.approvedBy,m.publication?.mode===OWNER_REVIEW_MODE?'material_publish_owner_ai':'material_publish_signed_v2',m.id+'@'+m.revision,m.publication?.mode===OWNER_REVIEW_MODE?ownerMaterialDigest(m):materialDigest(m)]);
 }
 await c.query('COMMIT');console.log('Published '+records.length+' approved material revisions.');
}catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();await pool.end();}
