import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {runtimeRoleStatements,PORTAL_RUNTIME_TABLES} from '../scripts/runtime-role-permissions.mjs';
test('runtime provisioning rejects arbitrary identity, mismatched profiles and unsafe password text',()=>{
 const good={role:'g28_stripe_runtime_test',profile:'stripe',password:randomBytes(36).toString('base64url')};
 for(const change of [{role:'neondb_owner'},{profile:'portal'},{password:"unsafe' sql"},{role:'g28_stripe_runtime_bad;DROP'}])assert.throws(()=>runtimeRoleStatements({...good,...change}));
 const sql=runtimeRoleStatements(good).join('\n');assert(sql.includes('NOCREATEROLE'));assert(!sql.includes('ALL TABLES'));assert(!sql.includes('DEFAULT PRIVILEGES'));assert(!PORTAL_RUNTIME_TABLES.includes('schema_migrations'));
});

test('disabled-signup preview profile has only health metadata and public campaign projection reads',()=>{const sql=runtimeRoleStatements({role:'g28_portal_runtime_preview',profile:'portal_preview',password:randomBytes(36).toString('base64url')}).join('\n');assert(sql.includes('schema_migrations'));assert(sql.includes('campaign_public_releases'));for(const token of ['accounts','sessions','treasury_secrets','financial_provider_events','content_revisions','INSERT','UPDATE','DELETE'])assert(!sql.includes(token));});

const options={role:'g28_portal_runtime_test',password:'a'.repeat(43),profile:'volunteer',database:'galinsky2028'};
test('volunteer-only credentials omit staff, publication and treasury privileges',()=>{
 const sql=runtimeRoleStatements(options).join('\n');
 assert.match(sql,/CONNECT ON DATABASE galinsky2028/);
 assert.match(sql,/NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS/);
 assert.match(sql,/g28\.volunteer_passkeys/);
 for(const table of ['admin_grants','staff_security','treasury_secrets','content_revisions','financial_provider_events'])assert(!sql.includes('g28.'+table));
 assert.match(sql,/GRANT SELECT ON g28\.materials,g28\.activity_modules,g28\.schema_migrations/);
});
test('role profiles refuse interpolated database names and mismatched identities',()=>{
 for(const database of ['other; DROP SCHEMA g28 CASCADE','"galinsky2028"','',undefined]) {
  if(database===undefined)assert.match(runtimeRoleStatements({...options,database}).join('\n'),/DATABASE neondb/);
  else assert.throws(()=>runtimeRoleStatements({...options,database}),/database name/);
 }
 assert.throws(()=>runtimeRoleStatements({...options,role:'g28_stripe_runtime_test'}),/mismatch/);
});
