// SQL-created login profiles: Neon API-created roles inherit administrative membership.
// Passwords are supplied in memory by an authorized operator, never logged here.
export const PORTAL_RUNTIME_TABLES=Object.freeze([
 'account_bookmarks','account_notice_keys','accounts','activity_modules','admin_grants','content_revisions','coordination_teams','help_requests','login_requests','mail_events','mail_suppressions','material_reading','materials','operation_claims','operation_definitions','outbox','page_events','page_visit_retention','page_visits','rate_buckets','sessions','staff_security','task_progress','tool_consents','training_attestations','treasury_secrets','volunteer_passkey_challenges','volunteer_passkeys','volunteer_role_preferences',
]);
const identifier=value=>{if(typeof value!=='string'||!/^g28_(?:stripe|portal)_runtime_[a-z0-9_]{1,40}$/.test(value))throw Error('Use an explicitly scoped runtime login name.');return '"'+value+'"';};
export function runtimeRoleStatements({role,password,profile}){
 const id=identifier(role);
 if(!['stripe','portal','portal_preview'].includes(profile)||!role.startsWith('g28_'+(profile==='portal_preview'?'portal':profile)+'_runtime_'))throw Error('Runtime name/profile mismatch.');
 if(typeof password!=='string'||!/^[A-Za-z0-9_-]{43,128}$/.test(password))throw Error('Use a generated high-entropy URL-safe password.');
 const grants=profile==='portal_preview'?[`GRANT SELECT ON g28.schema_migrations TO ${id}`,`GRANT SELECT ON g28.campaign_public_releases,g28.campaign_public_settings,g28.campaign_public_media,g28.sharing_assets_public TO ${id}`]:profile==='stripe'?[
  `GRANT SELECT,INSERT,UPDATE ON g28.stripe_checkout_intents TO ${id}`,
  `GRANT SELECT,INSERT ON g28.stripe_webhook_receipts TO ${id}`,
  `GRANT INSERT ON g28.financial_provider_events TO ${id}`,
  `GRANT SELECT(provider,event_id) ON g28.financial_provider_events TO ${id}`,
 ]:[`GRANT SELECT,INSERT,UPDATE,DELETE ON ${PORTAL_RUNTIME_TABLES.map(t=>'g28.'+t).join(',')} TO ${id}`,
  `GRANT SELECT,INSERT ON g28.audit_events,g28.operation_claim_history,g28.treasury_audit,g28.treasury_exports TO ${id}`,
  `GRANT SELECT ON g28.financial_provider_events,g28.schema_migrations TO ${id}`,
  `GRANT SELECT ON g28.campaign_public_releases,g28.campaign_public_settings,g28.campaign_public_media,g28.sharing_assets_public TO ${id}`];
 return [`CREATE ROLE ${id} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}'`,
  `GRANT CONNECT ON DATABASE neondb TO ${id}`,`GRANT USAGE ON SCHEMA g28 TO ${id}`,...grants];
}
