// SQL-created login profiles: Neon API-created roles inherit administrative membership.
// Passwords are supplied in memory by an authorized operator, never logged here.
export const PORTAL_RUNTIME_TABLES=Object.freeze([
 'account_bookmarks','account_notice_keys','accounts','activity_modules','admin_grants','content_revisions','coordination_teams','help_requests','login_requests','mail_events','mail_suppressions','material_reading','materials','operation_claims','operation_definitions','outbox','page_events','page_visit_retention','page_visits','protected_devices','protected_records','rate_buckets','sessions','staff_security','task_progress','tool_consents','training_attestations','treasury_secrets','volunteer_passkey_challenges','volunteer_passkeys','volunteer_role_preferences',
]);
const identifier=value=>{if(typeof value!=='string'||!/^g28_(?:stripe|portal)_runtime_[a-z0-9_]{1,40}$/.test(value))throw Error('Use an explicitly scoped runtime login name.');return '"'+value+'"';};
export function runtimeRoleStatements({role,password,profile,database="neondb"}){
 const id=identifier(role);
 if(!['stripe','portal','portal_preview','volunteer'].includes(profile)||!role.startsWith('g28_'+(['portal_preview','volunteer'].includes(profile)?'portal':profile)+'_runtime_'))throw Error('Runtime name/profile mismatch.');
 if(typeof password!=='string'||!/^[A-Za-z0-9_-]{43,128}$/.test(password))throw Error('Use a generated high-entropy URL-safe password.');
 if(typeof database!=='string'||!/^[a-z][a-z0-9_]{0,62}$/.test(database))throw Error('Use an explicit safe database name.');
 const grants=profile==='volunteer'?[
  `GRANT SELECT,INSERT,UPDATE,DELETE ON g28.accounts,g28.sessions,g28.rate_buckets,g28.volunteer_passkey_challenges,g28.volunteer_passkeys,g28.volunteer_role_preferences,g28.task_progress,g28.account_bookmarks,g28.material_reading TO ${id}`,
  `GRANT SELECT ON g28.materials,g28.activity_modules,g28.schema_migrations,g28.help_requests TO ${id}`,
  // Existing account closure/export removes that account from coordination and queued mail.
  `GRANT SELECT,UPDATE ON g28.coordination_teams TO ${id}`,
  `GRANT SELECT,DELETE ON g28.login_requests,g28.outbox TO ${id}`,
 ]:profile==='portal_preview'?[`GRANT SELECT ON g28.schema_migrations TO ${id}`,`GRANT SELECT ON g28.campaign_public_releases,g28.campaign_public_settings,g28.campaign_public_media,g28.sharing_assets_public TO ${id}`]:profile==='stripe'?[
  `GRANT SELECT,INSERT,UPDATE ON g28.stripe_checkout_intents TO ${id}`,
  `GRANT SELECT,INSERT ON g28.stripe_webhook_receipts TO ${id}`,
  `GRANT SELECT,INSERT ON g28.stripe_payment_identities,g28.stripe_remedy_events TO ${id}`,
  `GRANT INSERT ON g28.financial_provider_events TO ${id}`,
  `GRANT SELECT(provider,event_id,payment_id,event_kind,amount_cents) ON g28.financial_provider_events TO ${id}`,
 ]:[`GRANT SELECT,INSERT,UPDATE,DELETE ON ${PORTAL_RUNTIME_TABLES.map(t=>'g28.'+t).join(',')} TO ${id}`,
  `GRANT SELECT,INSERT ON g28.audit_events,g28.operation_claim_history,g28.treasury_audit,g28.treasury_exports,g28.protected_lifecycle_events TO ${id}`,
  `GRANT SELECT ON g28.financial_provider_events,g28.schema_migrations TO ${id}`,
  `GRANT SELECT ON g28.stripe_remedy_events TO ${id}`,
  `GRANT SELECT,INSERT ON g28.treasury_evidence,g28.treasury_policies,g28.treasury_donor_revisions,g28.treasury_journal,g28.treasury_settlements,g28.treasury_settlement_entries,g28.treasury_deposits,g28.treasury_workflow_audit,g28.treasury_case_notices TO ${id}`,
  `GRANT SELECT,INSERT,UPDATE ON g28.treasury_donors,g28.treasury_gifts,g28.treasury_cases,g28.treasury_commands TO ${id}`,
  `GRANT SELECT ON g28.campaign_public_releases,g28.campaign_public_settings,g28.campaign_public_media,g28.sharing_assets_public TO ${id}`];
 return [`CREATE ROLE ${id} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}'`,
  `GRANT CONNECT ON DATABASE ${database} TO ${id}`,`GRANT USAGE ON SCHEMA g28 TO ${id}`,...grants];
}
