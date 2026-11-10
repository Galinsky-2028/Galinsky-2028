// Intentionally server-readable, authenticated encryption at rest, NOT E2EE.
// Bind the record class, identity and revision inside the authenticated payload;
// an envelope copied from any other vault/record context fails before use.
import { sealTreasury, openTreasury } from './treasury-vault.mjs';
import { assert } from './validation.mjs';
export const sealFinanceIdentity = (id, version, value, key) =>
  sealTreasury('bank', { context: 'g28:donor-identity:v1', id, version, value }, key);
export function openFinanceIdentity(id, version, envelope, key) {
  const doc = openTreasury('bank', envelope, key);
  assert(
    doc.context === 'g28:donor-identity:v1' && doc.id === id && doc.version === version,
    'finance_identity_binding',
    'The encrypted identity does not match this record.',
    409,
  );
  return doc.value;
}
export const sealFinanceEvidence = (id, value, key) =>
  sealTreasury('bank', { context: 'g28:finance-evidence:v1', id, value }, key);
export function openFinanceEvidence(id, envelope, key) {
  const doc = openTreasury('bank', envelope, key);
  assert(
    doc.context === 'g28:finance-evidence:v1' && doc.id === id,
    'finance_evidence_binding',
    'The encrypted evidence does not match this record.',
    409,
  );
  return doc.value;
}
