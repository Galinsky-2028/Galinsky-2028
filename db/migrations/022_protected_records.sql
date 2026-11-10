-- Ciphertext and public recipient authority only. No recipient private keys.
CREATE TABLE IF NOT EXISTS g28.protected_devices (
 id uuid PRIMARY KEY,
 account_id uuid REFERENCES g28.accounts(id) ON DELETE SET NULL,
 fingerprint text NOT NULL UNIQUE,
 public_key text NOT NULL,
 label text NOT NULL,
 state text NOT NULL CHECK(state IN ('enrolled','approved','revoked')),
 scope text CHECK(scope IN ('incident','help','correction','profile','operational_note')),
 approved_by uuid REFERENCES g28.accounts(id) ON DELETE SET NULL,
 generation integer NOT NULL CHECK(generation>0),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS g28.protected_records (
 id uuid PRIMARY KEY,
 author_id uuid REFERENCES g28.accounts(id) ON DELETE SET NULL,
 participants uuid[] NOT NULL,
 document jsonb NOT NULL,
 version integer NOT NULL CHECK(version>0),
 retain_until timestamptz NOT NULL,
 legal_hold boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS g28.protected_lifecycle_events (
 id uuid PRIMARY KEY,
 actor_id text NOT NULL,
 record_id uuid NOT NULL,
 action text NOT NULL,
 evidence_digest text,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS protected_participants ON g28.protected_records USING gin(participants);
CREATE INDEX IF NOT EXISTS protected_lifecycle_reference ON g28.protected_lifecycle_events(record_id);
-- Only the account row being deleted can drive this narrow cleanup. The
-- volunteer-only runtime does not need general protected-table permissions.
CREATE OR REPLACE FUNCTION g28.close_protected_account() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtext('g28-protected-directory'));
 INSERT INTO g28.protected_lifecycle_events(id,actor_id,record_id,action)
 SELECT gen_random_uuid(),OLD.id::text,id,'account_closure_ciphertext_deleted'
 FROM g28.protected_records WHERE author_id=OLD.id AND legal_hold=false;
 DELETE FROM g28.protected_records WHERE author_id=OLD.id AND legal_hold=false;
 UPDATE g28.protected_devices SET state='revoked',generation=generation+1
 WHERE account_id=OLD.id AND state<>'revoked';
 RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION g28.close_protected_account() FROM PUBLIC;
DROP TRIGGER IF EXISTS close_protected_account ON g28.accounts;
CREATE TRIGGER close_protected_account BEFORE DELETE ON g28.accounts
FOR EACH ROW EXECUTE FUNCTION g28.close_protected_account();
INSERT INTO g28.schema_migrations(version) VALUES('022_protected_records') ON CONFLICT DO NOTHING;
