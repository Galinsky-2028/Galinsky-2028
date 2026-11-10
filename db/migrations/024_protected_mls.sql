-- Public cryptographic authority and one-time MLS delivery metadata only.
-- Root/device private keys, private KeyPackages and MLS states stay on clients.
CREATE TABLE IF NOT EXISTS g28.protected_identities (
 id uuid PRIMARY KEY,
 account_id uuid REFERENCES g28.accounts(id) ON DELETE SET NULL,
 current boolean NOT NULL DEFAULT true,
 root_fingerprint text NOT NULL UNIQUE,
 initial_state jsonb NOT NULL,
 state jsonb NOT NULL,
 state_hash text NOT NULL,
 sequence integer NOT NULL CHECK(sequence>0),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS protected_current_identity ON g28.protected_identities(account_id) WHERE current AND account_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS g28.protected_identity_events (
 id uuid PRIMARY KEY,
 identity_id uuid NOT NULL REFERENCES g28.protected_identities(id),
 sequence integer NOT NULL,
 previous_state_hash text NOT NULL,
 document jsonb NOT NULL,
 root_signature text NOT NULL,
 device_signature text,
 state_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(identity_id,sequence)
);
-- Retired key identities are never reused, including after replacement.
CREATE TABLE IF NOT EXISTS g28.protected_identity_keys (
 key_id text PRIMARY KEY,
 identity_id uuid NOT NULL REFERENCES g28.protected_identities(id),
 subject_id uuid NOT NULL,
 generation integer NOT NULL,
 kind text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE g28.protected_devices ADD COLUMN IF NOT EXISTS identity_id uuid REFERENCES g28.protected_identities(id);
ALTER TABLE g28.protected_devices ADD COLUMN IF NOT EXISTS mls_signing_key text;
ALTER TABLE g28.protected_devices ADD COLUMN IF NOT EXISTS quarantined boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS protected_devices_identity ON g28.protected_devices(identity_id);
CREATE TABLE IF NOT EXISTS g28.protected_package_claims (
 record_id uuid PRIMARY KEY,
 account_id uuid REFERENCES g28.accounts(id) ON DELETE SET NULL,
 sender_device_id uuid NOT NULL REFERENCES g28.protected_devices(id),
 recipient_devices uuid[] NOT NULL,
 kind text NOT NULL,
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS g28.protected_key_packages (
 id uuid PRIMARY KEY,
 device_id uuid NOT NULL REFERENCES g28.protected_devices(id),
 identity_id uuid NOT NULL REFERENCES g28.protected_identities(id),
 generation integer NOT NULL,
 package_sha256 text NOT NULL UNIQUE,
 init_sha256 text NOT NULL UNIQUE,
 package_ref text NOT NULL UNIQUE,
 wire text,
 expires_at timestamptz NOT NULL,
 state text NOT NULL CHECK(state IN ('available','reserved','used','expired')),
 record_id uuid,
 lease_until timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS protected_key_packages_available ON g28.protected_key_packages(device_id,state,expires_at);
CREATE INDEX IF NOT EXISTS protected_key_packages_record ON g28.protected_key_packages(record_id);
-- Closure withdraws routing authority. It must not forge a root-signed
-- identity transition. Older prototype devices retain their prior semantics.
CREATE OR REPLACE FUNCTION g28.close_protected_account() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtext('g28-protected-directory'));
 INSERT INTO g28.protected_lifecycle_events(id,actor_id,record_id,action)
 SELECT gen_random_uuid(),OLD.id::text,id,'account_closure_ciphertext_deleted'
 FROM g28.protected_records WHERE author_id=OLD.id AND legal_hold=false;
 DELETE FROM g28.protected_records WHERE author_id=OLD.id AND legal_hold=false;
 UPDATE g28.protected_devices SET quarantined=true WHERE account_id=OLD.id;
 UPDATE g28.protected_devices SET state='revoked',generation=generation+1
 WHERE account_id=OLD.id AND identity_id IS NULL AND state<>'revoked';
 UPDATE g28.protected_identities SET current=false WHERE account_id=OLD.id;
 UPDATE g28.protected_key_packages SET state='expired',wire=NULL,lease_until=NULL
 WHERE device_id IN (SELECT id FROM g28.protected_devices WHERE account_id=OLD.id) AND state<>'used';
 RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION g28.close_protected_account() FROM PUBLIC;
INSERT INTO g28.schema_migrations(version) VALUES('024_protected_mls') ON CONFLICT DO NOTHING;
