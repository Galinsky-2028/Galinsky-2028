-- Volunteer-owned discoverable WebAuthn credentials. No mailbox, password or
-- email identity is manufactured for credential-only volunteers.
CREATE TABLE IF NOT EXISTS g28.volunteer_passkey_challenges(
 token_hash text PRIMARY KEY,
 kind text NOT NULL CHECK(kind IN ('register','authenticate')),
 challenge text NOT NULL,
 account_id uuid,
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS volunteer_passkey_challenges_expiry ON g28.volunteer_passkey_challenges(expires_at);
CREATE TABLE IF NOT EXISTS g28.volunteer_passkeys(
 credential_id text PRIMARY KEY,
 account_id uuid NOT NULL REFERENCES g28.accounts(id) ON DELETE CASCADE,
 public_key text NOT NULL,
 counter bigint NOT NULL CHECK(counter>=0),
 transports jsonb NOT NULL DEFAULT '[]'::jsonb,
 created_at timestamptz NOT NULL DEFAULT now(),
 last_used_at timestamptz
);
CREATE INDEX IF NOT EXISTS volunteer_passkeys_account ON g28.volunteer_passkeys(account_id);
INSERT INTO g28.schema_migrations(version) VALUES('021_volunteer_passkeys') ON CONFLICT DO NOTHING;
