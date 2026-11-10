CREATE TABLE IF NOT EXISTS g28.treasury_evidence (
 id uuid PRIMARY KEY,
 digest text NOT NULL,
 byte_count integer NOT NULL,
 encrypted_envelope text NOT NULL,
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS treasury_evidence_digest ON g28.treasury_evidence(digest);
CREATE TABLE IF NOT EXISTS g28.treasury_policies (
 id uuid PRIMARY KEY,
 version integer NOT NULL UNIQUE,
 document jsonb NOT NULL,
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS g28.treasury_donors (
 id uuid PRIMARY KEY,
 encrypted_envelope text NOT NULL,
 evidence_digest text NOT NULL,
 version integer NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS g28.treasury_donor_revisions (
 donor_id uuid NOT NULL REFERENCES g28.treasury_donors(id),
 version integer NOT NULL,
 encrypted_envelope text NOT NULL,
 evidence_digest text NOT NULL,
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(donor_id,version)
);
CREATE TABLE IF NOT EXISTS g28.treasury_journal (
 id uuid PRIMARY KEY,
 gift_id uuid NOT NULL,
 source text NOT NULL,
 external_reference text NOT NULL,
 environment text NOT NULL CHECK(environment IN ('test','live')),
 event_kind text NOT NULL,
 document jsonb NOT NULL,
 digest text NOT NULL,
 created_by text NOT NULL,
 posted_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(source,external_reference,environment)
);
CREATE INDEX IF NOT EXISTS treasury_journal_gift ON g28.treasury_journal(gift_id);
CREATE TABLE IF NOT EXISTS g28.treasury_gifts (
 id uuid PRIMARY KEY,
 donor_id uuid NOT NULL REFERENCES g28.treasury_donors(id),
 source text NOT NULL,
 environment text NOT NULL CHECK(environment IN ('test','live')),
 state jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS g28.treasury_settlements (
 id uuid PRIMARY KEY,
 source text NOT NULL,
 environment text NOT NULL CHECK(environment IN ('test','live')),
 external_reference text NOT NULL,
 document jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(source,environment,external_reference)
);
CREATE TABLE IF NOT EXISTS g28.treasury_settlement_entries (
 entry_id uuid PRIMARY KEY REFERENCES g28.treasury_journal(id),
 settlement_id uuid NOT NULL REFERENCES g28.treasury_settlements(id)
);
CREATE TABLE IF NOT EXISTS g28.treasury_deposits (
 id uuid PRIMARY KEY,
 settlement_id uuid NOT NULL REFERENCES g28.treasury_settlements(id),
 bank_reference text NOT NULL,
 document jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(settlement_id,bank_reference)
);
CREATE TABLE IF NOT EXISTS g28.treasury_cases (
 id uuid PRIMARY KEY,
 gift_id uuid NOT NULL REFERENCES g28.treasury_gifts(id),
 document jsonb NOT NULL,
 version integer NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS g28.treasury_commands (
 id uuid PRIMARY KEY,
 case_id uuid NOT NULL REFERENCES g28.treasury_cases(id),
 document jsonb NOT NULL,
 status text NOT NULL CHECK(status IN ('processing','accepted','uncertain','failed','reconciled')),
 provider_reference text,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS g28.treasury_workflow_audit (
 id uuid PRIMARY KEY,
 actor_id text NOT NULL,
 object_id uuid NOT NULL,
 action text NOT NULL,
 digest text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS g28.treasury_case_notices (
 case_id uuid NOT NULL REFERENCES g28.treasury_cases(id),
 case_version integer NOT NULL,
 donor_id uuid NOT NULL REFERENCES g28.treasury_donors(id),
 donor_version integer NOT NULL,
 job_id uuid UNIQUE REFERENCES g28.outbox(id) ON DELETE SET NULL,
 PRIMARY KEY(case_id,case_version)
);
ALTER TABLE g28.outbox DROP CONSTRAINT IF EXISTS outbox_kind_check;
ALTER TABLE g28.outbox ADD CONSTRAINT outbox_kind_check CHECK(kind IN ('account_login','account_welcome','account_security','account_reminder','finance_attention'));
CREATE TABLE IF NOT EXISTS g28.stripe_payment_identities (
 session_id text PRIMARY KEY REFERENCES g28.stripe_checkout_intents(session_id),
 payment_intent_id text NOT NULL UNIQUE,
 livemode boolean NOT NULL
);
CREATE TABLE IF NOT EXISTS g28.stripe_remedy_events (
 event_id text PRIMARY KEY REFERENCES g28.stripe_webhook_receipts(event_id),
 session_id text NOT NULL,
 provider_reference text NOT NULL,
 command_id uuid,
 kind text NOT NULL,
 amount_cents bigint NOT NULL,
 event_sha256 text NOT NULL,
 occurred_at timestamptz NOT NULL,
 livemode boolean NOT NULL
);
CREATE INDEX IF NOT EXISTS treasury_gifts_page ON g28.treasury_gifts(updated_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS treasury_gifts_donor ON g28.treasury_gifts(donor_id,environment);
CREATE INDEX IF NOT EXISTS treasury_cases_page ON g28.treasury_cases(updated_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS treasury_cases_gift ON g28.treasury_cases(gift_id);
CREATE INDEX IF NOT EXISTS treasury_commands_page ON g28.treasury_commands(updated_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS treasury_evidence_page ON g28.treasury_evidence(created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS treasury_journal_page ON g28.treasury_journal(posted_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS treasury_settlements_page ON g28.treasury_settlements(created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS treasury_deposits_page ON g28.treasury_deposits(created_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS financial_source_page ON g28.financial_provider_events(received_at DESC,provider DESC,event_id DESC);
INSERT INTO g28.schema_migrations(version) VALUES('023_treasury_workflows') ON CONFLICT DO NOTHING;
