-- Prospective financial consent, manual-capture reservations and command audit.
-- No PAN, CVV, client secrets or protected volunteer narratives belong here.
CREATE TABLE IF NOT EXISTS g28.card_contribution_policies (
 id uuid PRIMARY KEY,
 version integer NOT NULL UNIQUE CHECK(version>0),
 document jsonb NOT NULL,
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS g28.card_enrollments (
 id uuid PRIMARY KEY,
 client_reference text NOT NULL UNIQUE,
 request_document jsonb NOT NULL,
 request_sha256 text NOT NULL,
 environment text NOT NULL CHECK(environment IN ('test','live')),
 setup_session_id text UNIQUE,
 setup_intent_id text UNIQUE,
 customer_id text,
 payment_method_id text,
 encrypted_details text,
 status text NOT NULL CHECK(status IN ('preparing','pending','verified','requires_review','cancelled','uncertain')),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS g28.card_mandates (
 id uuid PRIMARY KEY,
 enrollment_id uuid NOT NULL UNIQUE REFERENCES g28.card_enrollments(id),
 donor_id uuid NOT NULL REFERENCES g28.treasury_donors(id),
 donor_version integer NOT NULL,
 environment text NOT NULL CHECK(environment IN ('test','live')),
 document jsonb NOT NULL,
 status text NOT NULL CHECK(status IN ('active','cancelled','held','complete')),
 version integer NOT NULL CHECK(version>0),
 approved_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(donor_id,donor_version) REFERENCES g28.treasury_donor_revisions(donor_id,version)
);
CREATE TABLE IF NOT EXISTS g28.card_mandate_revisions (
 mandate_id uuid NOT NULL REFERENCES g28.card_mandates(id),
 version integer NOT NULL,
 document jsonb NOT NULL,
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(mandate_id,version)
);
CREATE TABLE IF NOT EXISTS g28.card_periods (
 id uuid PRIMARY KEY,
 mandate_id uuid NOT NULL REFERENCES g28.card_mandates(id),
 mandate_version integer NOT NULL,
 installment integer NOT NULL CHECK(installment>=0 AND installment<120),
 donor_id uuid NOT NULL REFERENCES g28.treasury_donors(id),
 donor_version integer NOT NULL,
 environment text NOT NULL CHECK(environment IN ('test','live')),
 election text NOT NULL CHECK(election IN ('primary','general')),
 amount_cents bigint NOT NULL CHECK(amount_cents>=50 AND amount_cents<=99999999),
 document jsonb NOT NULL,
 status text NOT NULL CHECK(status IN ('reserved','authorizing','requires_action','authorized','capturing','captured_unposted','posted','cancelling','voided','uncertain','blocked')),
 reservation_active boolean NOT NULL DEFAULT true,
 expires_at timestamptz NOT NULL,
 provider_payment_id text UNIQUE,
 capture_event_id text UNIQUE,
 gift_id uuid REFERENCES g28.treasury_gifts(id),
 version integer NOT NULL CHECK(version>0),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(mandate_id,installment),
 FOREIGN KEY(donor_id,donor_version) REFERENCES g28.treasury_donor_revisions(donor_id,version)
);
CREATE TABLE IF NOT EXISTS g28.card_commands (
 id uuid PRIMARY KEY,
 period_id uuid NOT NULL REFERENCES g28.card_periods(id),
 action text NOT NULL CHECK(action IN ('authorize','capture','cancel')),
 request_document jsonb NOT NULL,
 request_sha256 text NOT NULL,
 status text NOT NULL CHECK(status IN ('processing','observed','uncertain','reconciled')),
 provider_reference text,
 result_document jsonb,
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS card_period_live_command ON g28.card_commands(period_id) WHERE status IN ('processing','uncertain');
CREATE TABLE IF NOT EXISTS g28.card_workflow_audit (
 id uuid PRIMARY KEY,
 actor_id text NOT NULL,
 object_id uuid NOT NULL,
 action text NOT NULL,
 digest text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS card_period_active_reservation ON g28.card_periods(donor_id,environment,election) WHERE reservation_active;
CREATE INDEX IF NOT EXISTS card_enrollment_page ON g28.card_enrollments(updated_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS card_mandate_page ON g28.card_mandates(updated_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS card_period_page ON g28.card_periods(updated_at DESC,id DESC);
INSERT INTO g28.schema_migrations(version) VALUES('025_card_mandates') ON CONFLICT DO NOTHING;
