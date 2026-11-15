-- Donor-only recovery, donor cancellation, replacement card setup and the
-- operational due-installment queue for TEST monthly card schedules.
-- Recovery codes are stored only as SHA-256 digests; no PAN, CVV or client secret.
ALTER TABLE g28.card_enrollments ADD COLUMN IF NOT EXISTS recovery_sha256 text UNIQUE;
ALTER TABLE g28.card_enrollments ADD COLUMN IF NOT EXISTS replaces_mandate_id uuid REFERENCES g28.card_mandates(id);
ALTER TABLE g28.card_enrollments ADD COLUMN IF NOT EXISTS donor_cancelled_at timestamptz;
CREATE TABLE IF NOT EXISTS g28.card_due_installments (
 mandate_id uuid NOT NULL REFERENCES g28.card_mandates(id),
 installment integer NOT NULL CHECK(installment>=0 AND installment<120),
 mandate_version integer NOT NULL CHECK(mandate_version>0),
 due_at timestamptz NOT NULL,
 window_ends_at timestamptz NOT NULL,
 status text NOT NULL CHECK(status IN ('due','reserved','missed','closed')),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(mandate_id,installment)
);
CREATE INDEX IF NOT EXISTS card_due_open ON g28.card_due_installments(status,due_at) WHERE status='due';
INSERT INTO g28.schema_migrations(version) VALUES('026_recurring_donor_service') ON CONFLICT DO NOTHING;
