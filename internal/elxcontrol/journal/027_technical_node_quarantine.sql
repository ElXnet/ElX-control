-- Stage 4: irreversible operator quarantine for an uncertain technical
-- mutation. QUARANTINE is NOT APPLIED, an authorization, or a slot release.
-- No transaction updates or deletes this record through the application.
-- Operators must physically fence the node before invoking the command.
CREATE TABLE elx_technical_node_quarantines (
    node_id uuid PRIMARY KEY,
    resource_id uuid NOT NULL,
    profile_id uuid NOT NULL REFERENCES elx_technical_profiles(profile_id),
    operation_id uuid NOT NULL REFERENCES elx_technical_profile_operations(operation_id),
    store_id uuid NOT NULL,
    phase text NOT NULL CHECK (phase IN ('INSTALLING','RETIRING')),
    evidence_sha256 bytea NOT NULL CHECK (octet_length(evidence_sha256)=32),
    operator_ref text NOT NULL CHECK (length(operator_ref) BETWEEN 3 AND 128),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (profile_id, operation_id),
    FOREIGN KEY (node_id,resource_id)
        REFERENCES elx_operation_targets(node_id,resource_id)
);
CREATE INDEX elx_technical_quarantine_resource
    ON elx_technical_node_quarantines(node_id,resource_id);
