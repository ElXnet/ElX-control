-- The enrolment process MUST pin the public key from an authenticated core,
-- never from an untrusted fence receipt or a client-submitted payload.
-- An unavailable/revoked core retains occupied slots until safe recovery.
CREATE TABLE elx_core_identities (
    node_id uuid NOT NULL,
    incarnation uuid NOT NULL,
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    revoked boolean NOT NULL DEFAULT false,
    registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (node_id, incarnation)
);
