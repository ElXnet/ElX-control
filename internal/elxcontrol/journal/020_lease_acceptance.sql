-- Independently authenticated proof that the pinned ElXray core actually
-- installed a short-lived Control-signed lease in its rate limiter.
-- A lease is tied to the *same* fresh challenge and pressure sample, not
-- merely to an agent ACK or a ticket issued by the Control server.
CREATE TABLE elx_rate_lease_acceptances (
    node_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    incarnation uuid NOT NULL,
    pressure_sequence bigint NOT NULL CHECK (pressure_sequence > 0),
    lease_sequence bigint NOT NULL CHECK (lease_sequence > 0),
    lease_expires_at timestamptz NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    policy_up bigint NOT NULL CHECK (policy_up > 0),
    policy_down bigint NOT NULL CHECK (policy_down > 0),
    ceiling_up bigint NOT NULL CHECK (ceiling_up > 0),
    ceiling_down bigint NOT NULL CHECK (ceiling_down > 0),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (node_id,resource_id),
    FOREIGN KEY (node_id,resource_id) REFERENCES elx_rate_grants(node_id,resource_id),
    FOREIGN KEY (node_id,incarnation) REFERENCES elx_core_identities(node_id,incarnation),
    CHECK (policy_up <= ceiling_up AND policy_down <= ceiling_down)
);
CREATE INDEX elx_lease_acceptance_expires
    ON elx_rate_lease_acceptances(lease_expires_at);
