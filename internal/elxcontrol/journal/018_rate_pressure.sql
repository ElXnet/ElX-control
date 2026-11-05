-- Persisted, independently authenticated rate-pressure high watermarks.
-- A missing sample is frozen/unknown, never treated as idle demand.
-- A new core incarnation requires explicit Control reconciliation; no
-- automatic ON CONFLICT incarnation swap is permitted.
CREATE TABLE elx_rate_pressure_samples (
    node_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    incarnation uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    sampled_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    core_revision bigint NOT NULL CHECK (core_revision > 0),
    policy_up bigint NOT NULL CHECK (policy_up BETWEEN 0 AND 1099511627776),
    policy_down bigint NOT NULL CHECK (policy_down BETWEEN 0 AND 1099511627776),
    up_bytes bigint NOT NULL CHECK (up_bytes >= 0),
    down_bytes bigint NOT NULL CHECK (down_bytes >= 0),
    up_blocked_calls bigint NOT NULL CHECK (up_blocked_calls >= 0),
    down_blocked_calls bigint NOT NULL CHECK (down_blocked_calls >= 0),
    up_blocked_nanos bigint NOT NULL CHECK (up_blocked_nanos >= 0),
    down_blocked_nanos bigint NOT NULL CHECK (down_blocked_nanos >= 0),
    up_waiters bigint NOT NULL CHECK (up_waiters BETWEEN 0 AND 1000000),
    down_waiters bigint NOT NULL CHECK (down_waiters BETWEEN 0 AND 1000000),
    PRIMARY KEY (node_id,resource_id),
    FOREIGN KEY (node_id,resource_id)
        REFERENCES elx_rate_grants(node_id,resource_id),
    FOREIGN KEY (node_id,incarnation)
        REFERENCES elx_core_identities(node_id,incarnation)
);
CREATE INDEX elx_rate_pressure_samples_received
    ON elx_rate_pressure_samples(received_at);
