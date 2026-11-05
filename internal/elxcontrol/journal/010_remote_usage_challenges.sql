-- Server-generated signed-usage challenges. A challenge is scoped to one
-- mTLS-authenticated node, one pinned ElXray incarnation, one accounting
-- assignment, and the schedule's current period. The node cannot supply a
-- different period or unprovisioned subscription in the response.
CREATE TABLE elx_remote_usage_challenges (
    node_id uuid NOT NULL,
    executor_id uuid NOT NULL,
    incarnation uuid NOT NULL,
    accounting_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    schedule_id uuid NOT NULL REFERENCES elx_period_schedules(id),
    period_id uuid NOT NULL,
    nonce char(32) NOT NULL CHECK (nonce ~ '^[0-9a-f]{32}$'),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (node_id, executor_id, incarnation, accounting_id, generation, schedule_id),
    FOREIGN KEY (node_id, executor_id, incarnation, accounting_id, generation, period_id)
        REFERENCES elx_accounting_assignments
            (node_id, executor_id, incarnation, accounting_id, generation, period_id)
);
CREATE INDEX elx_remote_challenges_expiry ON elx_remote_usage_challenges(expires_at);
