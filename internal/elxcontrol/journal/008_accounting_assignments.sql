-- Authoritative association of one ElXray subscription with one pre-provisioned
-- accounting stream and the pinned identity for that core boot.
-- Control provisions this mapping; the node must not choose a period, stream or
-- subscription from untrusted client input.
CREATE TABLE elx_accounting_assignments (
    node_id uuid NOT NULL,
    executor_id uuid NOT NULL,
    incarnation uuid NOT NULL,
    accounting_id uuid NOT NULL,
    generation bigint NOT NULL,
    period_id uuid NOT NULL,
    subscription_id text NOT NULL CHECK (
        length(subscription_id) BETWEEN 1 AND 1024
        AND subscription_id = btrim(subscription_id)
    ),
    PRIMARY KEY (node_id,executor_id,incarnation,accounting_id,generation,period_id),
    FOREIGN KEY (node_id,executor_id,incarnation,accounting_id,generation,period_id)
        REFERENCES elx_accounting_streams
        (node_id,executor_id,incarnation,accounting_id,generation,period_id),
    FOREIGN KEY (node_id,incarnation)
        REFERENCES elx_core_identities(node_id,incarnation)
);
