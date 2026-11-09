-- Independent monotonic Control witness for a core's durable store.
-- NEVER reconstruct this table from a node snapshot or agent-provided state.
-- Bootstrap requires an offline Control-approved baseline and attestation.
CREATE TABLE elx_core_store_witnesses (
    node_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    executor_id uuid NOT NULL,
    store_id uuid NOT NULL,
    authority_generation bigint NOT NULL CHECK (authority_generation > 0),
    core_revision bigint NOT NULL CHECK (core_revision > 0),
    core_incarnation uuid,
    last_operation_id uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (node_id, resource_id),
    FOREIGN KEY (node_id, resource_id)
        REFERENCES elx_operation_targets(node_id, resource_id),
    CONSTRAINT elx_witness_applied_pair CHECK (
        (core_incarnation IS NULL AND last_operation_id IS NULL)
        OR (core_incarnation IS NOT NULL AND last_operation_id IS NOT NULL)
    )
);

CREATE UNIQUE INDEX elx_witness_single_store_per_executor
    ON elx_core_store_witnesses(node_id, executor_id, store_id);
