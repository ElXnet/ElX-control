CREATE TABLE elx_operation_targets (
    node_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    PRIMARY KEY (node_id, resource_id)
);

CREATE TABLE elx_operations (
    node_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 262144),
    payload_hash bytea NOT NULL CHECK (octet_length(payload_hash) = 32),
    applied_at timestamptz,
    PRIMARY KEY (node_id, resource_id, operation_id),
    UNIQUE (node_id, resource_id, revision),
    FOREIGN KEY (node_id, resource_id)
        REFERENCES elx_operation_targets (node_id, resource_id)
);

CREATE UNIQUE INDEX elx_one_pending_operation
    ON elx_operations (node_id, resource_id) WHERE applied_at IS NULL;
