CREATE TABLE elx_rate_budgets (
    entitlement_id uuid PRIMARY KEY REFERENCES elx_entitlements(id),
    up_limit bigint NOT NULL CHECK (up_limit BETWEEN 0 AND 1099511627776),
    down_limit bigint NOT NULL CHECK (down_limit BETWEEN 0 AND 1099511627776)
);

CREATE TABLE elx_rate_grants (
    entitlement_id uuid NOT NULL REFERENCES elx_rate_budgets(entitlement_id),
    node_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    committed_up bigint NOT NULL CHECK (committed_up BETWEEN 0 AND 1099511627776),
    committed_down bigint NOT NULL CHECK (committed_down BETWEEN 0 AND 1099511627776),
    epoch bigint NOT NULL CHECK (epoch > 0),
    barrier_public_key bytea NOT NULL CHECK (octet_length(barrier_public_key) = 32),
    PRIMARY KEY (node_id, resource_id),
    FOREIGN KEY (node_id, resource_id) REFERENCES elx_operation_targets(node_id, resource_id)
);

CREATE TABLE elx_rate_moves (
    node_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    desired_up bigint NOT NULL CHECK (desired_up BETWEEN 0 AND 1099511627776),
    desired_down bigint NOT NULL CHECK (desired_down BETWEEN 0 AND 1099511627776),
    finalized boolean NOT NULL DEFAULT false,
    PRIMARY KEY (node_id, resource_id, operation_id),
    FOREIGN KEY (node_id, resource_id) REFERENCES elx_rate_grants(node_id, resource_id),
    FOREIGN KEY (node_id, resource_id, operation_id)
        REFERENCES elx_operations(node_id, resource_id, operation_id)
);

CREATE UNIQUE INDEX elx_one_rate_move ON elx_rate_moves(node_id, resource_id) WHERE NOT finalized;
CREATE INDEX elx_rate_grants_entitlement ON elx_rate_grants(entitlement_id);
