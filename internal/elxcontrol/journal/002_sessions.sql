CREATE TABLE elx_entitlements (
    id uuid PRIMARY KEY,
    active_slots integer NOT NULL CHECK (active_slots > 0),
    valid_until timestamptz NOT NULL,
    enabled boolean NOT NULL DEFAULT true
);

CREATE TABLE elx_devices (
    id uuid PRIMARY KEY,
    entitlement_id uuid NOT NULL REFERENCES elx_entitlements(id),
    key_generation bigint NOT NULL CHECK (key_generation > 0),
    revoked boolean NOT NULL DEFAULT false,
    UNIQUE (entitlement_id, id)
);

CREATE TABLE elx_session_owners (
    id uuid PRIMARY KEY,
    entitlement_id uuid NOT NULL REFERENCES elx_entitlements(id),
    device_id uuid NOT NULL,
    node_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    key_generation bigint NOT NULL CHECK (key_generation > 0),
    proof_hash bytea NOT NULL CHECK (octet_length(proof_hash) = 32),
    state text NOT NULL CHECK (state IN ('reserving','active','draining','unknown','released')),
    reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (entitlement_id, device_id) REFERENCES elx_devices(entitlement_id, id),
    UNIQUE (device_id, generation),
    UNIQUE (entitlement_id, operation_id)
);

CREATE UNIQUE INDEX elx_single_session_owner ON elx_session_owners(device_id)
WHERE state <> 'released';

CREATE INDEX elx_occupied_slots ON elx_session_owners(entitlement_id)
WHERE state <> 'released';
