-- Stage 4: durable technical VLESS profile reservation. This table does
-- NOT authorize VPN payload. Only an independently proven owner/device
-- admission (later stages) may do that.
CREATE TABLE elx_technical_profiles (
    profile_id uuid PRIMARY KEY,
    node_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    executor_id uuid NOT NULL,
    entitlement_id uuid NOT NULL REFERENCES elx_entitlements(id),
    subscription_id text NOT NULL CHECK (length(subscription_id) BETWEEN 1 AND 1024),
    email text NOT NULL CHECK (length(email) BETWEEN 1 AND 255),
    inbound_tag text NOT NULL CHECK (length(inbound_tag) BETWEEN 1 AND 128),
    profile_generation bigint NOT NULL CHECK (profile_generation > 0),
    authority_generation bigint NOT NULL CHECK (authority_generation > 0),
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    state text NOT NULL CHECK (state IN ('prepared','installed','retiring','retired')),
    operation_id uuid NOT NULL,
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256)=32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (node_id,resource_id)
       REFERENCES elx_operation_targets(node_id,resource_id)
);
-- Identity never silently jumps between nodes or reuses an old VLESS UUID.
CREATE UNIQUE INDEX elx_live_profile_user_per_inbound
    ON elx_technical_profiles(node_id,executor_id,inbound_tag,email)
    WHERE state <> 'retired';
-- VLESS normalizes bytes 6 and 7 of the UUID during authentication.
-- Keep its *effective* key unique per core executor for all generations,
-- including retired profiles, to prohibit alias takeover after restarts.
-- uuid_send returns UUID bytes in wire order; set_byte uses zero-based offsets.
CREATE UNIQUE INDEX elx_vless_effective_id_per_executor
    ON elx_technical_profiles(node_id,executor_id,
       (set_byte(set_byte(uuid_send(profile_id),6,0),7,0)));
CREATE INDEX elx_profiles_by_entitlement
    ON elx_technical_profiles(entitlement_id,state);

CREATE TABLE elx_technical_profile_operations (
    operation_id uuid PRIMARY KEY,
    profile_id uuid NOT NULL REFERENCES elx_technical_profiles(profile_id),
    action text NOT NULL CHECK (action IN ('prepare','install','retire')),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256)=32),
    profile_generation bigint NOT NULL CHECK (profile_generation > 0),
    authority_generation bigint NOT NULL CHECK (authority_generation > 0),
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    not_before bigint NOT NULL CHECK (not_before > 0),
    not_after bigint NOT NULL CHECK (not_after > not_before AND not_after-not_before <= 60),
    state text NOT NULL CHECK (state IN ('INTENT','APPLIED')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    applied_at timestamptz,
    CONSTRAINT elx_profile_op_applied_consistency
      CHECK ((state='INTENT' AND applied_at IS NULL) OR
             (state='APPLIED' AND applied_at IS NOT NULL))
);
CREATE INDEX elx_technical_profile_pending
    ON elx_technical_profile_operations(profile_id)
    WHERE state='INTENT';
