-- Safe per-node core incarnation replacement. A policy lease expires
-- after 15 seconds; cutover has at least a 45-second drain/grace period.
-- Old signed sessions and accounting are never blindly re-associated with
-- the new core. An operator must first obtain durable signed deny+drain
-- barriers and the last signed usage baseline from the retiring core.
CREATE TABLE elx_core_rotations (
    id uuid PRIMARY KEY,
    node_id uuid NOT NULL,
    old_incarnation uuid NOT NULL,
    new_incarnation uuid NOT NULL,
    new_public_key bytea NOT NULL CHECK (octet_length(new_public_key)=32),
    state text NOT NULL DEFAULT 'quiescing'
      CHECK (state IN ('quiescing','completed')),
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    earliest_cutover timestamptz NOT NULL,
    completed_at timestamptz,
    CHECK (old_incarnation<>new_incarnation),
    FOREIGN KEY (node_id,old_incarnation)
      REFERENCES elx_core_identities(node_id,incarnation),
    UNIQUE (node_id,old_incarnation,new_incarnation)
);
CREATE UNIQUE INDEX elx_one_rotation_per_node
    ON elx_core_rotations(node_id) WHERE state='quiescing';

-- Proven signed barrier transcript must be retained; an ordinary applied
-- policy operation never substitutes for a signed rate drain.
ALTER TABLE elx_rate_moves ADD COLUMN barrier_signature bytea
    CHECK (barrier_signature IS NULL OR octet_length(barrier_signature)=64);
ALTER TABLE elx_rate_moves ADD COLUMN barrier_at timestamptz;

-- Historic associations remain available for audits, while the active-only
-- uniqueness constraints permit a NEW signed boot to use the same grant.
ALTER TABLE elx_accounting_assignments
    ADD COLUMN active boolean NOT NULL DEFAULT true;
DROP INDEX elx_one_usage_source_per_rate_grant;
CREATE UNIQUE INDEX elx_one_usage_source_per_rate_grant
    ON elx_accounting_assignments(period_id,node_id,resource_id)
    WHERE resource_id IS NOT NULL AND active;
DROP INDEX elx_one_usage_subscription_per_node_period;
CREATE UNIQUE INDEX elx_one_usage_subscription_per_node_period
    ON elx_accounting_assignments(period_id,node_id,subscription_id) WHERE active;
