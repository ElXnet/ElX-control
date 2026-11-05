-- A durable leader fence per purchased entitlement. Renewals preserve epoch;
-- a takeover after expiry MUST increment epoch to invalidate stale workers.
-- All scheduler rate moves validate this row FOR UPDATE under the same locked
-- entitlement budget transaction used to reserve and enqueue their grant.
CREATE TABLE elx_rate_scheduler_leaders (
    entitlement_id uuid PRIMARY KEY REFERENCES elx_entitlements(id),
    holder_id uuid NOT NULL,
    epoch bigint NOT NULL CHECK (epoch > 0),
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
