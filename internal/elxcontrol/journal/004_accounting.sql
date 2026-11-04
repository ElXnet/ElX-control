CREATE TABLE elx_usage_periods (
    id uuid PRIMARY KEY,
    entitlement_id uuid NOT NULL REFERENCES elx_entitlements(id),
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL CHECK (ends_at > starts_at),
    direction text NOT NULL CHECK (direction IN ('up','down','total')),
    threshold_bytes bigint NOT NULL CHECK (threshold_bytes > 0),
    reduced_up bigint NOT NULL CHECK (reduced_up > 0 AND reduced_up <= 1099511627776),
    reduced_down bigint NOT NULL CHECK (reduced_down > 0 AND reduced_down <= 1099511627776),
    up_bytes bigint NOT NULL DEFAULT 0 CHECK (up_bytes >= 0),
    down_bytes bigint NOT NULL DEFAULT 0 CHECK (down_bytes >= 0)
);

CREATE TABLE elx_accounting_streams (
    node_id uuid NOT NULL,
    executor_id uuid NOT NULL,
    incarnation uuid NOT NULL,
    accounting_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    period_id uuid NOT NULL REFERENCES elx_usage_periods(id),
    sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    up_bytes bigint NOT NULL DEFAULT 0 CHECK (up_bytes >= 0),
    down_bytes bigint NOT NULL DEFAULT 0 CHECK (down_bytes >= 0),
    PRIMARY KEY (node_id,executor_id,incarnation,accounting_id,generation,period_id)
);

CREATE TABLE elx_fup_events (
    period_id uuid PRIMARY KEY REFERENCES elx_usage_periods(id),
    crossed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    reduced_up bigint NOT NULL,
    reduced_down bigint NOT NULL
);
