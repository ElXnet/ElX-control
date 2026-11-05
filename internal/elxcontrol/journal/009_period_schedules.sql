-- Timezone and cadence belong to a durable schedule. A period keeps the
-- same counter assignment at rollover and starts at the previous period end.
CREATE TABLE elx_period_schedules (
    id uuid PRIMARY KEY,
    entitlement_id uuid NOT NULL REFERENCES elx_entitlements(id),
    cadence text NOT NULL CHECK (cadence IN ('day','week','month')),
    timezone_name text NOT NULL CHECK (length(timezone_name) BETWEEN 1 AND 128),
    current_period_id uuid NOT NULL REFERENCES elx_usage_periods(id),
    enabled boolean NOT NULL DEFAULT true
);

ALTER TABLE elx_usage_periods
    ADD COLUMN schedule_id uuid REFERENCES elx_period_schedules(id);

CREATE UNIQUE INDEX elx_period_schedule_start
    ON elx_usage_periods(schedule_id,starts_at) WHERE schedule_id IS NOT NULL;

-- Once a rollover commits, delayed old-period samples must not be charged to
-- both periods. A new row inherits the old cumulative sequence and totals.
ALTER TABLE elx_accounting_streams
    ADD COLUMN closed boolean NOT NULL DEFAULT false;
