-- A signed usage sample is cumulative since its core incarnation, not since
-- the FUP period began. New assignments must first capture a trusted baseline
-- without charging historic bytes. Legacy streams keep their existing watermark.
ALTER TABLE elx_accounting_streams
    ADD COLUMN primed boolean NOT NULL DEFAULT true;

-- An accounting stream is tied to an exact rate-grant target. Previously the
-- mapping had no resource identifier, so coverage across node grants was
-- impossible to verify. Existing assignments are left unbound for migration
-- by an operator (never guess a mapping from IP or subscription URL).
ALTER TABLE elx_accounting_assignments
    ADD COLUMN resource_id uuid;

ALTER TABLE elx_accounting_assignments
    ADD CONSTRAINT elx_assignment_grant_target
    FOREIGN KEY (node_id,resource_id)
    REFERENCES elx_rate_grants(node_id,resource_id);

CREATE UNIQUE INDEX elx_one_usage_source_per_rate_grant
    ON elx_accounting_assignments(period_id,node_id,resource_id)
    WHERE resource_id IS NOT NULL;

CREATE UNIQUE INDEX elx_one_usage_subscription_per_node_period
    ON elx_accounting_assignments(period_id,node_id,subscription_id);
