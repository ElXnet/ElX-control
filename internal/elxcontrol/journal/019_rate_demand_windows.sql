-- Preserve one predecessor from the last two accepted, pinned, signed
-- per-node/resource pressure records. An old incarnation is deleted only
-- after verified core takeover; it cannot be spliced into a new window.
ALTER TABLE elx_rate_pressure_samples
    ADD COLUMN previous_sequence bigint CHECK (previous_sequence > 0),
    ADD COLUMN previous_sampled_at timestamptz,
    ADD COLUMN previous_core_revision bigint CHECK (previous_core_revision > 0),
    ADD COLUMN previous_policy_up bigint CHECK (previous_policy_up BETWEEN 0 AND 1099511627776),
    ADD COLUMN previous_policy_down bigint CHECK (previous_policy_down BETWEEN 0 AND 1099511627776),
    ADD COLUMN previous_up_bytes bigint CHECK (previous_up_bytes >= 0),
    ADD COLUMN previous_down_bytes bigint CHECK (previous_down_bytes >= 0),
    ADD COLUMN previous_up_blocked_calls bigint CHECK (previous_up_blocked_calls >= 0),
    ADD COLUMN previous_down_blocked_calls bigint CHECK (previous_down_blocked_calls >= 0),
    ADD COLUMN previous_up_blocked_nanos bigint CHECK (previous_up_blocked_nanos >= 0),
    ADD COLUMN previous_down_blocked_nanos bigint CHECK (previous_down_blocked_nanos >= 0),
    ADD CONSTRAINT elx_previous_pressure_window
        CHECK (previous_sequence IS NULL OR
            (previous_sampled_at IS NOT NULL AND previous_core_revision IS NOT NULL
             AND previous_policy_up IS NOT NULL AND previous_policy_down IS NOT NULL
             AND previous_up_bytes IS NOT NULL AND previous_down_bytes IS NOT NULL
             AND previous_up_blocked_calls IS NOT NULL AND previous_down_blocked_calls IS NOT NULL
             AND previous_up_blocked_nanos IS NOT NULL AND previous_down_blocked_nanos IS NOT NULL
             AND previous_sequence < sequence AND previous_sampled_at < sampled_at));
