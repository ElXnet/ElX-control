-- Stage-4 INSTALL is a distinct durable operation with a signed flow.
-- PREPARE never implies a live VLESS user or owner/device admission.
ALTER TABLE elx_technical_profile_operations
    ADD COLUMN flow text NOT NULL DEFAULT ''
    CHECK (flow IN ('', 'xtls-rprx-vision'));

-- Reusing a printed UUID under a new operation must never re-enable it.
CREATE UNIQUE INDEX elx_one_technical_install_per_profile
    ON elx_technical_profile_operations(profile_id) WHERE action='install';
