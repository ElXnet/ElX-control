-- One permanently reserved signed RETIRE per technical UUID. Retiring may
-- be requested after entitlement expiry: revocation must never require a paid
-- lease and must not release a device/owner slot without a separate fence.
CREATE UNIQUE INDEX elx_one_technical_retire_per_profile
    ON elx_technical_profile_operations(profile_id) WHERE action='retire';
