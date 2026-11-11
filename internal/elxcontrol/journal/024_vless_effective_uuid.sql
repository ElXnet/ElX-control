-- Follow-up migration: VLESS authenticates by a normalized UUID which
-- ignores bytes 6 and 7. Prevent two visually different profile UUIDs
-- referring to the same effective account on one executor, even if retired.
-- This is deliberately a NEW checksummed migration, not an edit to 023.
CREATE UNIQUE INDEX elx_vless_effective_id_per_executor
    ON elx_technical_profiles(node_id,executor_id,
       (set_byte(set_byte(uuid_send(profile_id),6,0),7,0)));
