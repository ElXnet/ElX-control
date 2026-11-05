-- An admission-proof's VLESS profile must be persisted explicitly.
-- Core drain receipts can then bind a fenced owner to one concrete profile,
-- instead of proving that an unrelated subscription or profile was stopped.
ALTER TABLE elx_session_owners ADD COLUMN profile_id uuid;
CREATE UNIQUE INDEX elx_single_active_profile
    ON elx_session_owners(profile_id)
    WHERE profile_id IS NOT NULL AND state <> 'released';
-- Existing unbound rows remain occupied. They cannot be released by a v2
-- profile fence; an operator must recover their real core state safely.
