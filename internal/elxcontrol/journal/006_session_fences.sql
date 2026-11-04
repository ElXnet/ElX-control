ALTER TABLE elx_session_owners
    ADD COLUMN core_incarnation uuid,
    ADD COLUMN fence_signature bytea CHECK (octet_length(fence_signature) = 64);
