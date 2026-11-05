-- Source health is based on successful authenticated new sequence commits,
-- never on an untrusted HTTP heartbeat or replayed signed evidence.
ALTER TABLE elx_accounting_streams
    ADD COLUMN last_received_at timestamptz;
