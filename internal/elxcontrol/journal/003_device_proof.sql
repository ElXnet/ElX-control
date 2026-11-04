ALTER TABLE elx_devices
    ADD COLUMN public_key bytea UNIQUE CHECK (octet_length(public_key) = 32);

CREATE TABLE elx_device_challenges (
    device_id uuid PRIMARY KEY REFERENCES elx_devices(id) ON DELETE CASCADE,
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 32),
    intent_hash bytea NOT NULL CHECK (octet_length(intent_hash) = 32),
    expires_at timestamptz NOT NULL
);
