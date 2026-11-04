-- Payment verification runs in a SEPARATE service. Control stores orders,
-- verified receipts, entitlements, and a durable disabled-profile outbox.
-- No card/phone/bank credentials or unverified client events are accepted.
CREATE TABLE elx_checkout_orders (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    account_id uuid NOT NULL REFERENCES elx_lk_accounts(id),
    entitlement_id uuid REFERENCES elx_entitlements(id),
    addon_devices smallint NOT NULL CHECK (addon_devices BETWEEN 0 AND 2),
    amount_minor integer NOT NULL CHECK (amount_minor BETWEEN 50000 AND 90000),
    currency char(3) NOT NULL CHECK (currency='RUB'),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','paid')),
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL CHECK (expires_at>issued_at),
    fulfilled_entitlement uuid REFERENCES elx_entitlements(id),
    UNIQUE (account_id,request_id)
);
CREATE INDEX elx_checkout_order_account ON elx_checkout_orders(account_id,issued_at DESC);

CREATE TABLE elx_payment_receipts (
    event_id uuid PRIMARY KEY,
    provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
    provider_payment_id text NOT NULL CHECK (length(provider_payment_id) BETWEEN 1 AND 128),
    order_id uuid NOT NULL UNIQUE REFERENCES elx_checkout_orders(id),
    amount_minor integer NOT NULL CHECK (amount_minor>0),
    currency char(3) NOT NULL CHECK (currency='RUB'),
    confirmed_at timestamptz NOT NULL,
    payload_hash bytea NOT NULL CHECK (octet_length(payload_hash)=32),
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (provider,provider_payment_id)
);

CREATE TABLE elx_paid_profiles (
    id uuid PRIMARY KEY,
    entitlement_id uuid NOT NULL UNIQUE REFERENCES elx_entitlements(id),
    vless_id uuid NOT NULL UNIQUE,
    subscription_id text NOT NULL UNIQUE CHECK (length(subscription_id) BETWEEN 16 AND 128),
    client_email text NOT NULL UNIQUE CHECK (length(client_email) BETWEEN 8 AND 128),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','staged','active','suspended')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- At-least-once transport. The panel MUST create the user disabled, with
-- credentials supplied by Control; only then does Control mark staged.
-- Crash after panel write is safe: replay uses identical ID/SubID/Email.
CREATE TABLE elx_profile_provision_jobs (
    id uuid PRIMARY KEY,
    profile_id uuid NOT NULL UNIQUE REFERENCES elx_paid_profiles(id),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','leased','staged','enable_pending','enable_leased','active')),
    lease_owner uuid,
    lease_until timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts>=0),
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((lease_owner IS NULL)=(lease_until IS NULL))
);

-- Renewals update the panel's expiry metadata without changing credentials or
-- bypassing Control's active entitlement / mandatory lease authorization.
-- They are separate from one-time profile creation so a paid renewal cannot
-- be lost while the creation job is in flight.
CREATE TABLE elx_profile_expiry_jobs (
    id uuid PRIMARY KEY,
    order_id uuid NOT NULL UNIQUE REFERENCES elx_checkout_orders(id),
    profile_id uuid NOT NULL REFERENCES elx_paid_profiles(id),
    valid_until timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','leased','done')),
    lease_owner uuid,
    lease_until timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts>=0),
    completed_at timestamptz,
    CHECK ((lease_owner IS NULL)=(lease_until IS NULL))
);
CREATE INDEX elx_profile_expiry_pending ON elx_profile_expiry_jobs(status,valid_until);
