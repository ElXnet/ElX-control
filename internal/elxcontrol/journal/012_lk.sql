-- Local account identity is separate from the administrator identity of 3X-UI.
-- Email/password registration is invite-only; an entitlement has one owner.
CREATE TABLE elx_lk_accounts (
    id uuid PRIMARY KEY,
    email text NOT NULL UNIQUE CHECK (email=lower(email) AND length(email) BETWEEN 3 AND 254),
    password_salt bytea NOT NULL CHECK (octet_length(password_salt)=16),
    password_hash bytea NOT NULL CHECK (octet_length(password_hash)=32),
    password_iterations integer NOT NULL CHECK (password_iterations BETWEEN 600000 AND 2000000),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE elx_lk_ownership (
    entitlement_id uuid PRIMARY KEY REFERENCES elx_entitlements(id),
    account_id uuid NOT NULL REFERENCES elx_lk_accounts(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX elx_lk_ownership_account ON elx_lk_ownership(account_id);
CREATE TABLE elx_lk_invites (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash)=32),
    entitlement_id uuid NOT NULL REFERENCES elx_entitlements(id),
    expires_at timestamptz NOT NULL,
    redeemed_by uuid REFERENCES elx_lk_accounts(id),
    redeemed_at timestamptz,
    CHECK ((redeemed_by IS NULL) = (redeemed_at IS NULL))
);
CREATE INDEX elx_lk_invites_entitlement ON elx_lk_invites(entitlement_id);
CREATE TABLE elx_lk_sessions (
    token_hash bytea PRIMARY KEY CHECK(octet_length(token_hash)=32),
    account_id uuid NOT NULL REFERENCES elx_lk_accounts(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX elx_lk_sessions_active ON elx_lk_sessions(account_id,expires_at)
WHERE revoked_at IS NULL;
CREATE TABLE elx_lk_login_attempts (
    email_hash bytea PRIMARY KEY CHECK(octet_length(email_hash)=32),
    failures integer NOT NULL DEFAULT 0 CHECK(failures>=0),
    window_start timestamptz NOT NULL DEFAULT clock_timestamp(),
    blocked_until timestamptz
);
