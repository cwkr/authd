CREATE TABLE clients (
    client_id VARCHAR NOT NULL PRIMARY KEY,
    access_token_lifetime INT NOT NULL DEFAULT 0,
    audience VARCHAR ARRAY,
    auth_code_lifetime INT NOT NULL DEFAULT 0,
    disable_implicit BOOLEAN NOT NULL DEFAULT FALSE,
    enable_refresh_token_rotation BOOLEAN NOT NULL DEFAULT FALSE,
    id_token_lifetime INT NOT NULL DEFAULT 0,
    redirect_uris VARCHAR ARRAY,
    refresh_token_lifetime INT NOT NULL DEFAULT 0,
    require_2fa BOOLEAN NOT NULL DEFAULT FALSE,
    signing_algorithm VARCHAR,
    secret_hash VARCHAR,
    created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_modified TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
