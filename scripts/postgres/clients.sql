CREATE TABLE clients (
    client_id VARCHAR NOT NULL PRIMARY KEY,
    redirect_uri_pattern VARCHAR,
    secret_hash VARCHAR,
    preset VARCHAR,
    disable_implicit BOOLEAN NOT NULL DEFAULT FALSE,
    enable_refresh_token_rotation BOOLEAN NOT NULL DEFAULT FALSE,
    created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_modified TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
