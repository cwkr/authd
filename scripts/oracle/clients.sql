CREATE TABLE clients (
    client_id VARCHAR2(255 CHAR) NOT NULL CONSTRAINT clients_pk PRIMARY KEY,
    access_token_lifetime NUMBER(15, 0) DEFAULT 0 NOT NULL,
    audience VARCHAR2(1023 CHAR),
    auth_code_lifetime NUMBER(15, 0) DEFAULT 0 NOT NULL,
    disable_implicit NUMBER(1, 0) DEFAULT 0 NOT NULL,
    enable_refresh_token_rotation NUMBER(1, 0) DEFAULT 0 NOT NULL,
    id_token_lifetime NUMBER(15, 0) DEFAULT 0 NOT NULL,
    redirect_uris VARCHAR2(1023 CHAR),
    refresh_token_lifetime NUMBER(15, 0) DEFAULT 0 NOT NULL,
    require_2fa NUMBER(1, 0) DEFAULT 0 NOT NULL,
    signing_algorithm VARCHAR2(255 CHAR),
    secret_hash VARCHAR2(255 CHAR),
    created TIMESTAMP(3) WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP(3) NOT NULL,
    last_modified TIMESTAMP(3) WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP(3) NOT NULL
);
