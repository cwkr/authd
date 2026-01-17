CREATE TABLE people (
    user_id VARCHAR NOT NULL PRIMARY KEY,
    password_hash VARCHAR NOT NULL,
    groups VARCHAR ARRAY,
    given_name VARCHAR,
    family_name VARCHAR,
    email VARCHAR,
    birthdate DATE,
    department VARCHAR,
    phone_number VARCHAR,
    room_number VARCHAR,
    street_address VARCHAR,
    locality VARCHAR,
    postal_code VARCHAR,
    otpauth_uri VARCHAR,
    created TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_modified TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
