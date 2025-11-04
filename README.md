# Auth Development Tools

## Auth Server

**NOT FIT FOR PRODUCTION USE**

This is a simple OAuth2 authorization server partially implementing the following standard:

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
  - Authorization Code
  - Implicit
  - Resource Owner Password Credentials
  - Client Credentials
  - Refresh Token
- [OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
- [Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)

It is possible to use PostgreSQL, Oracle Database or LDAP as stores.

### Install

```shell
go install github.com/cwkr/authd/cmd/auth-server@latest
```

### Settings

Auth Server will search for `auth-server.jsonc` or `auth-server.json` in the current working directory
and will load it's content when found.

```jsonc
{
  "issuer": "http://localhost:6080/",
  "port": 6080,
  // load signing key from file 
  "key": "@mykey.pem",
  // extra public keys to include in jwks
  "additional_keys": [
    "@othe.key",
    "http://localhost:7654/jwks.json"
  ],
  // available scopes
  "extra_scope": "profile email offline_access",
  "access_token_ttl": 3600,
  "refresh_token_ttl": 28800,
  "session_secret": "AwBVrwW0boviWc3L12PplWTEgO4B4dxi",
  "session_name": "_auth",
  "session_ttl": 28800,
  "keys_ttl": 900,
  // disable REST API completely 
  "disable_api": false,
  // require JWT to query people details with REST API
  "people_api_require_authn": true,
  "users": {
    "user": {
      "given_name": "First Name",
      "family_name": "Last Name",
      "groups": [
        "admin"
      ],
      "password_hash": "$2a$12$yos0Nv/lfhjKjJ7CSmkCteSJRmzkirYwGFlBqeY4ss3o3nFSb5WDy"
    }
  },
  "clients": {
    "app": {
      "redirect_uri_pattern": "https?:\\/\\/localhost(:\\d+)?\\/"
    }
  }
}
```

#### Custom token claims

| placeholder variable          |
|-------------------------------|
| `$birthdate`                  |
| `$client_id`                  |
| `$department`                 |
| `$email`                      |
| `$family_name`                |
| `$given_name`                 |
| `$groups`                     |
| `$groups_space_delimited`     |
| `$groups_comma_delimited`     |
| `$groups_semicolon_delimited` |
| `$locality`                   |
| `$phone_number`               |
| `$postal_code`                |
| `$roles`                      |
| `$roles_space_delimited`      |
| `$roles_comma_delimited`      |
| `$roles_semicolon_delimited`  |
| `$room_number`                |
| `$street_address`             |
| `$user_id`                    |

```jsonc
{
  // define custom access token claims
  "access_token_extra_claims": {
    "prn": "$user_id",
    "email": "$email",
    "givenName": "$given_name",
    "groups": "$groups_semicolon_delimited",
    "sn": "$family_name",
    "user_id": "$user_id"
  },
  // define custom id token claims
  "id_token_extra_claims": {
    "groups": "$groups"
  },
}
```

#### PostgreSQL as people store

Client column names are mapped by name:

| column name      |
|------------------|
| `user_id`        |
| `password_hash`  |
| `given_name`     |
| `family_name`    |
| `email`          |
| `birthdate`      |
| `department`     |
| `phone_number`   |
| `room_number`    |
| `street_address` |
| `locality`       |
| `postal_code`    |

```jsonc
{
  "people_store": {
    "uri": "postgresql://authserver:trustno1@localhost:5432/dev?sslmode=disable",
    "credentials_query": "SELECT user_id, password_hash FROM people WHERE lower(user_id) = lower($1)",
    "groups_query": "SELECT UNNEST(groups) FROM people WHERE lower(user_id) = lower($1)",
    "details_query": "SELECT given_name, family_name, email, TO_CHAR(birthdate, 'YYYY-MM-DD') birthdate, department, phone_number, room_number, street_address, locality, postal_code FROM people WHERE lower(user_id) = lower($1)",
    "update": "UPDATE people SET given_name = $2, family_name = $3, email = $4, department = $5, birthdate = TO_DATE($6, 'YYYY-MM-DD'), phone_number = $7, room_number = $8, street_address = $9, locality = $10, postal_code = $11, last_modified = now() WHERE lower(user_id) = lower($1)",
    "set_password": "UPDATE people SET password_hash = $2, last_modified = now() WHERE lower(user_id) = lower($1)"
  }
}
```

#### PostgreSQL as client store

Client column names are mapped by name:

| column name                       |
|-----------------------------------|
| `client_id`                       |
| `redirect_uri_pattern`            |
| `secret_hash`                     |
| `session_name`                    |
| `disable_implicit`                |
| `enable_refresh_token_rotation`   |

```jsonc
{
  "client_store": {
    "uri": "postgresql://authserver:trustno1@localhost:5432/dev?sslmode=disable",
    "query": "SELECT redirect_uri_pattern, secret_hash, session_name, disable_implicit, enable_refresh_token_rotation FROM clients WHERE lower(client_id) = lower($1)",
    "query_session_names": "SELECT client_id, session_name FROM clients"
  }
}
```

#### Oracle Database as people store

Client column names are mapped case-sensitive by name:

| column name      |
|------------------|
| `user_id`        |
| `password_hash`  |
| `given_name`     |
| `family_name`    |
| `email`          |
| `birthdate`      |
| `department`     |
| `phone_number`   |
| `room_number`    |
| `street_address` |
| `locality`       |
| `postal_code`    |

```jsonc
{
  "people_store": {
    "uri": "oracle://authserver:trustno1@localhost:1521/orcl?charset=UTF8",
    "credentials_query": "SELECT user_id, password_hash FROM people WHERE lower(user_id) = lower(:1)",
    "groups_query": "SELECT grp.group_id FROM people_groups pg LEFT JOIN groups grp ON pg.group_id = grp.group_id WHERE lower(pg.user_id) = lower(:1)",
    "details_query": "SELECT given_name \"given_name\", family_name \"family_name\", email \"email\", TO_CHAR(birthdate, 'YYYY-MM-DD') \"birthdate\", department \"department\", phone_number \"phone_number\", street_address \"street_address\", locality \"locality\", postal_code \"postal_code\" FROM people WHERE lower(user_id) = lower(:1)",
    "update": "UPDATE people SET given_name = :2, family_name = :3, email = :4, department = :5, birthdate = TO_DATE(:6, 'YYYY-MM-DD'), phone_number = :7, room_number = :8, street_address = :9, locality = :10, postal_code = :11, last_modified = now() WHERE lower(user_id) = lower(:1)",
    "set_password": "UPDATE people SET password_hash = :2, last_modified = now() WHERE lower(user_id) = lower(:1)"
  }
}
```

#### Oracle Database as client store

Client column names are mapped case-sensitive by name:

| column name                       |
|-----------------------------------|
| `client_id`                       |
| `redirect_uri_pattern`            |
| `secret_hash`                     |
| `session_name`                    |
| `disable_implicit`                |
| `enable_refresh_token_rotation`   |

```jsonc
{
  "client_store": {
    "uri": "oracle://authserver:trustno1@localhost:1521/orcl?charset=UTF8",
    "query": "SELECT redirect_uri_pattern \"redirect_uri_pattern\", secret_hash \"secret_hash\", session_name \"session_name\", disable_implicit \"disable_implicit\", enable_refresh_token_rotation \"enable_refresh_token_rotation\" FROM clients WHERE lower(client_id) = lower(:1)",
    "query_session_names": "SELECT client_id \"client_id\", session_name \"session_name\" FROM clients"
  }
}
```

#### Oracle Internet Directory (LDAP) as people store

```jsonc
{
  "people_store": {
    // use "+" for space in username
    "uri": "ldaps://cn=access_user,cn=Users,dc=example,dc=org:trustno1@oid.example.org:3070/dc=example,dc=org?read-only=true",
    "credentials_query": "(&(objectClass=person)(uid=%s))",
    "groups_query": "(&(objectClass=groupOfUniqueNames)(uniquemember=%s))",
    "details_query": "(&(objectClass=person)(uid=%s))",
    "parameters": {
      "user_id_attribute": "uid",
      // group ids will be full distinguished names like "cn=admin,cn=groups,dc=example,dc=org"
      // group ids would be only group name when group_id_attribute is "dc", but group names are not unique in OID
      "group_id_attribute": "dn",      
      "department_attribute": "departmentnumber",
      "email_attribute": "mail",
      "family_name_attribute": "sn",
      "given_name_attribute": "givenname",
      "phone_number_attribute": "telephonenumber",
      "room_number_attribute": "roomnumber",
      "street_address_attribute": "street",
      "locality_attribute": "l",
      "postal_code_attribute": "postalcode"
    }
  }
}
```

#### Map user roles

```jsonc
{
  "roles": {
    // map all groups as roles
    "*": {
      "by_group": ["*"]
    },
    // map role by any group
    "all_users": {
      "by_group": ["*"]
    },
    "admin": {
      // map role to specific user ids...
      "by_user_id": [
        "user1",
        "user2"
      ],
      // ...or group name as LDAP distinguished name
      "by_group_dn": [
        "cn=admin,cn=groups,dc=example,dc=org"
      ]
    }
  }
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
