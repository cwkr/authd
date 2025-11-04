package oauth2

import (
	"os"
	"strings"
)

const (
	ClaimClientID        = "client_id"
	ClaimExpiryTime      = "exp"
	ClaimIssuer          = "iss"
	ClaimIssuedAtTime    = "iat"
	ClaimNotBeforeTime   = "nbf"
	ClaimUserID          = "user_id"
	ClaimScope           = "scope"
	ClaimSubject         = "sub"
	ClaimType            = "typ"
	ClaimAudience        = "aud"
	ClaimAccessTokenHash = "at_hash"
	ClaimNonce           = "nonce"
	ClaimTokenID         = "jti"
)

func AddExtraClaims(claims map[string]any, extraClaims map[string]string, user User, clientID string, roleMappings RoleMappings) {
	for key, tmpl := range extraClaims {
		if strings.EqualFold(strings.TrimSpace(tmpl), "$groups") {
			if len(user.Groups) > 0 {
				claims[key] = user.Groups
			}
		} else if strings.EqualFold(strings.TrimSpace(tmpl), "$roles") {
			if roles := roleMappings.Roles(user); len(roles) > 0 {
				claims[key] = roles
			}
		} else if value := strings.TrimSpace(os.Expand(tmpl, func(name string) string {
			switch strings.ToLower(name) {
			case "birthdate":
				return user.Birthdate
			case "client_id":
				return clientID
			case "department":
				return user.Department
			case "email":
				return user.Email
			case "family_name":
				return user.FamilyName
			case "given_name":
				return user.GivenName
			case "locality":
				return user.Locality
			case "phone_number":
				return user.PhoneNumber
			case "postal_code":
				return user.PostalCode
			case "groups_space_delimited":
				return strings.Join(user.Groups, " ")
			case "groups_comma_delimited":
				return strings.Join(user.Groups, ",")
			case "groups_semicolon_delimited":
				return strings.Join(user.Groups, ";")
			case "roles_space_delimited":
				return strings.Join(roleMappings.Roles(user), " ")
			case "roles_comma_delimited":
				return strings.Join(roleMappings.Roles(user), ",")
			case "roles_semicolon_delimited":
				return strings.Join(roleMappings.Roles(user), ";")
			case "room_number":
				return user.RoomNumber
			case "street_address":
				return user.StreetAddress
			case "user_id":
				return user.UserID
			}
			return ""
		})); value != "" {
			claims[key] = value
		}
	}
}

func AddProfileClaims(claims map[string]any, user User) {
	if user.Birthdate != "" {
		claims["birthdate"] = user.Birthdate
	}
	if user.GivenName != "" {
		claims["given_name"] = user.GivenName
	}
	if user.FamilyName != "" {
		claims["family_name"] = user.FamilyName
	}
}

func AddEmailClaims(claims map[string]any, user User) {
	if user.Email != "" {
		claims["email"] = user.Email
		claims["email_verified"] = true
	}
}

func AddPhoneClaims(claims map[string]any, user User) {
	if user.PhoneNumber != "" {
		claims["phone_number"] = user.PhoneNumber
		claims["phone_number_verified"] = true
	}
}

func AddAddressClaims(claims map[string]any, user User) {
	if user.StreetAddress != "" || user.Locality != "" || user.PostalCode != "" {
		claims["address"] = map[string]any{
			"street_address": user.StreetAddress,
			"locality":       user.Locality,
			"postal_code":    user.PostalCode,
		}
	}
}
