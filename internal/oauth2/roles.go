package oauth2

import (
	"log"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type RoleMapping struct {
	ByGroup    []string `json:"by_group,omitempty"`
	ByGroupDN  []string `json:"by_group_dn,omitempty"`
	ByUserID   []string `json:"by_user_id,omitempty"`
	ByClientID []string `json:"by_client_id,omitempty"`
}

type RoleMappings map[string]RoleMapping

func (c RoleMappings) Roles(user User) []string {
	var roles = make([]string, 0)
	if slices.Contains(c["*"].ByGroup, "*") {
		roles = append(roles, user.Groups...)
	}
	for role, mapping := range c {
		if role == "*" {
			continue
		}
		if len(mapping.ByUserID) > 0 {
			for _, userID := range mapping.ByUserID {
				if strings.EqualFold(strings.TrimSpace(userID), user.UserID) || userID == "*" {
					if !slices.Contains(roles, role) {
						roles = append(roles, role)
					}
					break
				}
			}
		}
		if len(mapping.ByGroupDN) > 0 {
			var found = false
			for _, groupDN := range mapping.ByGroupDN {
				var wantedDN *ldap.DN
				if dn, err := ldap.ParseDN(groupDN); err != nil {
					log.Print(err)
					break
				} else {
					wantedDN = dn
				}
				for _, group := range user.Groups {
					if dn, err := ldap.ParseDN(group); err != nil {
						log.Print(err)
						continue
					} else {
						if dn.EqualFold(wantedDN) {
							if !slices.Contains(roles, role) {
								roles = append(roles, role)
							}
							found = true
							break
						}
					}
				}
				if found {
					break
				}
			}
		}
		if len(mapping.ByGroup) > 0 {
			var found = false
			for _, wantedGroup := range mapping.ByGroup {
				for _, userGroup := range user.Groups {
					if strings.EqualFold(strings.TrimSpace(wantedGroup), userGroup) || wantedGroup == "*" {
						if !slices.Contains(roles, role) {
							roles = append(roles, role)
						}
						found = true
						break
					}
				}
				if found {
					break
				}
			}
		}
	}
	log.Printf("user: %s, mapped roles: %s", user.UserID, strings.Join(roles, ", "))
	return roles
}

func (c RoleMappings) ClientRoles(clientID string) []string {
	var roles = make([]string, 0)

	for role, mapping := range c {
		if role == "*" {
			continue
		}

		if len(mapping.ByClientID) > 0 {
			for _, cid := range mapping.ByClientID {
				if strings.EqualFold(strings.TrimSpace(cid), strings.TrimSpace(clientID)) || cid == "*" {
					if !slices.Contains(roles, role) {
						roles = append(roles, role)
					}
					break
				}
			}
		}
	}

	log.Printf("client: %s, mapped roles: %s", clientID, strings.Join(roles, ", "))
	return roles
}
