package people

import (
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/sessions"
)

type ldapStore struct {
	inMemoryStore
	ldapURL           string
	baseDN            string
	bindUser          string
	bindPassword      string
	attributes        []string
	userIDAttr        string
	groupIDAttr       string
	birthdateAttr     string
	departmentAttr    string
	emailAttr         string
	familyNameAttr    string
	givenNameAttr     string
	phoneNumberAttr   string
	roomNumberAttr    string
	streetAddressAttr string
	localityAttr      string
	postalCodeAttr    string
	settings          *StoreSettings
	readOnly          bool
}

func NewLdapStore(sessionStore sessions.Store, users map[string]AuthenticPerson, sessionTTL int64, settings *StoreSettings) (Store, error) {
	var ldapURL, baseDN, bindUsername, bindPassword string
	var readOnly bool
	if uri, err := url.Parse(settings.URI); err == nil {
		if uri.User != nil {
			bindUsername = strings.ReplaceAll(uri.User.Username(), "+", " ")
			bindPassword, _ = uri.User.Password()
			for key, value := range uri.Query() {
				switch strings.ToLower(key) {
				case "readonly", "read-only", "read_only":
					readOnly, err = strconv.ParseBool(value[0])
					if err != nil {
						return nil, err
					}
				}
			}
		} else {
			readOnly = true
		}
		baseDN = strings.Trim(uri.Path, " \t\r\n/")
		ldapURL = fmt.Sprintf("%s://%s", uri.Scheme, uri.Host)
	} else {
		return nil, err
	}

	var attributes []string
	for name, value := range settings.Parameters {
		if strings.HasSuffix(name, "_attribute") && !strings.HasSuffix(name, "_id_attribute") && value != "" {
			attributes = append(attributes, value)
		}
	}

	return &ldapStore{
		inMemoryStore: inMemoryStore{
			sessionStore: sessionStore,
			users:        users,
			sessionTTL:   sessionTTL,
		},
		ldapURL:           ldapURL,
		baseDN:            baseDN,
		bindUser:          bindUsername,
		bindPassword:      bindPassword,
		attributes:        attributes,
		userIDAttr:        settings.Parameters["user_id_attribute"],
		groupIDAttr:       settings.Parameters["group_id_attribute"],
		birthdateAttr:     settings.Parameters["birthdate_attribute"],
		departmentAttr:    settings.Parameters["department_attribute"],
		emailAttr:         settings.Parameters["email_attribute"],
		familyNameAttr:    settings.Parameters["family_name_attribute"],
		givenNameAttr:     settings.Parameters["given_name_attribute"],
		phoneNumberAttr:   settings.Parameters["phone_number_attribute"],
		roomNumberAttr:    settings.Parameters["room_number_attribute"],
		streetAddressAttr: settings.Parameters["street_address_attribute"],
		localityAttr:      settings.Parameters["locality_attribute"],
		postalCodeAttr:    settings.Parameters["postal_code_attribute"],
		settings:          settings,
		readOnly:          readOnly,
	}, nil
}

func (p ldapStore) queryGroups(conn *ldap.Conn, userDN string) ([]string, error) {

	if p.settings.GroupsQuery == "" {
		return []string{}, nil
	}

	var groups []string

	log.Printf("LDAP: %s; # %s", p.settings.GroupsQuery, userDN)
	// (&(objectClass=groupOfUniqueNames)(uniquemember=%s))
	var ldapGroupsSearch = ldap.NewSearchRequest(
		p.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(p.settings.GroupsQuery, ldap.EscapeFilter(userDN)),
		[]string{p.groupIDAttr},
		nil,
	)
	if groupsResults, err := conn.Search(ldapGroupsSearch); err == nil {
		for _, group := range groupsResults.Entries {
			if strings.EqualFold("DN", p.groupIDAttr) {
				groups = append(groups, group.DN)
			} else {
				groups = append(groups, group.GetEqualFoldAttributeValue(p.groupIDAttr))
			}
		}
	} else {
		return nil, err
	}

	return groups, nil
}

func (p ldapStore) queryDetails(conn *ldap.Conn, userID string) (string, *Person, error) {
	var person Person
	var userDN string

	log.Printf("LDAP: %s; # %s", p.settings.DetailsQuery, userID)
	// (&(objectClass=person)(uid=%s))
	var ldapSearch = ldap.NewSearchRequest(
		p.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(p.settings.DetailsQuery, userID),
		p.attributes,
		nil,
	)
	if results, err := conn.Search(ldapSearch); err == nil {
		if len(results.Entries) == 1 {
			var entry = results.Entries[0]
			userDN = entry.DN
			if p.birthdateAttr != "" {
				person.Birthdate = entry.GetEqualFoldAttributeValue(p.birthdateAttr)
			}
			if p.departmentAttr != "" {
				person.Department = entry.GetEqualFoldAttributeValue(p.departmentAttr)
			}
			if p.emailAttr != "" {
				person.Email = entry.GetEqualFoldAttributeValue(p.emailAttr)
			}
			if p.familyNameAttr != "" {
				person.FamilyName = entry.GetEqualFoldAttributeValue(p.familyNameAttr)
			}
			if p.givenNameAttr != "" {
				person.GivenName = entry.GetEqualFoldAttributeValue(p.givenNameAttr)
			}
			if p.phoneNumberAttr != "" {
				person.PhoneNumber = entry.GetEqualFoldAttributeValue(p.phoneNumberAttr)
			}
			if p.roomNumberAttr != "" {
				person.RoomNumber = entry.GetEqualFoldAttributeValue(p.roomNumberAttr)
			}
			if p.streetAddressAttr != "" {
				person.StreetAddress = entry.GetEqualFoldAttributeValue(p.streetAddressAttr)
			}
			if p.localityAttr != "" {
				person.Locality = entry.GetEqualFoldAttributeValue(p.localityAttr)
			}
			if p.postalCodeAttr != "" {
				person.PostalCode = entry.GetEqualFoldAttributeValue(p.postalCodeAttr)
			}
		} else {
			return "", nil, ErrPersonNotFound
		}
	} else {
		return "", nil, err
	}

	return userDN, &person, nil
}

func (p ldapStore) Authenticate(userID, password string) (string, error) {
	var realUserID, found = p.inMemoryStore.Authenticate(userID, password)
	if found == nil {
		return realUserID, nil
	}

	var conn, err = ldap.DialURL(p.ldapURL)
	if err != nil {
		log.Printf("!!! ldap connection error: %v", err)
		return "", err
	}
	defer conn.Close()

	if p.bindUser != "" && p.bindPassword != "" {
		if err = conn.Bind(p.bindUser, p.bindPassword); err != nil {
			log.Printf("!!! ldap bind error: %v", err)
			return "", err
		}
	}

	// (&(objectClass=person)(uid=%s))
	log.Printf("LDAP: %s; # %s", p.settings.CredentialsQuery, userID)
	var ldapSearch = ldap.NewSearchRequest(
		p.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf(p.settings.CredentialsQuery, ldap.EscapeFilter(userID)),
		[]string{"dn", p.userIDAttr},
		nil,
	)
	var results *ldap.SearchResult
	if results, err = conn.Search(ldapSearch); err == nil {
		if len(results.Entries) == 1 {
			var entry = results.Entries[0]
			if err = conn.Bind(entry.DN, password); err == nil {
				return entry.GetEqualFoldAttributeValue(p.userIDAttr), nil
			} else {
				log.Printf("!!! authentication using ldap bind failed: %v", err)
			}
		} else {
			log.Printf("!!! Person not found: %s", userID)
		}
	} else {
		log.Printf("!!! Query for person failed: %v", err)
		return "", err
	}

	return "", ErrAuthenticationFailed
}

func (p ldapStore) Lookup(userID string) (*Person, error) {
	var person, err = p.inMemoryStore.Lookup(userID)
	if err == nil {
		return person, nil
	}

	var groups []string
	var conn *ldap.Conn
	var userDN string

	conn, err = ldap.DialURL(p.ldapURL)
	if err != nil {
		log.Printf("!!! ldap connection error: %v", err)
		return nil, err
	}
	defer conn.Close()

	if p.bindUser != "" && p.bindPassword != "" {
		if err = conn.Bind(p.bindUser, p.bindPassword); err != nil {
			log.Printf("!!! ldap bind error: %v", err)
			return nil, err
		}
	}

	if userDN, person, err = p.queryDetails(conn, userID); err != nil {
		log.Printf("!!! Query for details failed: %v", err)
		return nil, err
	}

	if groups, err = p.queryGroups(conn, userDN); err != nil {
		log.Printf("!!! Query for groups failed: %v", err)
		return nil, err
	}
	person.Groups = groups

	log.Printf("%#v", *person)
	return person, nil
}

func (p ldapStore) ReadOnly() bool {
	return p.readOnly
}

func (p ldapStore) Put(userID string, person *Person) error {
	if p.readOnly || p.bindUser == "" || p.bindPassword == "" {
		return ErrReadOnly
	}
	var err error
	var conn *ldap.Conn
	var userDN string
	var oldPerson *Person

	conn, err = ldap.DialURL(p.ldapURL)
	if err != nil {
		log.Printf("!!! ldap connection error: %v", err)
		return err
	}
	defer conn.Close()

	if err := conn.Bind(p.bindUser, p.bindPassword); err != nil {
		log.Printf("!!! ldap bind error: %v", err)
		return err
	}

	if userDN, oldPerson, err = p.queryDetails(conn, userID); err != nil {
		log.Printf("!!! Query for details failed: %v", err)
		return err
	}

	var req = ldap.NewModifyRequest(userDN, nil)

	if p.departmentAttr != "" {
		if person.Department == "" {
			if oldPerson.Department != "" {
				req.Delete(p.departmentAttr, []string{oldPerson.Department})
			}
		} else {
			if person.Department != oldPerson.Department {
				if oldPerson.Department == "" {
					req.Add(p.departmentAttr, []string{person.Department})
				} else {
					req.Replace(p.departmentAttr, []string{person.Department})
				}
			}
		}
	}

	if p.birthdateAttr != "" {
		if person.Birthdate == "" {
			if oldPerson.Birthdate != "" {
				req.Delete(p.birthdateAttr, []string{oldPerson.Birthdate})
			}
		} else {
			if person.Birthdate != oldPerson.Birthdate {
				if oldPerson.Birthdate == "" {
					req.Add(p.birthdateAttr, []string{person.Birthdate})
				} else {
					req.Replace(p.birthdateAttr, []string{person.Birthdate})
				}
			}
		}
	}

	if p.emailAttr != "" {
		if person.Email == "" {
			if oldPerson.Email != "" {
				req.Delete(p.emailAttr, []string{oldPerson.Email})
			}
		} else {
			if person.Email != oldPerson.Email {
				if oldPerson.Email == "" {
					req.Add(p.emailAttr, []string{person.Email})
				} else {
					req.Replace(p.emailAttr, []string{person.Email})
				}
			}
		}
	}

	if p.familyNameAttr != "" {
		if person.FamilyName == "" {
			if oldPerson.FamilyName != "" {
				req.Delete(p.familyNameAttr, []string{oldPerson.FamilyName})
			}
		} else {
			if person.FamilyName != oldPerson.FamilyName {
				if oldPerson.FamilyName == "" {
					req.Add(p.familyNameAttr, []string{person.FamilyName})
				} else {
					req.Replace(p.familyNameAttr, []string{person.FamilyName})
				}
			}
		}
	}

	if p.givenNameAttr != "" {
		if person.GivenName == "" {
			if oldPerson.GivenName != "" {
				req.Delete(p.givenNameAttr, []string{oldPerson.GivenName})
			}
		} else {
			if person.GivenName != oldPerson.GivenName {
				if oldPerson.GivenName == "" {
					req.Add(p.givenNameAttr, []string{person.GivenName})
				} else {
					req.Replace(p.givenNameAttr, []string{person.GivenName})
				}
			}
		}
	}

	if p.localityAttr != "" {
		if person.Locality == "" {
			if oldPerson.Locality != "" {
				req.Delete(p.localityAttr, []string{oldPerson.Locality})
			}
		} else {
			if person.Locality != oldPerson.Locality {
				if oldPerson.Locality == "" {
					req.Add(p.localityAttr, []string{person.Locality})
				} else {
					req.Replace(p.localityAttr, []string{person.Locality})
				}
			}
		}
	}

	if p.phoneNumberAttr != "" {
		if person.PhoneNumber == "" {
			if oldPerson.PhoneNumber != "" {
				req.Delete(p.phoneNumberAttr, []string{oldPerson.PhoneNumber})
			}
		} else {
			if person.PhoneNumber != oldPerson.PhoneNumber {
				if oldPerson.PhoneNumber == "" {
					req.Add(p.phoneNumberAttr, []string{person.PhoneNumber})
				} else {
					req.Replace(p.phoneNumberAttr, []string{person.PhoneNumber})
				}
			}
		}
	}

	if p.postalCodeAttr != "" {
		if person.PostalCode == "" {
			if oldPerson.PostalCode != "" {
				req.Delete(p.postalCodeAttr, []string{oldPerson.PostalCode})
			}
		} else {
			if person.PostalCode != oldPerson.PostalCode {
				if oldPerson.PostalCode == "" {
					req.Add(p.postalCodeAttr, []string{person.PostalCode})
				} else {
					req.Replace(p.postalCodeAttr, []string{person.PostalCode})
				}
			}
		}
	}

	if p.roomNumberAttr != "" {
		if person.RoomNumber == "" {
			if oldPerson.RoomNumber != "" {
				req.Delete(p.roomNumberAttr, []string{oldPerson.RoomNumber})
			}
		} else {
			if person.RoomNumber != oldPerson.RoomNumber {
				if oldPerson.RoomNumber == "" {
					req.Add(p.roomNumberAttr, []string{person.RoomNumber})
				} else {
					req.Replace(p.roomNumberAttr, []string{person.RoomNumber})
				}
			}
		}
	}

	if p.streetAddressAttr != "" {
		if person.StreetAddress == "" {
			if oldPerson.StreetAddress != "" {
				req.Delete(p.streetAddressAttr, []string{oldPerson.StreetAddress})
			}
		} else {
			if person.StreetAddress != oldPerson.StreetAddress {
				if oldPerson.StreetAddress == "" {
					req.Add(p.streetAddressAttr, []string{person.StreetAddress})
				} else {
					req.Replace(p.streetAddressAttr, []string{person.StreetAddress})
				}
			}
		}
	}
	var changedAttributes []string
	for _, change := range req.Changes {
		changedAttributes = append(changedAttributes, change.Modification.Type)
	}
	if len(changedAttributes) > 0 {
		log.Printf("LDAP: modify %s attributes: %s", userDN, strings.Join(changedAttributes, ", "))
		if err := conn.Modify(req); err != nil {
			log.Printf("!!! ldap modify failed: %v", err)
			return err
		}
	} else {
		log.Printf("LDAP: no attributes modified of %s", userDN)
	}

	return nil
}

func (p ldapStore) ChangePassword(userID, password string) error {
	if p.readOnly || p.bindUser == "" || p.bindPassword == "" {
		return ErrReadOnly
	}
	var err error
	var conn *ldap.Conn
	var userDN string

	conn, err = ldap.DialURL(p.ldapURL)
	if err != nil {
		log.Printf("!!! ldap connection error: %v", err)
		return err
	}
	defer conn.Close()

	if err := conn.Bind(p.bindUser, p.bindPassword); err != nil {
		log.Printf("!!! ldap bind error: %v", err)
		return err
	}

	if userDN, _, err = p.queryDetails(conn, userID); err != nil {
		log.Printf("!!! Query for details failed: %v", err)
		return err
	}

	var req = ldap.NewPasswordModifyRequest(userDN, "", password)
	log.Printf("LDAP: modify password for user: %s", userDN)
	if _, err := conn.PasswordModify(req); err != nil {
		log.Printf("!!! ldap modify password failed: %v", err)
		return err
	}

	return nil
}
