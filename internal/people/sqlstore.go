package people

import (
	"database/sql"
	"errors"
	"log"
	"strings"

	"github.com/blockloop/scan/v2"
	"github.com/cwkr/authd/internal/sqlutil"
	"golang.org/x/crypto/bcrypt"
)

type sqlStore struct {
	inMemoryStore
	dbconn   *sql.DB
	settings *StoreSettings
}

type PersonDetails struct {
	Birthdate     sql.NullString `db:"birthdate"`
	Department    sql.NullString `db:"department"`
	Email         sql.NullString `db:"email"`
	FamilyName    sql.NullString `db:"family_name"`
	GivenName     sql.NullString `db:"given_name"`
	PhoneNumber   sql.NullString `db:"phone_number"`
	RoomNumber    sql.NullString `db:"room_number"`
	StreetAddress sql.NullString `db:"street_address"`
	Locality      sql.NullString `db:"locality"`
	PostalCode    sql.NullString `db:"postal_code"`
}

func (p PersonDetails) Person() *Person {
	return &Person{
		Birthdate:     p.Birthdate.String,
		Department:    p.Department.String,
		Email:         p.Email.String,
		FamilyName:    p.FamilyName.String,
		GivenName:     p.GivenName.String,
		PhoneNumber:   p.PhoneNumber.String,
		RoomNumber:    p.RoomNumber.String,
		StreetAddress: p.StreetAddress.String,
		Locality:      p.Locality.String,
		PostalCode:    p.PostalCode.String,
	}
}

func NewSqlStore(users map[string]AuthenticPerson, dbs map[string]*sql.DB, settings *StoreSettings) (Store, error) {
	if dbconn, err := sqlutil.GetDB(dbs, settings.URI); err != nil {
		return nil, err
	} else {
		return &sqlStore{
			inMemoryStore: inMemoryStore{
				users: users,
			},
			dbconn:   dbconn,
			settings: settings,
		}, nil
	}
}

func (p sqlStore) queryGroups(userID string) ([]string, error) {

	if p.settings.GroupsQuery == "" {
		return []string{}, nil
	}

	var groups []string

	log.Printf("SQL: %s; -- %s", p.settings.GroupsQuery, userID)
	// SELECT id FROM groups WHERE lower(user_id) = lower($1)
	if rows, err := p.dbconn.Query(p.settings.GroupsQuery, userID); err == nil {
		if err := scan.Rows(&groups, rows); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	return groups, nil
}

func (p sqlStore) queryDetails(userID string) (*Person, error) {
	var personDetails PersonDetails

	log.Printf("SQL: %s; -- %s", p.settings.DetailsQuery, userID)
	// SELECT given_name, family_name, email, TO_CHAR(birthdate, 'YYYY-MM-DD') birthdate, department,
	// phone_number, room_number, street_address, locality, postal_code
	// FROM people WHERE lower(user_id) = lower($1)
	if rows, err := p.dbconn.Query(p.settings.DetailsQuery, userID); err == nil {
		if err := scan.RowStrict(&personDetails, rows); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrPersonNotFound
			}
			return nil, err
		}
	} else {
		return nil, err
	}
	return personDetails.Person(), nil
}

func (p sqlStore) Authenticate(userID, password string) (string, error) {
	var realUserID, err = p.inMemoryStore.Authenticate(userID, password)
	if err == nil {
		return realUserID, nil
	}

	// SELECT user_id, password_hash FROM people WHERE lower(user_id) = lower($1)
	log.Printf("SQL: %s; -- %s", p.settings.CredentialsQuery, userID)
	var row = p.dbconn.QueryRow(p.settings.CredentialsQuery, userID)
	var passwordHash string
	if err := row.Scan(&realUserID, &passwordHash); err == nil {
		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			log.Printf("!!! password comparison failed: %v", err)
		} else {
			return realUserID, nil
		}
	} else {
		log.Printf("!!! Query for person failed: %v", err)
		if err != sql.ErrNoRows {
			return "", err
		}
	}

	return "", ErrAuthenticationFailed
}

func (p sqlStore) Lookup(userID string) (*Person, error) {
	var person, err = p.inMemoryStore.Lookup(userID)
	if err == nil {
		return person, nil
	}

	var groups []string

	if person, err = p.queryDetails(userID); err != nil {
		log.Printf("!!! Query for details failed: %v", err)
		return nil, err
	}

	if groups, err = p.queryGroups(userID); err != nil {
		log.Printf("!!! Query for groups failed: %v", err)
		return nil, err
	}
	person.Groups = groups

	log.Printf("%#v", *person)
	return person, nil
}

func (p sqlStore) Ping() error {
	return p.dbconn.Ping()
}

func (p sqlStore) ReadOnly() bool {
	return false
}

func (p sqlStore) Put(userID string, person *Person) error {
	// UPDATE people SET given_name = $2, family_name = $3, email = $4, department = $5,
	// birthdate = TO_DATE($6, 'YYYY-MM-DD'), phone_number = $7, room_number = $8, street_address = $9, locality = $10,
	// postal_code = $11, last_modified = now() WHERE lower(user_id) = lower($1)
	log.Printf(
		"SQL: %s; -- %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s",
		p.settings.Update, userID, person.GivenName, person.FamilyName, person.Email, person.Department,
		person.Birthdate, person.PhoneNumber, person.RoomNumber,
		person.StreetAddress, person.Locality, person.PostalCode,
	)
	if _, err := p.dbconn.Exec(
		p.settings.Update,
		userID,
		strings.TrimSpace(person.GivenName),
		strings.TrimSpace(person.FamilyName),
		strings.TrimSpace(person.Email),
		strings.TrimSpace(person.Department),
		strings.TrimSpace(person.Birthdate),
		strings.TrimSpace(person.PhoneNumber),
		strings.TrimSpace(person.RoomNumber),
		strings.TrimSpace(person.StreetAddress),
		strings.TrimSpace(person.Locality),
		strings.TrimSpace(person.PostalCode),
	); err != nil {
		return err
	}
	return nil
}

func (p sqlStore) ChangePassword(userID, password string) error {
	if passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), 5); err != nil {
		return err
	} else {
		// UPDATE people SET password_hash = $2, last_modified = now() WHERE lower(user_id) = lower($1)
		log.Printf("SQL: %s; -- %s", p.settings.ChangePasswordQuery, userID)
		if _, err := p.dbconn.Exec(p.settings.ChangePasswordQuery, userID, passwordHash); err != nil {
			return err
		}
	}
	return nil
}
