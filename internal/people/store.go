package people

type Store interface {
	Authenticate(userID, password string) (string, error)
	Lookup(userID string) (*Person, error)
	Ping() error
	ReadOnly() bool
	Put(userID string, person *Person) error
	ChangePassword(userID, password string) error
}
