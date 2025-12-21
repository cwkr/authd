package clients

type Store interface {
	Authenticate(clientID, clientSecret string) (*Client, error)
	Lookup(clientID string) (*Client, error)
	List() ([]string, error)
	Ping() error
}
