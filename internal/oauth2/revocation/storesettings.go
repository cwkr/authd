package revocation

type StoreSettings struct {
	URI    string `json:"uri,omitempty"`
	Query  string `json:"query,omitempty"`
	Insert string `json:"insert,omitempty"`
}
