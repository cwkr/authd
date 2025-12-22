package otpauth

type StoreSettings struct {
	URI    string `json:"uri,omitempty"`
	Query  string `json:"query,omitempty"`
	Update string `json:"update,omitempty"`
	Delete string `json:"delete,omitempty"`
}
