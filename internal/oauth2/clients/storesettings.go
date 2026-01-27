package clients

type StoreSettings struct {
	URI         string `json:"uri,omitempty"`
	LookupQuery string `json:"lookup_query,omitempty"`
	ListQuery   string `json:"list_query,omitempty"`
}
