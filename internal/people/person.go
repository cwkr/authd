package people

type Person struct {
	Birthdate     string   `json:"birthdate,omitempty"`
	Department    string   `json:"department,omitempty"`
	Email         string   `json:"email,omitempty"`
	FamilyName    string   `json:"family_name,omitempty"`
	GivenName     string   `json:"given_name,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	PhoneNumber   string   `json:"phone_number,omitempty"`
	RoomNumber    string   `json:"room_number,omitempty"`
	StreetAddress string   `json:"street_address,omitempty"`
	Locality      string   `json:"locality,omitempty"`
	PostalCode    string   `json:"postal_code,omitempty"`
}
