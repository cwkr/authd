package mail

type MailSettings struct {
	ServerURI string `json:"server_uri,omitempty"`
	From      string `json:"from,omitempty"`
}
