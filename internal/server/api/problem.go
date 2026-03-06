package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

type Response struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func Problem(w http.ResponseWriter, status int, detail string) {
	var statusText = http.StatusText(status)
	slog.Error(fmt.Sprintf("%d %s: %s", status, statusText, detail))
	var response = Response{
		Title:  statusText,
		Status: status,
		Detail: detail,
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	var bytes, _ = json.Marshal(response)
	w.Write(bytes)
}
