package httputil

import (
	"fmt"
	"log/slog"
	"net/http"
)

func PlainError(w http.ResponseWriter, error string, code int) {
	var statusText = http.StatusText(code)
	if code < 500 {
		slog.Warn(fmt.Sprintf("%d %s: %s", code, statusText, error))
	} else {
		slog.Error(fmt.Sprintf("%d %s: %s", code, statusText, error))
	}
	http.Error(w, fmt.Sprintf("%d %s", code, error), code)
}
