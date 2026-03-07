package httputil

import (
	"fmt"
	"net/http"
	"net/url"
)

func RedirectFragment(w http.ResponseWriter, r *http.Request, url string, params url.Values) {
	http.Redirect(w, r, fmt.Sprintf("%s#%s", url, params.Encode()), http.StatusFound)
}

func RedirectQuery(w http.ResponseWriter, r *http.Request, url string, params url.Values) {
	http.Redirect(w, r, fmt.Sprintf("%s?%s", url, params.Encode()), http.StatusFound)
}
