package server

import (
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cwkr/authd/internal/httputil"
)

//go:embed assets/favicon.ico
var favicon []byte

//go:embed assets/favicon-16x16.png
var favicon16x16 []byte

//go:embed assets/favicon-32x32.png
var favicon32x32 []byte

func FaviconHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Content-Length", fmt.Sprint(len(favicon)))
		httputil.Cache(w, 120*time.Hour)
		w.Write(favicon)
	})
}

func Favicon16x16Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Length", fmt.Sprint(len(favicon16x16)))
		httputil.Cache(w, 120*time.Hour)
		w.Write(favicon16x16)
	})
}

func Favicon32x32Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Length", fmt.Sprint(len(favicon32x32)))
		httputil.Cache(w, 120*time.Hour)
		w.Write(favicon32x32)
	})
}
