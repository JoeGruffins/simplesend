package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

const (
	passFile = "password.txt"
	filesDir = "files"
)

var (
	authSHA [32]byte
)

func main() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(dir)
	passPath := filepath.Join(dir, passFile)
	auth, err := ioutil.ReadFile(passPath)
	if err != nil {
		log.Fatal(err)
	}
	if len(auth) == 0 {
		log.Fatal("empty password")
	}
	auth = auth[:len(auth)-1]
	authStr := "Basic " +
		base64.StdEncoding.EncodeToString(append([]byte(":"), auth[:]...))
	authSHA = sha256.Sum256([]byte(authStr))
	for i, _ := range auth {
		auth[i] = 0
	}
	authStr = ""

	filesPath := filepath.Join(dir, filesDir)

	fs := http.FileServer(http.Dir(filesPath))

	logHandle := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t := time.Now()
			log.Printf("serving %s to %s", path.Base(r.URL.Path), r.RemoteAddr)
			h.ServeHTTP(w, r)
			log.Printf("served %s to %s in %v", path.Base(r.URL.Path), r.RemoteAddr, time.Now().Sub(t))
		})
	}

	mux := chi.NewRouter()
	httpServer := &http.Server{
		Handler:      mux,
		Addr:         ":3000",
		ReadTimeout:  12 * time.Hour,
		WriteTimeout: 12 * time.Hour,
	}

	mux.Use(middleware.Recoverer)
	mux.Use(middleware.RealIP)
	mux.Use(authMiddleware)

	mux.Handle("/files/*", http.StripPrefix("/files", logHandle(fs)))

	log.Fatal(httpServer.ListenAndServe())
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fail := func() {
			log.Printf("authentication failure from ip: %s", r.RemoteAddr)
			w.Header().Add("WWW-Authenticate", `Basic realm="simple send"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}
		auth := r.Header["Authorization"]
		if len(auth) == 0 {
			fail()
			return
		}

		as := sha256.Sum256([]byte(auth[0]))
		if subtle.ConstantTimeCompare(authSHA[:], as[:]) != 1 {
			fail()
			return
		}
		log.Printf("authenticated user with ip: %s", r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}
