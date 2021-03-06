// Copyright 2022 Thorsten Kukuk
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mws

import (
	"log"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"time"
	"syscall"
	"io/fs"
	"crypto/tls"
)

const (
	requestIDKey int = 0
)

var (
	Version="unreleased"
	HttpDir="."
        ListenAddr=":80"
        ListenAddrSSL string
	ReadTimeout=5
	WriteTimeout=10
        TlsKey string
        TlsCert string
	healthy int32
	logger = log.New(os.Stdout, "", log.LstdFlags)
	logerr = log.New(os.Stderr, "", log.LstdFlags)

)


//
// Webserver functions
//

func RunServer() {

	if (len(ListenAddr) <= 0 && len(ListenAddrSSL) <= 0) {
		logerr.Fatalf("Neither a HTTP nor HTTPS port specified, aborting...\n");
	}

	logger.Printf("Mini-WebServer (mws) %s is starting...\n", Version)
	logger.Printf("Serving directory is \"%s\"\n", HttpDir)

	router := http.NewServeMux()
	router.Handle("/", index())
	router.Handle("/healthz", healthz())

	nextRequestID := func() string {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	httpServ := &http.Server{
		Addr:         ListenAddr,
		Handler:      tracing(nextRequestID)(logging(logger)(router)),
		ErrorLog:     logger,
		ReadTimeout:  time.Duration(ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(WriteTimeout) * time.Second,
	}

	httpsServ := &http.Server{
		Addr:         ListenAddrSSL,
		Handler:      tracing(nextRequestID)(logging(logger)(router)),
		ErrorLog:     logger,
		ReadTimeout:  time.Duration(ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(WriteTimeout) * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
		},
	}

	if len(ListenAddrSSL) > 0 {
		httpsServ.TLSConfig.Certificates = []tls.Certificate{getOrCreateTLSCertificate(TlsCert, TlsKey)}
	}

	done := make(chan bool)
	quit := make(chan os.Signal, 1)
	// interrupt signal sent from terminal
	signal.Notify(quit, os.Interrupt)
	// sigterm signal sent from kubernetes
	signal.Notify(quit, syscall.SIGTERM)
	errs := make(chan error)

	go func() {
		<-quit
		logger.Println("Server is shutting down...")
		atomic.StoreInt32(&healthy, 0)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// shutdown servers
		if len(ListenAddr) > 0 {
			httpServ.SetKeepAlivesEnabled(false)
			if err := httpServ.Shutdown(ctx); err != nil {
				logerr.Fatalf("Could not gracefully shutdown http server: %v\n", err)
			}
		}
		if len(ListenAddrSSL) > 0 {
			httpsServ.SetKeepAlivesEnabled(false)
			if err := httpsServ.Shutdown(ctx); err != nil {
				logerr.Fatalf("Could not gracefully shutdown https server: %v\n", err)
			}
		}
		close(done)
	}()

	go func() {
		if (len(ListenAddr) > 0) {
			logger.Printf("Staring HTTP service on %s ...\n", ListenAddr)

			if err := httpServ.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logerr.Printf("HTTP: could not listen on %s: %v\n", ListenAddr, err)
				errs <- err
			}
		}
	}()

	go func() {
		if (len(ListenAddrSSL) > 0) {
			logger.Printf("Staring HTTPS service on %s ...\n", ListenAddrSSL)

			if err := httpsServ.ListenAndServeTLS("",""); err != nil && err != http.ErrServerClosed {
				logerr.Printf("HTTPS: could not listen on %s: %v\n", ListenAddrSSL, err)
				errs <- err
			}
		}
	}()

	// give servers a little bit of time to start...
	time.Sleep(100 * time.Millisecond)
	logger.Println("Server is ready to handle requests")
	atomic.StoreInt32(&healthy, 1)

	select {
	case <-errs:
		logerr.Fatalln("Aborting...")
	case <-done:
		logger.Println("Server stopped")
	}
}


// check if the Path is a directory
func isDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.IsDir()
}

// check if the Path is a regular file and nothing else
func isPathOk(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}

	mode := fileInfo.Mode()
	if (mode&fs.ModeNamedPipe != 0) {
		return false
	}

	return mode.IsRegular()
}

func index() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isPathOk(HttpDir + r.URL.Path) {
			// URL path is no regular file, maybe it's a directory?
			if isDirectory(HttpDir + r.URL.Path) {
				// Directory, check for common index files.
				// XXX Should be a loop over an array
				if isPathOk(HttpDir + r.URL.Path + "/index.html") {
					http.ServeFile(w, r, HttpDir + r.URL.Path + "/index.html")
					return
				} else if isPathOk(HttpDir + r.URL.Path + "/index.htm") {
					http.ServeFile(w, r, HttpDir + r.URL.Path + "/index.htm")
					return
				}
			}

			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		http.ServeFile(w, r, HttpDir + r.URL.Path)
	})
}

func healthz() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&healthy) == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
}

func logging(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				requestID, ok := r.Context().Value(requestIDKey).(string)
				if !ok {
					requestID = "unknown"
				}
				logger.Println(requestID, r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func tracing(nextRequestID func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-Id")
			if requestID == "" {
				requestID = nextRequestID()
			}
			ctx := context.WithValue(r.Context(), requestIDKey, requestID)
			w.Header().Set("X-Request-Id", requestID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
