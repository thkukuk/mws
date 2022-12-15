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
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sync/atomic"
	"time"
	"strings"
	"syscall"
	"io/fs"
	"crypto/tls"

	"github.com/thkukuk/mws/pkg/certificates"
)

const (
	requestIDKey int = 0
)

type Redirects struct {
        UrlPath string
        Target  string
}

var (
	Version="unreleased"
	HttpDir="."
        ListenAddr=":80"
        ListenAddrSSL string
	ReadTimeout=5
	WriteTimeout=10
        TlsKey string
        TlsCert string
	Quiet=false
	healthy int32
	logger = log.New(os.Stdout, "", log.LstdFlags)
	logerr = log.New(os.Stderr, "", log.LstdFlags)
	RevProxy []Redirects
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

	for i := range RevProxy {
		logger.Printf("Add reverse proxy entry: %s -> %s\n",
			RevProxy[i].UrlPath, RevProxy[i].Target)

		// initialize a reverse proxy and pass the actual backend server url here
		proxy, err := NewProxy(RevProxy[i].Target)
		if err != nil {
			panic(err)
		}
		router.HandleFunc(RevProxy[i].UrlPath, ProxyRequestHandler(proxy))
	}

	nextRequestID := func() string {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	httpServ := &http.Server{
		Addr:         ListenAddr,
		Handler:      tracing(nextRequestID)(logging(logger)(router)),
		ErrorLog:     logerr,
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
		cert, err := certificates.GetOrCreateTLSCertificate(TlsCert, TlsKey)
		if err != nil {
			logerr.Fatal(err)
		}
		httpsServ.TLSConfig.Certificates = []tls.Certificate{cert}
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
				if r.URL.Path[len(r.URL.Path)-1:] != "/" {
					http.Redirect (w, r, r.URL.Path + "/", 301)
					return
				}

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
				if !Quiet {
					requestID, ok := r.Context().Value(requestIDKey).(string)
					if !ok {
						requestID = "unknown"
					}
					logger.Println(requestID, r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent())
				}
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


//
// Reverse Proxy functions
//

// NewProxy takes target host and creates a reverse proxy
func NewProxy(targetHost string) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(targetHost)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	targetQuery := target.RawQuery
	proxy.Director =  func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", target.Host)
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
     		req.URL.Path, req.URL.RawPath = joinURLPath(target, req.URL)
     		if targetQuery == "" || req.URL.RawQuery == "" {
     			req.URL.RawQuery = targetQuery + req.URL.RawQuery
     		} else {
     			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
     		}
    		if _, ok := req.Header["User-Agent"]; !ok {
     			// explicitly disable User-Agent so it's not set to default value
     			req.Header.Set("User-Agent", "")
     		}
	}
	//	ErrorHandler: func(rw http.ResponseWriter, r *http.Request, err error) {
	//		fmt.Printf("error was: %+v", err)
	//		rw.WriteHeader(http.StatusInternalServerError)
	//		rw.Write([]byte(err.Error()))
	//	},
	//}

	return proxy, nil
}

// ProxyRequestHandler handles the http request using proxy
func ProxyRequestHandler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func joinURLPath(a, b *url.URL) (path, rawpath string) {
     	if a.RawPath == "" && b.RawPath == "" {
     		return singleJoiningSlash(a.Path, b.Path), ""
     	}
     	// Same as singleJoiningSlash, but uses EscapedPath to determine
     	// whether a slash should be added
     	apath := a.EscapedPath()
     	bpath := b.EscapedPath()

     	aslash := strings.HasSuffix(apath, "/")
     	bslash := strings.HasPrefix(bpath, "/")

     	switch {
     	case aslash && bslash:
     		return a.Path + b.Path[1:], apath + bpath[1:]
     	case !aslash && !bslash:
     		return a.Path + "/" + b.Path, apath + "/" + bpath
     	}
     	return a.Path + b.Path, apath + bpath
}
