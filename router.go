// Copyright (C) Pagoda Box, Inc - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential

package router

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jcelliott/lumber"
)

// A Route contains the routing rules for a specific match. A match is based on
// the subdomain, domain, and path. If no path is specified, subdomain/domain
// matching will be used. A path may include the "*" wildcard character at the
// end of the path ("/admin*") for a broader match.
//
// "Targets" are not required if a "Page" is defined. A target is a list of
// servers to proxy a request to. A page gets served to clients upon a successful
// domain/path match. Pages take precedence over targets.
//
// FwdPath is similar to nginx's "sub_filter" as it allows the user to specify
// what query path gets forwarded to the client.
type Route struct {
	// defines match characteristics
	SubDomain string `json:"subdomain"` // subdomain to match on - "admin"
	Domain    string `json:"domain"`    // domain to match on - "myapp.com"
	Path      string `json:"path"`      // route to match on - "/admin"
	// defines actions
	Targets []string `json:"targets"` // ips of servers - ["http://127.0.0.1:8080/app1","http://127.0.0.2"] (optional)
	FwdPath string   `json:"fwdpath"` // path to forward to targets - "/goadmin" incoming req: test.com/admin -> 127.0.0.1/goadmin (optional)
	Page    string   `json:"page"`    // page to serve instead of routing to targets - "<HTML>We are fixing it</HTML>" (optional)

	// defines health check
	Endpoint       string `json:"endpoint"`        // url path to check for health (todo: what to do when fwdpath is set) (non blank enables health checks)
	ExpectedCode   int    `json:"expected_code"`   // expected http response code (default 200)
	ExpectedBody   string `json:"expected_body"`   // expected body
	ExpectedHeader string `json:"expected_header"` // expected http header (field:value)
	Host           string `json:"host"`            // 'host' header to use when performing health check
	Timeout        int    `json:"timeout"`         // milliseconds before connection times out (default 3000 (3s))
	Attempts       int    `json:"attempts"`        // number of times to try before marking dead
	// Pulse          int    `json:"pulse"`           // seconds delay between health checks (default 60?)

	// stored proxies
	proxies []*proxy
}

// A proxy is used for creating reverse proxies
type proxy struct {
	targetUrl    string                 // one of the Route's targets
	fwdPath      string                 // customizable path to forward to target
	healthy      bool                   // used for removing from balancing
	prefixPath   string                 // prefix to subtract from request path when forwarding
	reverseProxy *httputil.ReverseProxy // handler that forwards requests to another server, proxying their response back to the client
	// ignoreCert   bool                   // ignore checking upstream cert (likely will be configurable later, but we trust the upstream)
}

// ignore checking upstream cert (likely will be more granular later)
var IgnoreUpstreamCerts bool

// routes stores all registered Route objects
var routes = []Route{}

// routesMutex ensures updates to routes are atomic
var routesMutex = sync.RWMutex{}

// UpdateRoutes replaces registered routes with a new set and initializes their
// proxies, if needed
func UpdateRoutes(newRoutes []Route) error {
	for i := range newRoutes {
		if newRoutes[i].ExpectedCode == 0 {
			newRoutes[i].ExpectedCode = 200
		}
		if newRoutes[i].Timeout == 0 {
			newRoutes[i].Timeout = 3000
		}
		if newRoutes[i].Attempts == 0 {
			newRoutes[i].Attempts = 3
		}
		for _, tgt := range newRoutes[i].Targets {
			prox := &proxy{targetUrl: tgt, fwdPath: newRoutes[i].FwdPath, prefixPath: newRoutes[i].Path}
			err := prox.initProxy()
			if err == nil {
				newRoutes[i].proxies = append(newRoutes[i].proxies, prox)
			} else {
				lumber.Error("[NANOBOX-ROUTER] Failed to update routes - %v", err)
				return err
			}
		}
	}

	routesMutex.Lock()
	routes = newRoutes
	routesMutex.Unlock()
	lumber.Trace("[NANOBOX-ROUTER] Routes updated")
	return nil
}

// Routes returns registered routes
func Routes() []Route {
	return routes
}

// initProxy establishes the ReverseProxy
func (self *proxy) initProxy() error {
	if self.reverseProxy == nil {
		uri, err := url.Parse(self.targetUrl)
		if err != nil {
			return err
		}
		self.reverseProxy = NewSingleHostReverseProxy(uri, self.fwdPath, IgnoreUpstreamCerts, self.prefixPath)
		self.healthy = true // assume newly added nodes are healthy
		lumber.Trace("[NANOBOX-ROUTER] New proxy set")
	}
	return nil
}

// Start starts both http and tls servers
func Start(httpAddress, tlsAddress string) error {
	err := StartHTTP(httpAddress)
	if err != nil {
		return err
	}
	return StartTLS(tlsAddress)
}

// NewSingleHostReverseProxy is a customized copy of httputil.NewSingleHostReverseProxy
// that allows optional nginx 'sub_filter'-like behavior (customize "path"
// forwarded to target) as well as optionally ignoring upstream cert checking
func NewSingleHostReverseProxy(target *url.URL, fwdPath string, ignore bool, prefixPath string) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		if fwdPath == "" {
			// if no forward path specified, use path defined in target + query path
			req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		} else {
			fPath := singleJoiningSlash(fwdPath, strings.TrimPrefix(req.URL.Path, prefixPath))
			// use path defined in target + specified forward path + prefix stripped req path
			req.URL.Path = singleJoiningSlash(target.Path, fPath)
		}
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
	}

	// use DefaultTransport, determine and set InsecureSkipVerify accordingly
	transport := http.DefaultTransport
	transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: ignore}
	transport.(*http.Transport).MaxIdleConns = 10
	transport.(*http.Transport).IdleConnTimeout = 120 * time.Second

	return &httputil.ReverseProxy{Director: director, Transport: transport}
}

// Deprecated: Use NewSingleHostReverseProxy instead
//
// NewReverseProxy is a customized copy of httputil.NewSingleHostReverseProxy
// that allows optional nginx 'sub_filter'-like behavior (customize "path"
// forwarded to target)
func NewReverseProxy(target *url.URL, fwdPath string) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		if fwdPath == "" {
			// if no forward path specified, use path defined in target + query path
			req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		} else {
			// use path defined in target + specified forward path
			req.URL.Path = singleJoiningSlash(target.Path, fwdPath)
		}
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
	}

	return &httputil.ReverseProxy{Director: director}
}

// singleJoiningSlash is a helper function copied from httputil
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

// rfc https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html 13.5.1 makes it sound like
// websocket proxying should not be done (other than maybe tcp proxy) lets make it happen

// ServeWS is a combination of ReverseProxy.ServeHTTP from `net/http/httputil`
// and piping logic from `nanopack/redundis`.  It doesn't exactly match rfc spec
// for html proxying, but since it's more an http connection turned bare tcp, I
// don't feel bad.
func ServeWS(rw http.ResponseWriter, req *http.Request, p *httputil.ReverseProxy) {
	outreq := new(http.Request)
	*outreq = *req

	p.Director(outreq)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := outreq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outreq.Header.Set("X-Forwarded-For", clientIP)
	}

	// method of dialing the endpoint in order to create a pipe
	var dial func(network, address string) (net.Conn, error)

	// if port not specified, use default port for scheme
	if !strings.Contains(outreq.URL.Host, ":") {
		if outreq.URL.Scheme == "wss" || outreq.URL.Scheme == "https" {
			outreq.URL.Host = fmt.Sprintf("%s:443", outreq.URL.Host)
			// outreq.Header.Set("X-Forwarded-Proto", "wss") // todo: where these directly hit the ssl/non endpoint, is this necessary?
		} else {
			outreq.URL.Host = fmt.Sprintf("%s:80", outreq.URL.Host)
			// outreq.Header.Set("X-Forwarded-Proto", "ws") // todo: where these directly hit the ssl/non endpoint, is this necessary?
		}
	}

	// dial securely if secure scheme is specified
	if outreq.URL.Scheme == "wss" || outreq.URL.Scheme == "https" {
		dial = func(network, address string) (net.Conn, error) {
			return tls.Dial(network, address, p.Transport.(*http.Transport).TLSClientConfig)
		}
	} else {
		dial = net.Dial
	}

	// dial endpoint
	lumber.Trace("Dialing tcp %v", outreq.URL.Host)
	endpoint, err := dial("tcp", outreq.URL.Host)
	if err != nil {
		rw.WriteHeader(502)
		rw.Write([]byte("Failed to contact endpoint\n"))
		lumber.Error("[NANOBOX-ROUTER] Error contacting endpoint '%s' - %v", outreq.URL.String(), err)
		return
	}

	// ensure the ResponseWriter is hijackable (https://golang.org/pkg/net/http/#Hijacker)
	hj, ok := rw.(http.Hijacker)
	if !ok {
		rw.WriteHeader(500)
		rw.Write([]byte("Invalid ResponseWriter\n"))
		lumber.Error("[NANOBOX-ROUTER] Invalid ResponseWriter format")
		return
	}

	// hijack the connection from http server library
	user, _, err := hj.Hijack()
	if err != nil {
		rw.WriteHeader(500)
		rw.Write([]byte("Failed to proxy\n"))
		lumber.Error("[NANOBOX-ROUTER] Error hijacking request - %v", err)
		return
	}

	// user connection is ours to handle
	defer user.Close()
	defer endpoint.Close()

	// forward request to the endpoint (for upgrading)
	err = outreq.Write(endpoint)
	if err != nil {
		rw.WriteHeader(500)
		rw.Write([]byte("Failed to forward request\n"))
		lumber.Error("[NANOBOX-ROUTER] Error forwarding request - %v", err)
		return
	}

	// for piping connection from user and connection to endpoint
	pipe := func(writer, reader *net.Conn, label string) {
		io.Copy(*writer, *reader)
		lumber.Trace("[NANOBOX-ROUTER] %v hung up", label)
		// probably redundant, we get here because a failure to read in the io.Copy()
		(*reader).Close()

		// end the other relevant io.Copy()
		if *writer != nil {
			(*writer).Close()
		}

		// set reader to nil so dial doesn't continue trying to reach a dead endpoint
		*reader = nil
	}

	lumber.Trace("[NANOBOX-ROUTER] Piping user to endpoint...")
	go pipe(&endpoint, &user, "User")
	lumber.Trace("[NANOBOX-ROUTER] Piping endpoint to user...")
	pipe(&user, &endpoint, "Endpoint")
}
