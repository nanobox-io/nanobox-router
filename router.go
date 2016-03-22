// Copyright (C) Pagoda Box, Inc - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential

package router

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/jcelliott/lumber"
)

// A Route contains the routing rules for a specific match. A match is based on
// the subdomain, domain, and path. If no path is specified, subdomain/domain
// matching will be used. If a path does not end in "/", the match will be
// similar to /path*/ (subject to change).
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

	// stored proxies
	proxies []*proxy
}

// A proxy is used for creating reverse proxies
type proxy struct {
	targetUrl    string                 // one of the Route's targets
	fwdPath      string                 // customizable path to forward to target
	reverseProxy *httputil.ReverseProxy // handler that forwards requests to another server, proxying their response back to the client
}

// routes stores all registered Route objects
var routes = []Route{}

// mutex ensures updates to routes and certs are atomic
var mutex = sync.Mutex{}

// UpdateRoutes replaces registered routes with a new set and initializes their
// proxies, if needed
func UpdateRoutes(newRoutes []Route) {
	for i := range newRoutes {
		for _, tgt := range newRoutes[i].Targets {
			prox := &proxy{targetUrl: tgt, fwdPath: newRoutes[i].FwdPath}
			err := prox.initProxy()
			if err == nil {
				newRoutes[i].proxies = append(newRoutes[i].proxies, prox)
			} else {
				lumber.Error("[NANOBOX-ROUTER] Failed to update routes - %v", err)
			}
		}
	}

	mutex.Lock()
	routes = newRoutes
	mutex.Unlock()
	lumber.Trace("[NANOBOX-ROUTER] Routes updated")
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
		self.reverseProxy = NewReverseProxy(uri, self.fwdPath)
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
