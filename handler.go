// Copyright (C) Pagoda Box, Inc - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential

package router

import (
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/jcelliott/lumber"
)

// the number used to % for round robin requests
var robiner = uint32(0)

// The handler is an HTTP Handler that takes an incoming request and compares
// it to registered routing rules. It then either serves a defined "page" to the
// client, or it sends the request to another server, proxying the response back
// to the client.
type handler struct {
	https bool
}

// ServeHTTP finds a routing rule matching the incoming request and either serves
// a predefined "page" or proxies the request (round-robin) to predefined
// "targets". If a request doesn't match a routing rule (rules too specific) I
// respond with a 502 - NoRoutes error.
func (self handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if ErrorHandler != nil {
		lumber.Trace("[NANOBOX-ROUTER] Serving ErrorHandler")
		ErrorHandler.ServeHTTP(rw, req)
		return
	}
	if self.https {
		lumber.Trace("[NANOBOX-ROUTER] Setting X-Forwarded-Proto")
		req.Header.Set("X-Forwarded-Proto", "https")
	}

	// because net.SplitHostPort errors if no port
	re := regexp.MustCompile(`:\d+`) // used to remove the port from the host
	host := string(re.ReplaceAll([]byte(req.Host), nil))

	// find match
	lumber.Trace("[NANOBOX-ROUTER] URL-----%+q", req.URL)
	route := bestMatch(host, req.URL.Path)
	// lumber.Trace("[NANOBOX-ROUTER] Request Headers: '%+q'", req.Header)
	if route != nil {
		lumber.Trace("[NANOBOX-ROUTER] Route chosen: '%+q'", route)

		// serve page
		if route.Page != "" {
			rw.Write([]byte(route.Page))
			return
		}
		// if proxies not established, respond with error
		if len(route.proxies) == 0 {
			NoRoutes{}.ServeHTTP(rw, req)
			return
		}

		var thisProxy *proxy
		var unhealthyCounter int = 0

	robinProxy:
		// proxy the request (round-robin)
		thisProxy = route.proxies[atomic.AddUint32(&robiner, 1)%uint32(len(route.proxies))]
		if !thisProxy.healthy {
			// if we've tried all known endpoints, all unhealthy, return NoHealthy error
			if unhealthyCounter >= len(route.proxies) {
				NoHealthy{}.ServeHTTP(rw, req)
				return
			}
			unhealthyCounter++
			goto robinProxy
		}

		// todo: maybe? or just check target's scheme
		if strings.ToLower(req.Header.Get("Upgrade")) == "websocket" {
			lumber.Trace("[NANOBOX-ROUTER] Websocket detected...")
			ServeWS(rw, req, thisProxy.reverseProxy)
		} else {
			thisProxy.reverseProxy.ServeHTTP(rw, req)
		}
		return
	}

	// no registered route matches the request (routes too specific)
	lumber.Debug("[NANOBOX-ROUTER] Unsure where to route!")
	NoRoutes{}.ServeHTTP(rw, req)
}

// bestMatch is the route matching system. It first checks the request's
// subdomain (if any), then the domain, followed by the path. If a match is not
// found, the request's subdomain is stripped, one at a time, and checked again
// in a recursive manor until a match is or isn't found. Path matches are scored
// so the route with the longest matching path is chosen.
func bestMatch(host, path string) (route *Route) {
	lumber.Trace("[NANOBOX-ROUTER] Checking Request: '%v'...", host+path)
	matchScore := 0

	routesMutex.RLock()
	for i := range routes {
		lumber.Trace("[NANOBOX-ROUTER] Checking Route: '%v'", routes[i].SubDomain+"."+routes[i].Domain+routes[i].Path)
		if subdomainMatch(host, routes[i]) && domainMatch(host, routes[i]) && pathMatch(path, routes[i]) {
			// Assign a temporary score to check against current matchscore for
			// proper routing. We add length of all parts to get a more exact match
			// if the route has the same parts set. Without the bonus, a route
			// with a domain could beat the more defined route with a subdomain.
			bonus := 0
			// The reason for the imbalance is to account for cases where one route
			// has only the domain and path set, and another route has only the
			// subdomain and same path set.
			if routes[i].SubDomain != "" {
				bonus += 1500
			}
			if routes[i].Domain != "" {
				bonus += 1000
			}
			if routes[i].Path != "" {
				bonus += 500
			}

			tempScore := len(routes[i].Path) + len(routes[i].SubDomain) + len(routes[i].Domain) + bonus
			lumber.Trace("[NANOBOX-ROUTER] tempScore: '%v'", tempScore)

			if tempScore > matchScore {
				matchScore = tempScore
				route = &routes[i]
				lumber.Trace("[NANOBOX-ROUTER] Matchscore: '%v'", matchScore)
			}
		}
	}
	routesMutex.RUnlock()

	if route == nil {
		hostParts := strings.Split(host, ".")
		// if there's no subdomain to strip, return
		if len(hostParts) <= 2 {
			return nil
		}
		lumber.Trace("[NANOBOX-ROUTER] Stripping subdomain: '%v'", hostParts[0])
		// strip a subdomain and try matching again
		return bestMatch(strings.Join(hostParts[1:], "."), path)
	}
	return route
}

// subdomainMatch checks if the request has a subdomain and if we have routes
// that match that subdomain
func subdomainMatch(requestHost string, r Route) bool {
	// if there is no subdomain, no need to worry about matching
	if r.SubDomain == "" {
		return true
	}

	subdomain := ""
	hostBits := strings.Split(requestHost, ".")
	if len(hostBits) > 2 {
		subdomain = strings.Join(hostBits[:len(hostBits)-2], ".")
		lumber.Trace("[NANOBOX-ROUTER] Subdomain: '%s'", subdomain)
	}

	match := strings.HasPrefix(subdomain, r.SubDomain)
	lumber.Trace("[NANOBOX-ROUTER] Subdomain match? '%t'", match)
	return match
}

// domainMatch checks if the route has a domain and if the request matches
func domainMatch(requestHost string, r Route) bool {
	// if there is no domain, no need to worry about matching
	if r.Domain == "" {
		return true
	}
	domain := ""
	hostBits := strings.Split(requestHost, ".")
	if len(hostBits) >= 2 {
		domain = strings.Join(hostBits[len(hostBits)-2:], ".")
		lumber.Trace("[NANOBOX-ROUTER] Domain: '%s'", domain)
	}
	match := domain == r.Domain
	lumber.Trace("[NANOBOX-ROUTER] Domain match? '%t'", match)
	return match
}

// pathMatch checks if the route has a path and if the request matches
func pathMatch(requestPath string, r Route) bool {
	// if there is no path, no need to worry about matching (default to "/")
	if r.Path == "" {
		return true
	}
	match := false
	switch r.Path[len(r.Path)-1] {
	case '/':
		// check for parent dir match
		match = strings.HasPrefix(requestPath, r.Path)
	case '*':
		// check for prefix match
		match = strings.HasPrefix(requestPath, r.Path[:len(r.Path)-1])
	default:
		// check for exact match or exact match + "/"
		match = (r.Path == requestPath) || strings.HasPrefix(requestPath, r.Path+"/")
	}
	lumber.Trace("[NANOBOX-ROUTER] Path match: '%t'", match)
	return match
}
