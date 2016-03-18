// Copyright (C) Pagoda Box, Inc - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential

package router

import (
	"net/http/httputil"
	"net/url"
	"sync"

	"github.com/jcelliott/lumber"
)

// A route object from the api
type Route struct {
	SubDomain string   `json:"subdomain"` // subdomain to match on - "admin"
	Domain    string   `json:"domain"`    // domain to match on - "myapp.com"
	Path      string   `json:"path"`      // route to match on - "/admin"
	Targets   []string `json:"targets"`   // ips of servers - ["127.0.0.1","127.0.0.2"]
	Page      string   `json:"page"`      // page to serve instead of routing to targets - "<HTML>We are fixing it</HTML>"

	proxies []*proxy
}

// Simple Ip storage for creating Reverse Proxies
type proxy struct {
	URL          string
	reverseProxy *httputil.ReverseProxy
}

var routes = []Route{}
var mutex = sync.Mutex{}

// replace my routes with a new set
func UpdateRoutes(newRoutes []Route) {
	for i := range newRoutes {
		for _, target := range newRoutes[i].Targets {
			prox := &proxy{URL: target}
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

// Show my cached copy of the routes.
func Routes() []Route {
	return routes
}

// Establish the ReverseProxy
func (self *proxy) initProxy() error {
	if self.reverseProxy == nil {
		uri, err := url.Parse(self.URL)
		if err != nil {
			return err
		}
		self.reverseProxy = httputil.NewSingleHostReverseProxy(uri)
		lumber.Trace("[NANOBOX-ROUTER] New proxy set")
	}
	return nil
}

// Start both http and tls servers
func Start(httpAddress, tlsAddress string) error {
	err := StartHTTP(httpAddress)
	if err != nil {
		return err
	}
	return StartTLS(tlsAddress)
}
