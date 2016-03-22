// Copyright (C) Pagoda Box, Inc - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential

// Package router is a client for creating/maintaining http(s) proxies.
//
// Certificates
//
// Certificates are stored as a KeyPair which contains the key and certificate.
// A tls.Certificate is created and stored separately and used for serving https
// clients. If a certificate is added, a tls listener will be created, and the
// X-Forwarded-Proto header will be set to "https" before the request gets proxied
// to the target. The certificate's Common Name must be set in order for the
// router to serve it to a matching incoming request.
//
// Start secure routing as follows:
//
//  StartTLS("0.0.0.0:443")
//
// Set certificates as follows:
//
//  UpdateCerts([]KeyPair{KeyPair{Key: "abcd123", Cert: "1234abc"}})
//
// Get certificates (key/cert pairs) as follows:
//
//  keys := Keys()
//
//
// Routes
//
// Routes have 2 implicit parts: matching criteria and action definitions. The
// matching portion includes subdomain, domain, and path. The matching algorighm
// is recursive, so a request to "admin.test.com" would still match the
// registered route `Route{Domain:"test.com"}`. Precedence is given to routes
// that match the request's subdomain (if any). Routes with the longest
// matching path are also prioritized (e.g. a request to "test.com/admin" would
// match "/admin" in `[]Route{Route{Path:"/"},Route{Path:"/admin"}}` because
// "/admin" is longer than "/").
//
// The action portion includes targets, fwdpath, and page. If page is specified,
// it gets served to the client when the request matches that route. Targets is
// a list of backend servers to proxy to. A target can include a path which, by
// default, will be prepended to the request's path prior to proxying. If fwdpath
// is set, it will be appended to any target path and used as the path forwarded
// to the target.
//
// Start routing as follows:
//
//  StartHTTP("0.0.0.0:80")
//
// Set routes as follows:
//
//  UpdateRoutes([]Route{Route{Domain: "test.com", Page: "Hello World!\n"}})
//
// Get registered routes as follows:
//
//  routes := Routes()
//
//
// Matching Scenarios
//
// Requests will always match the route with the longest path defined.
//
//  ROUTES
//    SUB   DOMAIN    PATH   PAGE
//    ""    test.com  /      "test"
//    ""    test.com  /admin "admin"
//
//  CURL
//    REQUEST            RESPONSE
//    test.com/admin     "admin"
//    test.com/admin/me  "admin"
//    admin.test.com     "test"
//    test.com/admins    "test"
//
// A path can include a "*" at the end to match similar requests.
//
//  ROUTES
//    SUB   DOMAIN    PATH   PAGE
//    ""    test.com  /      "test"
//    ""    test.com  /a*    "a is for apple"
//    ""    test.com  /b/    "b things"
//
//  CURL
//    REQUEST            RESPONSE
//    test.com/a         "a is for apple"
//    test.com/ant       "a is for apple"
//    test.com/ant/man   "a is for apple"
//    test.com/b         "test"
//    test.com/b/bear    "b things"
//
// A subdomain match takes precedence over a domain/path match.
//
//  ROUTES
//    SUB   DOMAIN    PATH   PAGE
//    admin test.com  /      "admin"
//    ""    test.com  /bill  "Buffalo Bill"
//
//  CURL
//    REQUEST              RESPONSE
//    admin.test.com/bill  "admin"
//    users.test.com/bill  "Buffalo Bill"
//
// If a Route's matcher has a subdomain only, then all requests with that
// particular subdomain will have the Route's defined action applied.
//
//  ROUTES
//    SUB   DOMAIN    PATH  PAGE
//    admin ""        /     "admin"
//    ""    test1.com /     "test1"
//
//  CURL
//    REQUEST            RESPONSE
//    admin.test1.com    "admin"
//    admin.test2.com    "admin"
//
// Logging
//
// In order to view logs embedded within nanobox-router, you must:
//  import "github.com/jcelliott/lumber"
// and set the level of logging desired (see lumber docs for more info)
//  lumber.Level(lumber.LvlInt("INFO"))
//
package router // import "github.com/nanobox-io/nanobox-router"
