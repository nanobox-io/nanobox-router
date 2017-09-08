package router

import "net/http"

// allows defining an error and how its handled
var ErrorHandler http.Handler

// ErrNoRoutes is for setting a custom error message/html page if no routes are configured
var ErrNoRoutes []byte

type NoRoutes struct {
}

func (self NoRoutes) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(502)
	// if custom no routes error is set, use it
	if len(ErrNoRoutes) != 0 {
		rw.Write(ErrNoRoutes)
	} else {
		rw.Write([]byte("NoRoutes\n"))
	}
}

// ErrNoHealthy is for setting a custom error message/html page if no servers are healthy
var ErrNoHealthy []byte

type NoHealthy struct {
}

func (self NoHealthy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(502)
	// if custom no routes error is set, use it
	if len(ErrNoHealthy) != 0 {
		rw.Write(ErrNoHealthy)
	} else {
		rw.Write([]byte("NoHealthy\n"))
	}
}
