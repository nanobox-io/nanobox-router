package router

import "net/http"

// allows defining an error and how its handled
var ErrorHandler http.Handler

type NoRoutes struct {
}

func (self NoRoutes) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.WriteHeader(502)
	rw.Write([]byte("NoRoutes\n"))
}
