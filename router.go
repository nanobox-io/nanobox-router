package router

import (
	"github.com/nanobox-core/hatchet"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	DefaultPort = "80"
)

// Router is the device by which you create routing rules
type Router struct {
	log     hatchet.Logger
	Targets map[string]string
	Port    string
}

// New creates a new router sets its logger and returns a pointer to the Router
// object
func New(port string, logger hatchet.Logger) *Router {

	if logger == nil {
		logger = hatchet.DevNullLogger{}
	}

	r := &Router{
		log:     logger,
		Port:    port,
		Targets: make(map[string]string),
	}

	r.start()

	return r
}

// start fires up the http listener and routes traffic to your targets targets
// dont have to be set when the start is started but before the router can route
// the traffic it needs to know where traffic is going
func (r *Router) start() {
	go func() {
		r.log.Debug("[ROUTER]listening on port: %v", r.Port)
		err := http.ListenAndServe("0.0.0.0:"+r.Port, http.HandlerFunc(r.proxy))
    if err != nil {
      r.log.Error(err.Error())
    }
	}()
}

// AddTarget adds a path and target to the router this allows the router to know
// where traffic is going
func (r *Router) AddTarget(path, target string) {
	r.Targets[path] = target
}

// RemoveTarget removes a path from the routing table
func (r *Router) RemoveTarget(path string) {
	delete(r.Targets, path)
}

// proxy is the http handler that does the all the real routing work
func (r *Router) proxy(rw http.ResponseWriter, req *http.Request) {

	//
	uri := r.findTarget(req.RequestURI) + req.RequestURI

	r.log.Debug("[ROUTER]"+req.Method + ": " + uri)

	//
	remote, err := http.NewRequest(req.Method, uri, req.Body)
	r.fatal(err)

	copyHeader(req.Header, &remote.Header)

	// Create a client and query the target
	var transport http.Transport
	res, err := transport.RoundTrip(remote)
	r.fatal(err)

	r.log.Debug("[ROUTER]Resp-Headers: %v\n", res.Header)

	//
	body, err := ioutil.ReadAll(res.Body)
	r.fatal(err)

	defer res.Body.Close()

	//
	local := rw.Header()
	copyHeader(res.Header, &local)
	local.Add("Requested-Host", remote.Host)

	rw.Write(body)
}

// fatal handle errors and log data It does not stop execution
func (r *Router) fatal(err error) {
	if err != nil {
		r.log.Error(err.Error())
	}
}

// copyHeader copies the header from source to dest
func copyHeader(source http.Header, dest *http.Header) {
	for n, v := range source {
		for _, vv := range v {
			dest.Add(n, vv)
		}
	}
}

// findTarget starts with the path given and it looks through the paths to find
// a match. If it cant find it it strips the path one / back and recursively tries
// finding something.
func (r *Router) findTarget(path string) string {
	r.log.Debug("[ROUTER]Find target for: %v", path)

	//
	if target, ok := r.Targets[path]; ok {
		r.log.Debug("[ROUTER]Found: %v", target)

		return target
	} else {
		if path == "/" {
			return ""
		}
		arr := strings.Split(path, "/")

		//
		return r.findTarget(strings.Join(arr[:len(arr)-2], "/") + "/")
	}
}
