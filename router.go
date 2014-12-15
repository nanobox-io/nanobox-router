package router

import (
  // "github.com/jcelliott/lumber"
  "net/http"
  "io/ioutil"
  "strconv"
  "errors"
  "strings"
)

type Logger interface {
  Fatal(string, ...interface{})
  Error(string, ...interface{})
  Warn(string, ...interface{})
  Info(string, ...interface{})
  Debug(string, ...interface{})
  Trace(string, ...interface{})
}

// Router is the device by which you create routing rules
type Router struct {
  log Logger
  Targets map[string]string
  Port    int
}

// New creates a new router sets its logger and returns a pointer to the Router object
func New(port int, log Logger) *Router, error {
  if log == nil {
    return nil, errors.New("Cannot create a new Router without a logger")
  }
  return &Router{
    log: log,
    Port: port,
    Targets: make(map[string]string),
  }
}

// Start fires up the http listener and routes traffic to your targets
// targets dont have to be set when the start is started 
// but before the router can route the traffic it needs to know where traffic is going
func (r *Router) Start() {
  go func () {
    r.log.Info(strconv.Itoa(r.Port))
    pHandler := http.HandlerFunc(r.report)
    http.ListenAndServe("0.0.0.0:"+strconv.Itoa(r.Port), pHandler)
  }()
}

// AddTarget adds a path and target to the router
// this allows the router to know where traffic is going
func (r *Router) AddTarget(path, target string) {
  r.Targets[path] = target
}

// RemoveTarget removes a path from the routing table
func (r *Router) RemoveTarget(path) {
  delete(r.Targets, path)
}

// report is the http handler that does the all the real routing work
func (r *Router)report(w http.ResponseWriter, req *http.Request){

  uri := r.findTarget(req.RequestURI)+req.RequestURI

  r.log.Info(req.Method + ": " + uri)

  if req.Method == "POST" {
    body, err := ioutil.ReadAll(req.Body)
    r.fatal(err)
    r.log.Info("Body: %v\n", string(body));
  }

  rr, err := http.NewRequest(req.Method, uri, req.Body)
  r.fatal(err)
  copyHeader(req.Header, &rr.Header)

  // Create a client and query the target
  var transport http.Transport
  resp, err := transport.RoundTrip(rr)
  r.fatal(err)

  r.log.Info("Resp-Headers: %v\n", resp.Header);

  defer resp.Body.Close()
  body, err := ioutil.ReadAll(resp.Body)
  r.fatal(err)

  dH := w.Header()
  copyHeader(resp.Header, &dH)
  dH.Add("Requested-Host", rr.Host)

  w.Write(body)
}

// fatal handle errors and log data
// It does not stop execution
func (r *Router) fatal(err error) {
  if err != nil {
    r.log.Error(err.Error())
  }
}

// copyHeader copies the header from source to dest
func copyHeader(source http.Header, dest *http.Header){
  for n, v := range source {
      for _, vv := range v {
          dest.Add(n, vv)
      }
  }
}

// findTarget starts with the path given and it looks through the paths
// to find a match. If it cant find it it strips the path one / back 
// and recursively tries finding something.
func (r *Router) findTarget(path string) string {
  r.log.Info(path)
  if tar, ok := r.Targets[path]; ok {
    r.log.Info(tar)
    return tar
  } else {
    if path == "/" {
      return ""
    }
    arr := strings.Split(path, "/")
    return r.findTarget(strings.Join(arr[:len(arr)-2], "/")+"/")
  }
}

