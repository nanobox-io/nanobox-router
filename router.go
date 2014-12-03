package router

import (
  // "github.com/jcelliott/lumber"
  "net/http"
  "io/ioutil"
  "strconv"
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

type DevNullLogger int8
func (d DevNullLogger) Fatal(thing string,v ...interface{}) {}
func (d DevNullLogger) Error(thing string,v ...interface{}) {}
func (d DevNullLogger) Warn(thing string,v ...interface{}) {}
func (d DevNullLogger) Info(thing string,v ...interface{}) {}
func (d DevNullLogger) Debug(thing string,v ...interface{}) {}
func (d DevNullLogger) Trace(thing string,v ...interface{}) {}

type Router struct {
  log Logger
  Targets map[string]string
  Port    int

}


func New(port int, log Logger) *Router {
  if log == nil {
    log = DevNullLogger(0)
  }
  return &Router{
    log: log,
    Port: port,
    Targets: make(map[string]string),
  }
}


func (r *Router) Start() {
  go func () {
    r.log.Info(strconv.Itoa(r.Port))
    pHandler := http.HandlerFunc(r.report)
    http.ListenAndServe("0.0.0.0:"+strconv.Itoa(r.Port), pHandler)
  }()
}

func (r *Router) AddTarget(path, target string) {
  r.Targets[path] = target
}

func (r *Router) RemoveTarget(path, target string) {
  delete(r.Targets, path)
}


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

func (r *Router) fatal(err error) {
  if err != nil {
    r.log.Fatal(err.Error())
  }
}

func copyHeader(source http.Header, dest *http.Header){
  for n, v := range source {
      for _, vv := range v {
          dest.Add(n, vv)
      }
  }
}

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

