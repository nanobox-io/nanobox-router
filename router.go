package router

import (
  // "github.com/jcelliott/lumber"
  "net/http"
  "io/ioutil"
  "strconv"

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
  Target string
  Port   int

}


func New(port int, log Logger) *Router {
  if log == nil {
    log = DevNullLogger(0)
  }
  return &Router{
    log: log,
    Port: port,

  }
}


func (r *Router) Start() {
  go func () {
    r.log.Info(strconv.Itoa(r.Port))
    r.log.Info(r.Target)
    pHandler := http.HandlerFunc(r.report)
    http.ListenAndServe("localhost:"+strconv.Itoa(r.Port), pHandler)
  }()
}

func (r *Router) SetTarget(target string) {
  r.Target = target
}


func (r *Router)report(w http.ResponseWriter, req *http.Request){

  uri := r.Target+req.RequestURI

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

func (r *Router)fatal(err error) {
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