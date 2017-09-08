package router_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jcelliott/lumber"
	"golang.org/x/net/websocket"

	"github.com/nanobox-io/nanobox-router"
)

// nanobox-router.test SSC
var key = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDboW1FcXq8rJX\nDwGZ2+solI9YR73/uqG0tp2WzPIMUSQY1FbvD9GO8wSToWdnDHW9M15eiLrk1TAn\nuo99phAovlw5RAsv5vopCf13MKVuWXaSwp6bB52qqLnr5SI2wtJBe5/+LzqUNq5/\nnfsUH0dEBc6hOOUeQPVcd8zAQJblKzg5O90wplqy5Iki4xfGrcF2paB8D4I91X7e\n+JRRVZA79zSzZ4x/opV/fsyL5tfRxoCNn9wnDH2KPR2k/e+A4Tw1fo6TisH4scSp\nMRLjf4Xg7+M72E7SDQ3/5+9d5egynzjT2LjHty8Le5J4fV42jtCQrB/PGys1B8Cx\npNtjo1gvAgMBAAECggEAXFZ7HF1mPyVeuB2h/wVWrbzLocV78zlGMDFcciTxdHpe\nGNEzJg8OT4FpNyu6xIixlKyRuQ7XZ0mHUC4ooBB3cBjJUFFjC8YRipRqywcUEvh4\nOs1zzQIjL8A64EdKDB+u4ju8E4hTIDZZ6nhFanOA45Xu1GQidVHx3DfKaUfbQ/l9\nX+AesqN+fpQBsxfKvYPtaKH8OMjcpLmlSns96r7IY5GQQv1Egy4M1W+Urljgcqim\nFblFOOIFD65nTLsGz6VhENc7gF/ueIv2hrlMYvSQQIM9IdrzGfCYLWzDhzY1x9r3\nvh9Erqn0rub0Rap5Wi7gdM8KIqJEjzp0mYvv2j9hmQKBgQDgLFkIE5j2AQn4S4+n\nFP9GHwgzrFuYOe9FAuoeIeVwcb6eNU6B2ptL3PJ/Pbd1dHcmef9pXUa2cpMo682D\ndQOc1h4kl9mNIvxVIj9Vu6fW0PrOBavGyJLsas0iKxiwzzF9bMt9aqcDphu/hfbB\nnXk70eRG9rUdn6EmvkbtEzSBbQKBgQDfLY4DMq2hhpHeRdLsxMYT3OPyeOcV9boD\nB3bVkxy61XTzFTaVyh6gWx9gxpY9mmv5yH96e93rQaqs5ScIuXrBTvSBTOyRTTw1\nzoZeiH0jN/nMV4x7sdhcrXo7hu7OjqcWGFzMiAYH44E277mrx56dvAgigrIJgPBY\njjX6w2waiwKBgDEwCekHw8xWtgVRLxgON2T/ciFEdGSWcbXGyfAKp/lgO98i+zLq\n8KBYvqzEsfiHsY0zv6My4E0wHrIf61wo1L4ZDUwiNY4OWyei+BqrrkwoVp/WBrb7\nU6GkXZZdtnE1RTqsIIpIWJUoYXZIwrgBAZTqnRglEeCKIiYKIi3qxN6RAoGBAKxX\nsG/1xbGTirdbsjtW5SNXk8ud483IeUF3lSPuu+PnjK1et01KzQXF+GAyWrjts+4r\nD45VcxUGG7fyKYeKPCplP1lOPu0h+JoQhyEfQ4tb4ZIUFY870joXWOn5FBb8gDkG\nzTrA2+9hl1oGG5p0x59FIf8McFH4eSHZiAPCv4trAoGBANw+K8+qmVCLOIpGGYqd\nRl2c2V35Qf17bXlLhv+fEliCI6ixp1fLfglE0IXcGtnSnnUH2cWpC5dlythEfyPH\nAfnZHDvuJ6K0uDgDq90EmwKyHQxihUF57D6oR6FZ3MPqmj41umeQyxC/HGtJm6po\na1Zn/gvZVeitHeVAeDJfJ/J8\n-----END PRIVATE KEY-----"
var cert = "-----BEGIN CERTIFICATE-----\nMIIDbTCCAlWgAwIBAgIJAM/PXFTYkPDoMA0GCSqGSIb3DQEBCwUAME0xCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJJRDETMBEGA1UECgwKbmFub2JveC5pbzEcMBoGA1UE\nAwwTbmFub2JveC1yb3V0ZXIudGVzdDAeFw0xNjAzMjIxODQyMTJaFw0xNzAzMjIx\nODQyMTJaME0xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJJRDETMBEGA1UECgwKbmFu\nb2JveC5pbzEcMBoGA1UEAwwTbmFub2JveC1yb3V0ZXIudGVzdDCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAMNuhbUVxeryslcPAZnb6yiUj1hHvf+6obS2\nnZbM8gxRJBjUVu8P0Y7zBJOhZ2cMdb0zXl6IuuTVMCe6j32mECi+XDlECy/m+ikJ\n/XcwpW5ZdpLCnpsHnaqouevlIjbC0kF7n/4vOpQ2rn+d+xQfR0QFzqE45R5A9Vx3\nzMBAluUrODk73TCmWrLkiSLjF8atwXaloHwPgj3Vft74lFFVkDv3NLNnjH+ilX9+\nzIvm19HGgI2f3CcMfYo9HaT974DhPDV+jpOKwfixxKkxEuN/heDv4zvYTtINDf/n\n713l6DKfONPYuMe3Lwt7knh9XjaO0JCsH88bKzUHwLGk22OjWC8CAwEAAaNQME4w\nHQYDVR0OBBYEFMRZye+7JAUv7l/44AVnocivjzJ7MB8GA1UdIwQYMBaAFMRZye+7\nJAUv7l/44AVnocivjzJ7MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\nAH2ygiWZs8pRYWQy6PKj3arci4diFkBiISGTFoAeE1tYkZVE6fM5acPaOV1z7/Fr\nSKeiRhlC7sfcRURaDPDy0of5V83PazQqs3+SNV4KR+O2PNZk6DalKmtwOlNHRKkJ\n5s79rWgqY1wEt4s5atIwVEgdg7WRz41V7WK5Q9IMkFqYVn8MHVKd0k3nuA9ksfXA\nQPBypyOEJGx7EML6Tena/YerpTmcw2Xt4ssxiZQIn/wP3dyqISGark8BNWK6y7iG\nWkt2VZCvKXhb5Q+s4IlxA58InR1b+8/NauYyL1bUgcc3LBHN5Ty6nMUUeb2WPQ32\n4qod6vx2rJfj718EYjrWdaI=\n-----END CERTIFICATE-----"
var fakeListen = "127.0.0.1:8088"
var proxyHttp = "127.0.0.1:8080"
var proxyTls = "127.0.0.1:8443"
var headers chan http.Header

func TestMain(m *testing.M) {
	headers = make(chan http.Header)
	lumber.Level(lumber.LvlInt("FATAL"))
	// lumber.Level(lumber.LvlInt("TRACE"))
	// start fake webserver (we will use to check what headers get set)
	go startFakeWeb()

	err := router.StartHTTP(proxyHttp)
	if err != nil {
		fmt.Printf("Failed to start http - %v\n", err)
		os.Exit(1)
	}
	fmt.Println("HTTP started")

	err = router.StartTLS(proxyTls)
	if err != nil {
		fmt.Printf("Failed to start https - %v\n", err)
		os.Exit(1)
	}
	fmt.Println("HTTPS started")
	time.Sleep(time.Second)

	rtn := m.Run()

	os.Exit(rtn)
}

// TestTls ensures http proxying works and sets the correct headers as well as
// ensures Route management works
func TestRoutes(t *testing.T) {

	// test bad routes
	routes := []router.Route{router.Route{Domain: "http://nanobox-router.test", Targets: []string{"!@#$%^&"}}}
	router.UpdateRoutes(routes)

	// configure a route
	routes = []router.Route{router.Route{Domain: "nanobox-router.test", Targets: []string{"http://" + fakeListen}}}

	// update the routes
	router.UpdateRoutes(routes)

	// get routes
	savedRoutes := router.Routes()

	if len(savedRoutes) != 1 || savedRoutes[0].Domain != "nanobox-router.test" {
		t.Errorf("Failed to update routes - %v", savedRoutes)
		t.FailNow()
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://"+proxyHttp, nil)
	if err != nil {
		t.Error("Failed test GET - %v", err)
		t.FailNow()
	}
	// set Host
	req.Host = "nanobox-router.test"
	// don't block on this request so we can process the chan
	go client.Do(req)

	// wait for headers
	time.Sleep(500 * time.Millisecond)
	hdrs := <-headers

	// standard request, proto should be http
	if hdrs.Get("X-Forwarded-Proto") != "http" || hdrs.Get("X-Forwarded-For") != "127.0.0.1" {
		t.Errorf("Headers do not match expected! Proto: '%v' For: '%v'", hdrs.Get("X-Forwarded-Proto"), hdrs.Get("X-Forwarded-For"))
	}
}

// TestTls ensures tls proxying works and sets the correct headers as well as
// ensures KeyPair(cert) management works
func TestTls(t *testing.T) {
	// configure routes
	routes := []router.Route{router.Route{Domain: "nanobox-router.test", Targets: []string{"http://" + fakeListen}}}
	router.UpdateRoutes(routes)

	// test bad certs
	certs := []router.KeyPair{router.KeyPair{Key: "key", Cert: "cert"}}
	router.UpdateCerts(certs)

	// configure a cert
	certs = []router.KeyPair{router.KeyPair{Key: key, Cert: cert}}

	// update the certs
	router.UpdateCerts(certs)

	// get certs
	savedCerts := router.Keys()

	if len(savedCerts) != 1 || savedCerts[0].Cert != cert {
		t.Errorf("Failed to update certs - %v", savedCerts)
		t.FailNow()
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://"+proxyTls, nil)
	if err != nil {
		t.Error("Failed test GET - %v", err)
		t.FailNow()
	}
	// set Host
	req.Host = "nanobox-router.test"
	// don't need to verify cert (self-signed)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	// don't block on this request so we can process the chan
	go client.Do(req)

	// wait for headers
	time.Sleep(500 * time.Millisecond)
	hdrs := <-headers

	if hdrs.Get("X-Forwarded-Proto") != "https" || hdrs.Get("X-Forwarded-For") != "127.0.0.1" {
		t.Errorf("Headers do not match expected! Proto: '%v' For: '%v'", hdrs.Get("X-Forwarded-Proto"), hdrs.Get("X-Forwarded-For"))
	}
}

// TestHandler ensures the handlers are performing correctly
func TestHandler(t *testing.T) {
	// configure routes
	routes := []router.Route{
		router.Route{Domain: "nanobox-router.test", Page: "route-a"},
		router.Route{SubDomain: "b", Path: "/b*", Page: "route-b"},
		router.Route{Domain: "nanobox-router.test", Path: "/c/", Page: "route-c"},
		router.Route{Domain: "nanobox-router.test", Path: "/d", Page: "route-d"},
		router.Route{Domain: "nanobox-router.test", Path: "/e*", Page: "route-e"},
		router.Route{Domain: "nanobox.test", Path: "/f", Page: "route-f"},
		router.Route{SubDomain: "f", Path: "/f", Page: "subdomain-f"},
		router.Route{Domain: "nanobox-router.test", Path: "/g", FwdPath: "/great-app", Targets: []string{"http://" + fakeListen}},
		router.Route{Domain: "nanobox-router.test", Path: "/h", Targets: []string{"http://" + fakeListen + "?app=mine"}},
		router.Route{Domain: "nanobox-router.test", Path: "/i"},
		router.Route{Domain: "nano-j.test", Path: "/j", Page: "domain-j"},
		router.Route{SubDomain: "j", Path: "/j", Page: "subdomain-j"},
		router.Route{Domain: "nano-k.test", Page: "domain-k"},
		router.Route{Path: "/k", Page: "path-k"},
	}
	router.UpdateRoutes(routes)

	// get routes
	savedRoutes := router.Routes()

	if len(savedRoutes) != 14 {
		t.Errorf("Failed to update routes - %v", savedRoutes)
		t.FailNow()
	}

	newReq := func(path string) *http.Request {
		req, err := http.NewRequest("GET", "https://"+proxyTls+path, nil)
		if err != nil {
			t.Error("Failed to create Request - %v", err)
			t.FailNow()
		}
		return req
	}
	getIt := func(req *http.Request) string {
		client := &http.Client{}
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		resp, err := client.Do(req)
		if err != nil {
			t.Error("Failed test GET - %v", err)
			t.FailNow()
		}
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Error("Failed to read Body - %v", err)
			t.FailNow()
		}

		return string(b)
	}
	// test "route-a"
	req := newReq("")
	req.Host = "nanobox-router.test"
	resp := getIt(req)
	if resp != "route-a" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test bad "route-b"
	req = newReq("")
	req.Host = "b.nanobox-router.test"
	resp = getIt(req)
	if resp != "route-a" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test "route-b"
	req = newReq("/b/")
	req.Host = "b.nanobox-router.test"
	resp = getIt(req)
	if resp != "route-b" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test bad "route-c"
	req = newReq("/cat")
	req.Host = "nanobox-router.test"
	resp = getIt(req)
	if resp != "route-a" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test "route-c"
	req = newReq("/c/")
	req.Host = "b.nanobox-router.test"
	resp = getIt(req)
	if resp != "route-c" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test bad "route-d"
	req = newReq("/dog")
	req.Host = "nanobox-router.test"
	resp = getIt(req)
	if resp != "route-a" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test "route-d"
	req = newReq("/d")
	req.Host = "nanobox-router.test"
	resp = getIt(req)
	if resp != "route-d" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test "route-e"
	req = newReq("/elephant")
	req.Host = "nanobox-router.test"
	resp = getIt(req)
	if resp != "route-e" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test "route-e"
	req = newReq("/e/a/b/dog")
	req.Host = "nanobox-router.test"
	resp = getIt(req)
	if resp != "route-e" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test bad "route-f"
	req = newReq("/")
	req.Host = "nanobox.test"
	resp = getIt(req)
	if resp != "NoRoutes\n" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test "route-f"
	req = newReq("/f")
	req.Host = "nanobox.test"
	resp = getIt(req)
	if resp != "route-f" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test "subdomain-f"
	req = newReq("/f")
	req.Host = "f.nanobox.test"
	resp = getIt(req)
	if resp != "subdomain-f" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test "route-g"
	req = newReq("/g")
	req.Host = "admin.nanobox-router.test"
	go getIt(req)
	<-headers

	// test "route-g"
	req = newReq("/g")
	req.Host = "nanobox-router.test"
	go getIt(req)
	<-headers

	// test "route-h"
	req = newReq("/h?id=1")
	req.Host = "nanobox-router.test"
	go getIt(req)
	<-headers

	// test bad "route-i"
	req = newReq("/i")
	req.Host = "nanobox-router.test"
	resp = getIt(req)
	if resp != "NoRoutes\n" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test "domain-j"
	req = newReq("/j")
	req.Host = "nano-j.test"
	resp = getIt(req)
	if resp != "domain-j" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test "subdomain-j"
	req = newReq("/j")
	req.Host = "j.nano-j.test"
	resp = getIt(req)
	if resp != "subdomain-j" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test "domain-k"
	req = newReq("/k")
	req.Host = "nano-k.test"
	resp = getIt(req)
	// domain wins over paths only, if path-k is desired for this request
	// add another route {Domain: "domain-k", Path: "/k", Page: "path-k"}
	if resp != "domain-k" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test "path-k"
	req = newReq("/k")
	req.Host = "nano-j.test"
	resp = getIt(req)
	if resp != "path-k" {
		t.Errorf("%q doesn't match expected out", resp)
	}

}

var oldProxyHttp = "127.0.0.1:8090"

// TestDepProxy tests deprecated new proxy function
func TestDepProxy(t *testing.T) {
	uri, err := url.Parse("http://" + fakeListen)
	if err != nil {
		t.Errorf("Failed to parse listen address", err)
	}

	oldProxy := router.NewReverseProxy(uri, "")

	go http.ListenAndServe(oldProxyHttp, oldProxy)
	time.Sleep(time.Second)

	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://"+oldProxyHttp, nil)
	if err != nil {
		t.Error("Failed create GET - %v", err)
		t.FailNow()
	}
	// set Host
	req.Host = "nanobox-router.test"

	go func() {
		_, err = client.Do(req)
		if err != nil {
			t.Error("Failed test GET - %v", err)
			t.FailNow()
		}
	}()
	time.Sleep(500 * time.Millisecond)
	hdrs := <-headers

	if hdrs.Get("X-Forwarded-Proto") != "" || hdrs.Get("X-Forwarded-For") != "127.0.0.1" {
		t.Errorf("Headers do not match expected! Proto: '%v' For: '%v'", hdrs.Get("X-Forwarded-Proto"), hdrs.Get("X-Forwarded-For"))
	}
}

var fakeWsListen = "127.0.0.1:8181"

// TestWebsockets tests websocket proxy functionality
func TestWebsockets(t *testing.T) {
	// add route to ws endpoint
	routes := []router.Route{
		router.Route{Path: "/zecho", Targets: []string{"ws://" + fakeWsListen}},
	}

	router.UpdateRoutes(routes)

	// create simple ws endpoint
	echo := func(ws *websocket.Conn) {
		io.Copy(ws, ws)
	}
	// todo: ensure this doesn't end-run the proxy
	http.Handle("/zecho", websocket.Handler(echo))

	go http.ListenAndServe(fakeWsListen, nil)
	time.Sleep(time.Second)

	// dial proxy address (should proxy to endpoint)
	ws, err := websocket.Dial("ws://"+proxyHttp+"/zecho", "", "http://localhost")
	if err != nil {
		t.Error("Failed ws DIAL - %v", err)
		t.FailNow()
	}

	// write a message on the socket
	if _, err := ws.Write([]byte("success!")); err != nil {
		t.Error("Failed ws WRITE - %v", err)
		t.FailNow()
	}

	var msg = make([]byte, 128)
	var n int
	// read the message from the socket
	if n, err = ws.Read(msg); err != nil {
		t.Error("Failed ws READ - %v", err)
		t.FailNow()
	}

	if string(msg[:n]) != "success!" {
		t.Errorf("%q doesn't match expected out", msg[:n])
	}
}

// TestStart tests starting both http/s proxy listeners
func TestStart(t *testing.T) {
	router.Start(proxyHttp, proxyTls)
}

// startFakeWeb is intended to just dump all headers into a channel
func startFakeWeb() error {
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		headers <- req.Header
		io.WriteString(w, "Success!\n")
	})
	// fmt.Println("Serving...")
	err := http.ListenAndServe(fakeListen, nil)
	if err != nil {
		fmt.Println("Something really Broke...")
		return err
	}
	fmt.Println("Something Broke...")
	return nil
}

func ExampleRoutes() {
	// configure a route
	routes := []router.Route{router.Route{Domain: "nanobox-router.test", Targets: []string{"http://127.0.0.1:8088"}}}

	// update the routes
	router.UpdateRoutes(routes)

	// get routes
	savedRoutes := router.Routes()
	if len(savedRoutes) < 1 {
		return
	}
	fmt.Printf("%v\n", savedRoutes[0].Domain)
	// Output:
	// nanobox-router.test
}

func ExampleKeys() {
	// self-signed key/cert
	key := "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDboW1FcXq8rJX\nDwGZ2+solI9YR73/uqG0tp2WzPIMUSQY1FbvD9GO8wSToWdnDHW9M15eiLrk1TAn\nuo99phAovlw5RAsv5vopCf13MKVuWXaSwp6bB52qqLnr5SI2wtJBe5/+LzqUNq5/\nnfsUH0dEBc6hOOUeQPVcd8zAQJblKzg5O90wplqy5Iki4xfGrcF2paB8D4I91X7e\n+JRRVZA79zSzZ4x/opV/fsyL5tfRxoCNn9wnDH2KPR2k/e+A4Tw1fo6TisH4scSp\nMRLjf4Xg7+M72E7SDQ3/5+9d5egynzjT2LjHty8Le5J4fV42jtCQrB/PGys1B8Cx\npNtjo1gvAgMBAAECggEAXFZ7HF1mPyVeuB2h/wVWrbzLocV78zlGMDFcciTxdHpe\nGNEzJg8OT4FpNyu6xIixlKyRuQ7XZ0mHUC4ooBB3cBjJUFFjC8YRipRqywcUEvh4\nOs1zzQIjL8A64EdKDB+u4ju8E4hTIDZZ6nhFanOA45Xu1GQidVHx3DfKaUfbQ/l9\nX+AesqN+fpQBsxfKvYPtaKH8OMjcpLmlSns96r7IY5GQQv1Egy4M1W+Urljgcqim\nFblFOOIFD65nTLsGz6VhENc7gF/ueIv2hrlMYvSQQIM9IdrzGfCYLWzDhzY1x9r3\nvh9Erqn0rub0Rap5Wi7gdM8KIqJEjzp0mYvv2j9hmQKBgQDgLFkIE5j2AQn4S4+n\nFP9GHwgzrFuYOe9FAuoeIeVwcb6eNU6B2ptL3PJ/Pbd1dHcmef9pXUa2cpMo682D\ndQOc1h4kl9mNIvxVIj9Vu6fW0PrOBavGyJLsas0iKxiwzzF9bMt9aqcDphu/hfbB\nnXk70eRG9rUdn6EmvkbtEzSBbQKBgQDfLY4DMq2hhpHeRdLsxMYT3OPyeOcV9boD\nB3bVkxy61XTzFTaVyh6gWx9gxpY9mmv5yH96e93rQaqs5ScIuXrBTvSBTOyRTTw1\nzoZeiH0jN/nMV4x7sdhcrXo7hu7OjqcWGFzMiAYH44E277mrx56dvAgigrIJgPBY\njjX6w2waiwKBgDEwCekHw8xWtgVRLxgON2T/ciFEdGSWcbXGyfAKp/lgO98i+zLq\n8KBYvqzEsfiHsY0zv6My4E0wHrIf61wo1L4ZDUwiNY4OWyei+BqrrkwoVp/WBrb7\nU6GkXZZdtnE1RTqsIIpIWJUoYXZIwrgBAZTqnRglEeCKIiYKIi3qxN6RAoGBAKxX\nsG/1xbGTirdbsjtW5SNXk8ud483IeUF3lSPuu+PnjK1et01KzQXF+GAyWrjts+4r\nD45VcxUGG7fyKYeKPCplP1lOPu0h+JoQhyEfQ4tb4ZIUFY870joXWOn5FBb8gDkG\nzTrA2+9hl1oGG5p0x59FIf8McFH4eSHZiAPCv4trAoGBANw+K8+qmVCLOIpGGYqd\nRl2c2V35Qf17bXlLhv+fEliCI6ixp1fLfglE0IXcGtnSnnUH2cWpC5dlythEfyPH\nAfnZHDvuJ6K0uDgDq90EmwKyHQxihUF57D6oR6FZ3MPqmj41umeQyxC/HGtJm6po\na1Zn/gvZVeitHeVAeDJfJ/J8\n-----END PRIVATE KEY-----"
	cert := "-----BEGIN CERTIFICATE-----\nMIIDbTCCAlWgAwIBAgIJAM/PXFTYkPDoMA0GCSqGSIb3DQEBCwUAME0xCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJJRDETMBEGA1UECgwKbmFub2JveC5pbzEcMBoGA1UE\nAwwTbmFub2JveC1yb3V0ZXIudGVzdDAeFw0xNjAzMjIxODQyMTJaFw0xNzAzMjIx\nODQyMTJaME0xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJJRDETMBEGA1UECgwKbmFu\nb2JveC5pbzEcMBoGA1UEAwwTbmFub2JveC1yb3V0ZXIudGVzdDCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAMNuhbUVxeryslcPAZnb6yiUj1hHvf+6obS2\nnZbM8gxRJBjUVu8P0Y7zBJOhZ2cMdb0zXl6IuuTVMCe6j32mECi+XDlECy/m+ikJ\n/XcwpW5ZdpLCnpsHnaqouevlIjbC0kF7n/4vOpQ2rn+d+xQfR0QFzqE45R5A9Vx3\nzMBAluUrODk73TCmWrLkiSLjF8atwXaloHwPgj3Vft74lFFVkDv3NLNnjH+ilX9+\nzIvm19HGgI2f3CcMfYo9HaT974DhPDV+jpOKwfixxKkxEuN/heDv4zvYTtINDf/n\n713l6DKfONPYuMe3Lwt7knh9XjaO0JCsH88bKzUHwLGk22OjWC8CAwEAAaNQME4w\nHQYDVR0OBBYEFMRZye+7JAUv7l/44AVnocivjzJ7MB8GA1UdIwQYMBaAFMRZye+7\nJAUv7l/44AVnocivjzJ7MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\nAH2ygiWZs8pRYWQy6PKj3arci4diFkBiISGTFoAeE1tYkZVE6fM5acPaOV1z7/Fr\nSKeiRhlC7sfcRURaDPDy0of5V83PazQqs3+SNV4KR+O2PNZk6DalKmtwOlNHRKkJ\n5s79rWgqY1wEt4s5atIwVEgdg7WRz41V7WK5Q9IMkFqYVn8MHVKd0k3nuA9ksfXA\nQPBypyOEJGx7EML6Tena/YerpTmcw2Xt4ssxiZQIn/wP3dyqISGark8BNWK6y7iG\nWkt2VZCvKXhb5Q+s4IlxA58InR1b+8/NauYyL1bUgcc3LBHN5Ty6nMUUeb2WPQ32\n4qod6vx2rJfj718EYjrWdaI=\n-----END CERTIFICATE-----"
	// configure a cert
	certs := []router.KeyPair{router.KeyPair{Key: key, Cert: cert}}

	// update the certs
	router.UpdateCerts(certs)

	// get certs
	savedCerts := router.Keys()
	if len(savedCerts) < 1 {
		return
	}
	fmt.Printf("%v\n", savedCerts[0].Key)
	// Output:
	// -----BEGIN PRIVATE KEY-----
	// MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDboW1FcXq8rJX
	// DwGZ2+solI9YR73/uqG0tp2WzPIMUSQY1FbvD9GO8wSToWdnDHW9M15eiLrk1TAn
	// uo99phAovlw5RAsv5vopCf13MKVuWXaSwp6bB52qqLnr5SI2wtJBe5/+LzqUNq5/
	// nfsUH0dEBc6hOOUeQPVcd8zAQJblKzg5O90wplqy5Iki4xfGrcF2paB8D4I91X7e
	// +JRRVZA79zSzZ4x/opV/fsyL5tfRxoCNn9wnDH2KPR2k/e+A4Tw1fo6TisH4scSp
	// MRLjf4Xg7+M72E7SDQ3/5+9d5egynzjT2LjHty8Le5J4fV42jtCQrB/PGys1B8Cx
	// pNtjo1gvAgMBAAECggEAXFZ7HF1mPyVeuB2h/wVWrbzLocV78zlGMDFcciTxdHpe
	// GNEzJg8OT4FpNyu6xIixlKyRuQ7XZ0mHUC4ooBB3cBjJUFFjC8YRipRqywcUEvh4
	// Os1zzQIjL8A64EdKDB+u4ju8E4hTIDZZ6nhFanOA45Xu1GQidVHx3DfKaUfbQ/l9
	// X+AesqN+fpQBsxfKvYPtaKH8OMjcpLmlSns96r7IY5GQQv1Egy4M1W+Urljgcqim
	// FblFOOIFD65nTLsGz6VhENc7gF/ueIv2hrlMYvSQQIM9IdrzGfCYLWzDhzY1x9r3
	// vh9Erqn0rub0Rap5Wi7gdM8KIqJEjzp0mYvv2j9hmQKBgQDgLFkIE5j2AQn4S4+n
	// FP9GHwgzrFuYOe9FAuoeIeVwcb6eNU6B2ptL3PJ/Pbd1dHcmef9pXUa2cpMo682D
	// dQOc1h4kl9mNIvxVIj9Vu6fW0PrOBavGyJLsas0iKxiwzzF9bMt9aqcDphu/hfbB
	// nXk70eRG9rUdn6EmvkbtEzSBbQKBgQDfLY4DMq2hhpHeRdLsxMYT3OPyeOcV9boD
	// B3bVkxy61XTzFTaVyh6gWx9gxpY9mmv5yH96e93rQaqs5ScIuXrBTvSBTOyRTTw1
	// zoZeiH0jN/nMV4x7sdhcrXo7hu7OjqcWGFzMiAYH44E277mrx56dvAgigrIJgPBY
	// jjX6w2waiwKBgDEwCekHw8xWtgVRLxgON2T/ciFEdGSWcbXGyfAKp/lgO98i+zLq
	// 8KBYvqzEsfiHsY0zv6My4E0wHrIf61wo1L4ZDUwiNY4OWyei+BqrrkwoVp/WBrb7
	// U6GkXZZdtnE1RTqsIIpIWJUoYXZIwrgBAZTqnRglEeCKIiYKIi3qxN6RAoGBAKxX
	// sG/1xbGTirdbsjtW5SNXk8ud483IeUF3lSPuu+PnjK1et01KzQXF+GAyWrjts+4r
	// D45VcxUGG7fyKYeKPCplP1lOPu0h+JoQhyEfQ4tb4ZIUFY870joXWOn5FBb8gDkG
	// zTrA2+9hl1oGG5p0x59FIf8McFH4eSHZiAPCv4trAoGBANw+K8+qmVCLOIpGGYqd
	// Rl2c2V35Qf17bXlLhv+fEliCI6ixp1fLfglE0IXcGtnSnnUH2cWpC5dlythEfyPH
	// AfnZHDvuJ6K0uDgDq90EmwKyHQxihUF57D6oR6FZ3MPqmj41umeQyxC/HGtJm6po
	// a1Zn/gvZVeitHeVAeDJfJ/J8
	// -----END PRIVATE KEY-----
}
