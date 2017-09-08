// Copyright (C) Pagoda Box, Inc - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential

package router

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jcelliott/lumber"
)

// StartHealth starts the health checking for all registered routes. Only routes
// with 'Endpoint' defined will get checked. 'pulse' is the delay (in seconds)
// between health checks (default 60?)
func StartHealth(pulse int) {
	if pulse == 0 {
		pulse = 60
	}
	// i'sa guyanese ya kno
	for true {

		routesMutex.RLock()
		for i := range routes {
			if routes[i].Endpoint != "" {
				go checkPulse(&routes[i]) // todo: what if this gets deleted after being sent off
				// go checkPulse(routes[i].Endpoint, routes[i].ExpectedCode, routes[i].ExpectedBody,
				// 	routes[i].ExpectedHeader, routes[i].Timeout, routes[i].Attempts)
			}
			// todo: think through pulse
			// time.Sleep(routes[i].Pulse)
		}
		routesMutex.RUnlock()

		time.Sleep(time.Duration(pulse) * time.Second)
	}
}

// func checkPulse(endpoint, eCode, eBody, eHeader string, timeout, attempts int) {
func checkPulse(route *Route) {
	for i := range route.proxies {
		failcount := 0
		for ; failcount < route.Attempts; failcount++ {
			// res, err := rest(route.Host, strings.Join([]strings{route.proxies[i].targetUrl, route.Endpoint}, "/"), route.Timeout)
			res, err := rest(route.Host, route.proxies[i].targetUrl+"/"+route.Endpoint, route.Timeout)
			if err != nil {
				lumber.Trace("Failed to check pulse - %s", err.Error())
				continue
			}

			if res.StatusCode == route.ExpectedCode {
				lumber.Trace("Expected code match")
				break
			}
			if route.ExpectedBody != "" && readBodyString(res.Body) == route.ExpectedBody {
				lumber.Trace("Expected body match")
				break
			}
			if route.ExpectedHeader != "" && checkHeader(route.ExpectedHeader, res.Header) {
				lumber.Trace("Expected header match")
				break
			}

			lumber.Trace("Endpoint reached, but checks failed - %d", res.StatusCode)
		}
		if failcount >= route.Attempts {
			route.proxies[i].healthy = false
			lumber.Trace("Proxy marked unhealthy")
		} else {
			route.proxies[i].healthy = true
			lumber.Trace("Proxy healthy")
		}
	}
}

// readBodyString reads the request body into a string for comparing
func readBodyString(body io.ReadCloser) string {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(body)
	if err != nil {
		lumber.Trace("Failed to read body into string - %s", err.Error())
		return ""
	}

	return buf.String()
}

// checkHeader checks if the contents of a specified header match
func checkHeader(expected string, headers http.Header) bool {
	headerBits := strings.Split(expected, ":")
	if len(headerBits) != 2 {
		lumber.Trace("Failed to check header - bad format")
		return false
	}

	// check if it matches
	return headers.Get(headerBits[0]) == headerBits[1]
}

func rest(host, uri string, timeout int) (*http.Response, error) {
	lumber.Trace("Checking %s", uri)
	var client *http.Client
	client = http.DefaultClient

	client.Timeout = (time.Duration(timeout) * time.Millisecond)
	// todo: maybe configurable?
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to create request - %s", err.Error())
	}

	// set Host header
	if host != "" {
		req.Header.Add("Host", host)
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to do request - %s", err.Error())
	}

	return res, nil
}
