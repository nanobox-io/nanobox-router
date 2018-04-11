// Copyright (C) Pagoda Box, Inc - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential

package router

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// the default address to listen on for http connections
var httpAddress = "0.0.0.0:80"

// httpListener allows updates to routes
var httpListener net.Listener

// httpServer allows updates to routes
var httpServer *http.Server

// Start the Http Listener. Intentionally handles http requests the same way as
// tls.
func StartHTTP(address string) error {
	var err error
	if httpListener != nil {
		httpListener.Close()
	}

	if address != "" {
		httpAddress = address
	}
	if httpAddress == "" {
		return fmt.Errorf("HTTP address not defined")
	}

	httpListener, err = net.Listen("tcp", httpAddress)
	if err != nil {
		return err
	}

	httpServer = &http.Server{
		Handler:           &handler{},
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         tlsConfig,
	}

	go httpServer.Serve(httpListener)

	return nil
}
