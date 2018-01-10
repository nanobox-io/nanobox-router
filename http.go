// Copyright (C) Pagoda Box, Inc - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential

package router

import (
	"net"
	"net/http"
	"time"
)

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

	httpListener, err = net.Listen("tcp", address)
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
