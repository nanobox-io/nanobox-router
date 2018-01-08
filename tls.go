// Copyright (C) Pagoda Box, Inc - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential

package router

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jcelliott/lumber"
)

// A KeyPair contains a key and certificate used to create a tls.Certificate
type KeyPair struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// certificates stores all generated Certificates
var certificates = []tls.Certificate{}

// keys stores all registered KeyPair objects
var keys = []KeyPair{}

// the default address to listen on for secure connections
var tlsAddress = "0.0.0.0:443"

// tlsListener is required for handling multiple certs
var tlsListener net.Listener

// tlsServer allows for upfront setting of timeouts
var tlsServer *http.Server

// certMutex ensures updates to certs are atomic
var certMutex = sync.RWMutex{}

// tlsConfig defines the tls preferences
var tlsConfig = &tls.Config{
	PreferServerCipherSuites: true,
	CurvePreferences:         []tls.CurveID{tls.CurveP256, tls.X25519, tls.CurveP384, tls.CurveP521},
	// MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		// tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		// tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	},
	NextProtos: []string{"h2", "http/1.1"},
}

// Start listening for secure connection.
// The web server is split out from the much simpler form of
//  http.ListenAndServeTLS(addr string, certFile string, keyFile string, handler Handler)
// because we needed to handle multiple certs all at the same time and we needed
// to be able to change the set of certs without restarting the server
// this can be done by establishing a tls listener seperate form the http Server.
func StartTLS(addr string) error {
	tlsAddress = addr
	var err error
	if tlsListener != nil {
		tlsListener.Close()
	}
	if tlsServer != nil {
		// todo: or .Shutdown() and handle things
		tlsServer.Close()
	}
	// start only if we have certificates registered
	if len(certificates) > 0 {
		// update certificates
		tlsConfig.Certificates = certificates

		// support sni
		tlsConfig.BuildNameToCertificate()
		tlsListener, err = tls.Listen("tcp", tlsAddress, tlsConfig)
		if err != nil {
			return err
		}

		tlsServer = &http.Server{
			Handler:      &handler{https:true},
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
			TLSConfig:    tlsConfig,
		}

		go tlsServer.Serve(tlsListener)
	}

	return nil
}

// UpdateCerts replaces registered certificates with a new set and restart the
// secure web server
func UpdateCerts(newKeys []KeyPair) error {
	newCerts := []tls.Certificate{}
	for _, newKey := range newKeys {
		// create a Certificate from KeyPair
		cert, err := tls.X509KeyPair([]byte(newKey.Cert), []byte(newKey.Key))
		if err == nil {
			newCerts = append(newCerts, cert)
		} else {
			lumber.Error("[NANOBOX-ROUTER] Failed to update certs - %v", err)
			return err
		}
	}

	certMutex.Lock()
	keys = newKeys
	certificates = newCerts
	certMutex.Unlock()
	err := StartTLS(tlsAddress)
	if err != nil {
		// if failed due to address in use, retry, otherwise just fail
		if strings.Contains(err.Error(), "already in use") {
			return UpdateCerts(newKeys)
		}
		lumber.Error("[NANOBOX-ROUTER] Failed to restart TLS listener - %v", err)
	}
	lumber.Trace("[NANOBOX-ROUTER] Certs updated")
	return nil
}

// Keys returns registered keys
func Keys() []KeyPair {
	return keys
}
