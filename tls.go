// Copyright (C) Pagoda Box, Inc - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential

package router

import (
	"crypto/tls"
	"net"
	"net/http"

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
	// start only if we have certificates registered
	if len(certificates) > 0 {
		config := &tls.Config{
			Certificates: certificates,
		}
		// support sni
		config.BuildNameToCertificate()
		tlsListener, err = tls.Listen("tcp", tlsAddress, config)
		if err != nil {
			return err
		}

		go http.Serve(tlsListener, &handler{https: true})
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

	mutex.Lock()
	keys = newKeys
	certificates = newCerts
	mutex.Unlock()
	StartTLS(tlsAddress)
	lumber.Trace("[NANOBOX-ROUTER] Certs updated")
	return nil
}

// Keys returns registered keys
func Keys() []KeyPair {
	return keys
}
