// Copyright (C) Pagoda Box, Inc - All Rights Reserved
// Unauthorized copying of this file, via any medium is strictly prohibited
// Proprietary and confidential

package router

import (
	"crypto/tls"
	"fmt"
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
	GetCertificate: getCertificate,
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

// cfgCerts contains the active certificates to be served and tls config.
var cfgCerts = &tls.Config{}

// defaultCert is the cert served by default.
var defaultCert tls.Certificate

// Start listening for secure connection.
// The web server is split out from the much simpler form of
//  http.ListenAndServeTLS(addr string, certFile string, keyFile string, handler Handler)
// because we needed to handle multiple certs all at the same time and we needed
// to be able to change the set of certs without restarting the server
// this can be done by establishing a tls listener seperate form the http Server.
func StartTLS(addr string) error {
	if addr != "" {
		tlsAddress = addr
	}

	if tlsAddress == "" {
		return fmt.Errorf("TLS address not defined")
	}

	var err error
	if tlsListener != nil {
		tlsListener.Close()
	}
	if tlsServer != nil {
		// todo: or .Shutdown() and handle things
		tlsServer.Close()
	}
	// start only if we have certificates registered
	if len(cfgCerts.Certificates) > 0 || defaultCert.Certificate != nil {
		fmt.Println("Starting tls listener")

		tlsListener, err = tls.Listen("tcp", tlsAddress, tlsConfig)
		if err != nil {
			return err
		}

		tlsServer = &http.Server{
			Handler:           &handler{https: true},
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       120 * time.Second,
			TLSConfig:         tlsConfig,
		}

		go tlsServer.Serve(tlsListener)
	}

	return nil
}

// SetDefaultCert sets the default cert.
func SetDefaultCert(cert, key string) error {
	c, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return fmt.Errorf("Failed to create cert from provided info - %s", err.Error())
	}
	defaultCert = c

	certMutex.Lock()
	cfgCerts.Certificates = append([]tls.Certificate{defaultCert}, certificates...)
	cfgCerts.BuildNameToCertificate()
	certMutex.Unlock()
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

	// prepend default cert to slice
	certs := append([]tls.Certificate{defaultCert}, newCerts...)

	certMutex.Lock()
	keys = newKeys
	// update certificates
	certificates = newCerts
	cfgCerts.Certificates = certs
	// support sni
	cfgCerts.BuildNameToCertificate()
	certMutex.Unlock()
	lumber.Debug("[NANOBOX-ROUTER] Certs updated")
	return nil
}

// Keys returns registered keys
func Keys() []KeyPair {
	return keys
}

// from crypto/tls

// getCertificate returns the best certificate for the given ClientHelloInfo,
// defaulting to the first element of c.Certificates.
func getCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if len(cfgCerts.Certificates) == 0 {
		return nil, fmt.Errorf("tls: no certificates configured")
	}

	if len(cfgCerts.Certificates) == 1 || cfgCerts.NameToCertificate == nil {
		// There's only one choice, so no point doing any work.
		return &cfgCerts.Certificates[0], nil
	}

	name := strings.ToLower(clientHello.ServerName)
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	if cert, ok := cfgCerts.NameToCertificate[name]; ok {
		return cert, nil
	}

	// try replacing labels in the name with wildcards until we get a
	// match.
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if cert, ok := cfgCerts.NameToCertificate[candidate]; ok {
			return cert, nil
		}
	}

	// If nothing matches, return the first certificate.
	return &cfgCerts.Certificates[0], nil
}
