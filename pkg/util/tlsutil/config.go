/*
Copyright 2020,2021 Avi Zimmerman

This file is part of kvdi.

kvdi is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

kvdi is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with kvdi.  If not, see <https://www.gnu.org/licenses/>.
*/

package tlsutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/kvdi/kvdi/apis/meta/v1"
)

// serverCertMountPath redeclared locally for mocking
var serverCertMountPath = v1.ServerCertificateMountPath

// clientCertMountPath redeclared locally for mocking
var clientCertMountPath = v1.ClientCertificateMountPath

// The minimum TLS version required for all mTLS traffic
var minTLSVersion = uint16(tls.VersionTLS13)

// NewServerTLSConfig returns a new server TLS configuration with client
// certificate verification enabled.
func NewServerTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(ServerKeypair())
	if err != nil {
		return nil, err
	}
	caCertPool, err := getCACertPool(serverCertMountPath)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		ClientCAs:                caCertPool,
		Certificates:             []tls.Certificate{cert},
		ClientAuth:               tls.RequireAndVerifyClientCert,
		PreferServerCipherSuites: true,
		MinVersion:               minTLSVersion,
		VerifyPeerCertificate:    verifyClientOnlyCertificate,
	}
	return tlsConfig, nil
}

// verifyClientOnlyCertificate rejects peer certificates that are also valid
// for server authentication. Only dedicated client certificates (such as the
// app's client keypair) may open mTLS sessions to proxy servers.
func verifyClientOnlyCertificate(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return errors.New("no verified client certificate presented")
	}
	leaf := verifiedChains[0][0]
	hasClientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageAny:
			return fmt.Errorf("client certificate %q is not a dedicated client certificate", leaf.Subject.CommonName)
		case x509.ExtKeyUsageClientAuth:
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		return fmt.Errorf("client certificate %q is missing client authentication usage", leaf.Subject.CommonName)
	}
	return nil
}

// NewClientTLSConfig returns a new client TLS configuration for use with
// connecting to a server requiring mTLS.
func NewClientTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(ClientKeypair())
	if err != nil {
		return nil, err
	}
	caCertPool, err := getCACertPool(clientCertMountPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   minTLSVersion,
	}, nil
}

// NewClientTLSConfigFromSecret returns a client TLS config from a kubernetes
// certificate secret.
func NewClientTLSConfigFromSecret(c client.Client, name, namespace string) (*tls.Config, error) {
	nn := types.NamespacedName{Name: name, Namespace: namespace}
	secret := &corev1.Secret{}
	if err := c.Get(context.TODO(), nn, secret); err != nil {
		return nil, err
	}
	for _, key := range []string{v1.CACertKey, corev1.TLSCertKey, corev1.TLSPrivateKeyKey} {
		if _, ok := secret.Data[key]; !ok {
			return nil, fmt.Errorf("%s missing from TLS secret", key)
		}
	}
	cert, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(secret.Data[v1.CACertKey]); !ok {
		return nil, errors.New("Failed to create CA certificate pool")
	}
	return &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   minTLSVersion,
	}, nil
}

// ServerKeypair returns the path to a server certificatee and key.
func ServerKeypair() (string, string) {
	return filepath.Join(serverCertMountPath, corev1.TLSCertKey),
		filepath.Join(serverCertMountPath, corev1.TLSPrivateKeyKey)
}

// ClientKeypair returns the path to a client certificatee and key.
func ClientKeypair() (string, string) {
	return filepath.Join(clientCertMountPath, corev1.TLSCertKey),
		filepath.Join(clientCertMountPath, corev1.TLSPrivateKeyKey)
}

// getCACertPool creates a CA Certificate pool from the CA found at the given
// mount point.
func getCACertPool(mountPath string) (*x509.CertPool, error) {
	caCertFile := filepath.Join(mountPath, v1.CACertKey)
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, errors.New("Failed to create CA cert pool")
	}
	return caCertPool, nil
}
