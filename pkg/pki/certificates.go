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

package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	appv1 "github.com/kvdi/kvdi/apis/app/v1"
	desktopsv1 "github.com/kvdi/kvdi/apis/desktops/v1"
	"github.com/kvdi/kvdi/pkg/util/tlsutil"
)

var ouName = []string{"kVDI"}

// serialNumberLimit is the upper bound for generated certificate serial numbers.
// RFC 5280 requires serials to be unique per issuer and the CA/Browser Forum
// baseline requirements mandate at least 64 bits of entropy.
var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func newKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keySize)
}

func newSerialNumber() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("could not generate certificate serial number: %w", err)
	}
	// Serial numbers must be positive non-zero integers.
	return serial.Add(serial, big.NewInt(1)), nil
}

func newCACertificate(cluster *appv1.VDICluster) (*x509.Certificate, error) {
	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cluster.GetCAName(),
			Organization: ouName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           caExtUsages,
		KeyUsage:              caUsages,
		BasicConstraintsValid: true,
		DNSNames:              []string{cluster.GetCAName()},
	}, nil
}

func newAppServerCertificate(cluster *appv1.VDICluster) (*x509.Certificate, error) {
	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cluster.GetAppName(),
			Organization: ouName,
		},
		DNSNames:     tlsutil.DNSNames(cluster.GetAppName(), cluster.GetCoreNamespace()),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		KeyUsage:     certificateUsages,
		ExtKeyUsage:  serverExtUsages,
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
		},
	}, nil
}

func newAppClientCertificate(cluster *appv1.VDICluster) (*x509.Certificate, error) {
	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cluster.GetAppName(),
			Organization: ouName,
		},
		DNSNames:     tlsutil.DNSNames(cluster.GetAppName(), cluster.GetCoreNamespace()),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		KeyUsage:     certificateUsages,
		ExtKeyUsage:  clientExtUsages,
	}, nil
}

func newDesktopProxyCertificate(cluster *appv1.VDICluster, desktop *desktopsv1.Session, serviceIP string) (*x509.Certificate, error) {
	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   serviceIP,
			Organization: ouName,
		},
		IPAddresses:  []net.IP{net.ParseIP(serviceIP)},
		DNSNames:     append(tlsutil.DNSNames(desktop.GetName(), desktop.GetNamespace()), serviceIP),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		KeyUsage:     certificateUsages,
		ExtKeyUsage:  serverExtUsages,
	}, nil
}

// encodeTLSKeyPair returns a map of PEM encoded values for the provided TLS key pair.
// The `ca` and `cert` are the raw asn1 data of the certificates.
func encodeTLSKeyPair(ca, cert []byte, key *rsa.PrivateKey) (certData map[string][]byte, err error) {
	caPEM := new(bytes.Buffer)
	if err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca,
	}); err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	if err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}); err != nil {
		return nil, err
	}
	caPrivKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		return nil, err
	}
	return map[string][]byte{
		caCertSecretKey:      caPEM.Bytes(),
		certificateSecretKey: certPEM.Bytes(),
		privateKeySecretKey:  caPrivKeyPEM.Bytes(),
	}, nil
}
