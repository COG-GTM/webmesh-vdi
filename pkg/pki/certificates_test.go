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
	"crypto/x509"
	"math/big"
	"testing"

	appv1 "github.com/kvdi/kvdi/apis/app/v1"
	desktopsv1 "github.com/kvdi/kvdi/apis/desktops/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewSerialNumberIsUniqueAndHasEntropy(t *testing.T) {
	minSerial := new(big.Int).Lsh(big.NewInt(1), 64)
	seen := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		serial, err := newSerialNumber()
		if err != nil {
			t.Fatalf("expected no error generating a serial number, got %v", err)
		}
		if serial.Sign() <= 0 {
			t.Fatalf("expected a positive serial number, got %s", serial.String())
		}
		if serial.Cmp(minSerial) < 0 {
			t.Errorf("expected a serial number with at least 64 bits of entropy, got %s", serial.String())
		}
		if _, ok := seen[serial.String()]; ok {
			t.Fatalf("generated a duplicate serial number: %s", serial.String())
		}
		seen[serial.String()] = struct{}{}
	}
}

func TestCertificateSerialNumbersDoNotCollide(t *testing.T) {
	cluster := &appv1.VDICluster{ObjectMeta: metav1.ObjectMeta{Name: "test-cluster"}}
	desktop := &desktopsv1.Session{ObjectMeta: metav1.ObjectMeta{Name: "test-desktop", Namespace: "default"}}

	certFuncs := map[string]func() (*x509.Certificate, error){
		"ca":     func() (*x509.Certificate, error) { return newCACertificate(cluster) },
		"server": func() (*x509.Certificate, error) { return newAppServerCertificate(cluster) },
		"client": func() (*x509.Certificate, error) { return newAppClientCertificate(cluster) },
		"proxy": func() (*x509.Certificate, error) {
			return newDesktopProxyCertificate(cluster, desktop, "127.0.0.1")
		},
	}

	seen := make(map[string]string)
	for name, certFunc := range certFuncs {
		// Generate each certificate twice to ensure serials are not fixed per type.
		for i := 0; i < 2; i++ {
			cert, err := certFunc()
			if err != nil {
				t.Fatalf("expected no error building the %s certificate, got %v", name, err)
			}
			serial := cert.SerialNumber.String()
			if other, ok := seen[serial]; ok {
				t.Errorf("%s certificate reuses the serial number of the %s certificate: %s", name, other, serial)
			}
			seen[serial] = name
		}
	}
}
