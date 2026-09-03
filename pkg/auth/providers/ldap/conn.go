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

package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

// connect creates a connection with the ldap server. It assumes the credentials
// are already present in the current interface. Connections to plain ldap://
// URLs are upgraded with StartTLS before any bind so credentials never leave
// the process unencrypted.
func (a *AuthProvider) connect() (*ldapv3.Conn, error) {
	if a.cluster.IsUsingLDAPOverTLS() {
		return ldapv3.DialURL(a.cluster.GetLDAPURL(), ldapv3.DialWithTLSConfig(a.tlsConfig))
	}
	conn, err := ldapv3.DialURL(a.cluster.GetLDAPURL())
	if err != nil {
		return nil, err
	}
	if err := conn.StartTLS(a.tlsConfig); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ldap server at %s does not support StartTLS, refusing to bind over cleartext: %w", a.cluster.GetLDAPURL(), err)
	}
	return conn, nil
}

func (a *AuthProvider) bind(conn *ldapv3.Conn) error {
	return conn.Bind(a.bindDN, a.bindPassw)
}

func (a *AuthProvider) fetchAndSetBindCredentials() error {
	var err error
	a.bindDN, a.bindPassw, err = a.getCredentials()
	return err
}

func (a *AuthProvider) setTLSConfig() error {
	caCert, err := a.cluster.GetLDAPCA()
	if err != nil {
		return err
	}
	var caCertPool *x509.CertPool
	if caCert != nil {
		caCertPool = x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("ldap tlsCACert does not contain any valid PEM certificates")
		}
	}
	u, err := url.Parse(a.cluster.GetLDAPURL())
	if err != nil {
		return err
	}
	a.tlsConfig = &tls.Config{
		InsecureSkipVerify: a.cluster.GetLDAPInsecureSkipVerify(),
		RootCAs:            caCertPool,
		ServerName:         u.Hostname(),
	}
	return nil
}
