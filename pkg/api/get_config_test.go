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

package api

import (
	"testing"

	appv1 "github.com/kvdi/kvdi/apis/app/v1"
)

func TestRedactConfig(t *testing.T) {
	spec := &appv1.VDIClusterSpec{
		AppNamespace: "kvdi",
		App:          &appv1.AppConfig{TLS: &appv1.TLSConfig{ServerSecret: "tls-secret"}},
		Auth: &appv1.AuthConfig{
			AdminSecret: "admin-secret",
			LDAPAuth: &appv1.LDAPConfig{
				URL:                   "ldaps://ldap.example.com",
				TLSCACert:             "cacert",
				BindUserDNSecretKey:   "ldap-userdn",
				BindPasswordSecretKey: "ldap-password",
				BindCredentialsSecret: "ldap-creds",
			},
			OIDCAuth: &appv1.OIDCConfig{
				IssuerURL:               "https://issuer.example.com",
				TLSCACert:               "cacert",
				ClientIDKey:             "oidc-clientid",
				ClientSecretKey:         "oidc-clientsecret",
				ClientCredentialsSecret: "oidc-creds",
			},
		},
		Secrets: &appv1.SecretsConfig{Vault: &appv1.VaultConfig{Address: "https://vault.example.com"}},
	}

	got := redactConfig(spec)

	if got.AppNamespace != "kvdi" || got.Auth.LDAPAuth.URL == "" || got.Auth.OIDCAuth.IssuerURL == "" {
		t.Error("fields required by the UI were removed")
	}
	if got.Secrets != nil || got.App.TLS != nil || got.Auth.AdminSecret != "" {
		t.Error("secrets backend, TLS secret or admin secret leaked")
	}
	l := got.Auth.LDAPAuth
	if l.TLSCACert != "" || l.BindUserDNSecretKey != "" || l.BindPasswordSecretKey != "" || l.BindCredentialsSecret != "" {
		t.Error("LDAP secret references leaked")
	}
	o := got.Auth.OIDCAuth
	if o.TLSCACert != "" || o.ClientIDKey != "" || o.ClientSecretKey != "" || o.ClientCredentialsSecret != "" {
		t.Error("OIDC secret references leaked")
	}
	if spec.Auth.AdminSecret != "admin-secret" || spec.Secrets == nil {
		t.Error("original spec was mutated")
	}
}
