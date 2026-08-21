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

package app

import (
	"testing"

	appv1 "github.com/kvdi/kvdi/apis/app/v1"
)

func TestNewAppServiceMonitorForCRTLSConfig(t *testing.T) {
	t.Run("operator server certificate", func(t *testing.T) {
		cluster := newCluster(t)
		monitor := newAppServiceMonitorForCR(cluster)
		tlsConfig := monitor.Spec.Endpoints[0].TLSConfig.SafeTLSConfig

		if tlsConfig.InsecureSkipVerify {
			t.Fatal("operator-issued server certificate should be verified")
		}
		if tlsConfig.CA.Secret == nil {
			t.Fatal("operator-issued server certificate should configure a CA secret")
		}
		if tlsConfig.CA.Secret.Name != cluster.GetAppServerTLSSecretName() {
			t.Errorf("CA secret name = %q, want %q", tlsConfig.CA.Secret.Name, cluster.GetAppServerTLSSecretName())
		}
		if tlsConfig.CA.Secret.Key != "ca.crt" {
			t.Errorf("CA secret key = %q, want %q", tlsConfig.CA.Secret.Key, "ca.crt")
		}
		if got, want := tlsConfig.ServerName, cluster.GetAppName()+"."+cluster.GetCoreNamespace()+".svc"; got != want {
			t.Errorf("TLS server name = %q, want %q", got, want)
		}
	})

	t.Run("external server certificate", func(t *testing.T) {
		cluster := newCluster(t)
		cluster.Spec.App = &appv1.AppConfig{
			TLS: &appv1.TLSConfig{ServerSecret: "external-server"},
		}
		monitor := newAppServiceMonitorForCR(cluster)
		tlsConfig := monitor.Spec.Endpoints[0].TLSConfig.SafeTLSConfig

		if !tlsConfig.InsecureSkipVerify {
			t.Fatal("external server certificate should preserve skipped verification")
		}
		if tlsConfig.CA.Secret != nil {
			t.Fatal("external server certificate should not configure the operator CA")
		}
		if tlsConfig.ServerName != "" {
			t.Errorf("TLS server name = %q, want empty", tlsConfig.ServerName)
		}
	})
}
