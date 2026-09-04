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
	"net/http"

	appv1 "github.com/kvdi/kvdi/apis/app/v1"
	"github.com/kvdi/kvdi/pkg/util/apiutil"
)

// swagger:route GET /api/config Miscellaneous getConfig
// Retrieves the current VDICluster configuration.
// responses:
//
//	200: configResponse
//	400: error
//	403: error
func (d *desktopAPI) GetConfig(w http.ResponseWriter, r *http.Request) {
	apiutil.WriteJSON(redactConfig(&d.vdiCluster.Spec), w)
}

// redactConfig returns a copy of the cluster spec with secret locations and
// secrets-backend connection details removed. The endpoint is readable by every
// authenticated user, so it must only expose what the UI needs.
func redactConfig(spec *appv1.VDIClusterSpec) *appv1.VDIClusterSpec {
	out := spec.DeepCopy()
	out.ImagePullSecrets = nil
	out.Secrets = nil
	if out.App != nil {
		out.App.TLS = nil
	}
	if out.Auth != nil {
		out.Auth.AdminSecret = ""
		if out.Auth.LDAPAuth != nil {
			out.Auth.LDAPAuth.TLSCACert = ""
			out.Auth.LDAPAuth.BindUserDNSecretKey = ""
			out.Auth.LDAPAuth.BindPasswordSecretKey = ""
			out.Auth.LDAPAuth.BindCredentialsSecret = ""
		}
		if out.Auth.OIDCAuth != nil {
			out.Auth.OIDCAuth.ClientIDKey = ""
			out.Auth.OIDCAuth.ClientSecretKey = ""
			out.Auth.OIDCAuth.ClientCredentialsSecret = ""
		}
	}
	return out
}

// Config response
// swagger:response configResponse
type swaggerConfigResponse struct {
	// in:body
	Body struct {
		appv1.VDIClusterSpec
	}
}
