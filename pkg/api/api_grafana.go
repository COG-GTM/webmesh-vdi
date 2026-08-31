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

	v1 "github.com/kvdi/kvdi/apis/meta/v1"
	"github.com/kvdi/kvdi/pkg/util/apiutil"
)

// GrafanaSessionCookie is the name of the cookie used to carry a kvdi session
// token on requests the grafana sidecar makes for its own assets and API.
const GrafanaSessionCookie = "kvdi-grafana-session"

// ValidateGrafanaSession requires a valid kvdi session on requests to the
// grafana sidecar, which itself runs with anonymous access enabled. The token
// may arrive in the session header, in a token query argument (the initial
// iframe navigation), or in a cookie scoped to the grafana path. Presenting the
// token as a query argument sets that cookie so the sidecar's subsequent
// requests for assets and datasource queries are authenticated as well. The
// token is verified on every request, so the cookie grants nothing beyond the
// lifetime of the session it carries.
func (d *desktopAPI) ValidateGrafanaSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var authToken string
		var fromQuery bool

		if authToken = r.Header.Get(TokenHeader); authToken == "" {
			if keys, ok := r.URL.Query()["token"]; ok && keys[0] != "" {
				authToken = keys[0]
				fromQuery = true
			} else if cookie, err := r.Cookie(GrafanaSessionCookie); err == nil {
				authToken = cookie.Value
			}
		}

		if authToken == "" {
			apiutil.ReturnAPIForbidden(nil, "No token provided in request", w)
			return
		}

		jwtSecret, err := d.secrets.ReadSecret(v1.JWTSecretKey, true)
		if err != nil {
			apiutil.ReturnAPIError(err, w)
			return
		}

		session, err := apiutil.DecodeAndVerifyJWT(jwtSecret, authToken)
		if err != nil {
			apiutil.ReturnAPIUnauthorized(nil, err.Error(), w)
			return
		}

		if !session.Authorized {
			apiutil.ReturnAPIForbidden(nil, "User session is not authorized", w)
			return
		}

		if fromQuery {
			http.SetCookie(w, &http.Cookie{
				Name:     GrafanaSessionCookie,
				Value:    authToken,
				Path:     "/api/grafana",
				HttpOnly: true,
				Secure:   !d.vdiCluster.AppTLSIsDisabled(),
				SameSite: http.SameSiteStrictMode,
			})
		}

		apiutil.SetRequestUserSession(r, session)

		next.ServeHTTP(w, r)
	})
}
