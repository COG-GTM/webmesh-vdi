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

// GrafanaTokenCookie is the cookie used to carry the access token on requests
// made from the metrics iframe. Grafana loads its own assets and issues its own
// XHRs, none of which can set the token header.
const GrafanaTokenCookie = "grafanaToken"

// grafanaProxyPath is the path the grafana proxy is served on.
const grafanaProxyPath = "/api/grafana"

// ValidateGrafanaSession ensures that requests to the grafana proxy carry a
// valid, authorized user session. The token can be provided in the session
// header, or in the cookie this handler sets on the first request that
// authenticates with the header.
func (d *desktopAPI) ValidateGrafanaSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authToken, fromCookie := getGrafanaAuthToken(r)
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

		if !fromCookie {
			// Scope the cookie to the proxy so grafana's own requests carry the
			// session along with them.
			http.SetCookie(w, &http.Cookie{
				Name:     GrafanaTokenCookie,
				Value:    authToken,
				Path:     grafanaProxyPath,
				HttpOnly: true,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteStrictMode,
			})
		}

		apiutil.SetRequestUserSession(r, session)
		next.ServeHTTP(w, r)
	})
}

// getGrafanaAuthToken returns the access token on the request and whether it
// was read from the grafana cookie.
func getGrafanaAuthToken(r *http.Request) (token string, fromCookie bool) {
	if token = r.Header.Get(TokenHeader); token != "" {
		return token, false
	}
	if cookie, err := r.Cookie(GrafanaTokenCookie); err == nil {
		return cookie.Value, true
	}
	return "", false
}
