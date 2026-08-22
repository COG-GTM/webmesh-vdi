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
	"time"

	v1 "github.com/kvdi/kvdi/apis/meta/v1"
	"github.com/kvdi/kvdi/pkg/util/apiutil"
)

// GrafanaTokenCookie is the cookie used to carry a user's access token on
// requests the browser makes for the embedded Grafana dashboards. The Grafana
// UI issues its own requests for assets and datasource queries, and those
// cannot carry the session token header.
const GrafanaTokenCookie = "grafanaToken"

// GrafanaProxyPath is the path the Grafana sidecar is proxied on.
const GrafanaProxyPath = "/api/grafana"

// ValidateGrafanaSession requires an authorized user session before a request
// is proxied to the Grafana sidecar. The token may be supplied in the session
// token header, in a token query argument, or in the cookie set by this
// middleware when a token is provided by query argument.
func (d *desktopAPI) ValidateGrafanaSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authToken, fromQuery := grafanaTokenFromRequest(r)
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
			// Hand the token back as a cookie scoped to the proxy so that the
			// requests Grafana makes on its own are authenticated as well.
			http.SetCookie(w, &http.Cookie{
				Name:     GrafanaTokenCookie,
				Value:    authToken,
				Path:     GrafanaProxyPath,
				Expires:  time.Unix(session.ExpiresAt, 0),
				HttpOnly: true,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteStrictMode,
			})
		}

		apiutil.SetRequestUserSession(r, session)

		next.ServeHTTP(w, r)
	})
}

// grafanaTokenFromRequest returns the access token in the request and whether
// it was provided as a query argument.
func grafanaTokenFromRequest(r *http.Request) (token string, fromQuery bool) {
	if token = r.Header.Get(TokenHeader); token != "" {
		return token, false
	}
	if keys, ok := r.URL.Query()["token"]; ok && keys[0] != "" {
		return keys[0], true
	}
	if cookie, err := r.Cookie(GrafanaTokenCookie); err == nil && cookie != nil {
		return cookie.Value, false
	}
	return "", false
}
