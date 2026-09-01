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
	"strings"
	"time"

	v1 "github.com/kvdi/kvdi/apis/meta/v1"
	"github.com/kvdi/kvdi/pkg/util/apiutil"
)

// GrafanaTokenCookie is the name of the cookie used to hold the session token
// for requests to the grafana proxy.
const GrafanaTokenCookie = "kvdi-grafana-token"

// ValidateGrafanaSession verifies that requests to the grafana proxy carry a
// valid, authorized kvdi session. The token is taken from the session header,
// or from the cookie set on a previous request that carried the header. The
// cookie is what allows the sub-resources requested by the embedded grafana UI,
// which cannot set headers, to be authenticated.
func (d *desktopAPI) ValidateGrafanaSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var authToken string
		var fromHeader bool

		if authToken = r.Header.Get(TokenHeader); authToken != "" {
			fromHeader = true
		} else if cookie, err := r.Cookie(GrafanaTokenCookie); err == nil {
			authToken = cookie.Value
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

		if fromHeader {
			http.SetCookie(w, &http.Cookie{
				Name:     GrafanaTokenCookie,
				Value:    authToken,
				Path:     "/api/grafana",
				Expires:  time.Unix(session.ExpiresAt, 0),
				HttpOnly: true,
				Secure:   isHTTPS(r),
				SameSite: http.SameSiteStrictMode,
			})
		}

		next.ServeHTTP(w, r)
	})
}

// isHTTPS returns true if the request reached the server over TLS, either
// directly or through a terminating proxy.
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
