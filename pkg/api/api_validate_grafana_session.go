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

	v1 "github.com/kvdi/kvdi/apis/meta/v1"
	"github.com/kvdi/kvdi/pkg/util/apiutil"
)

const grafanaTokenCookie = "kvdi-grafana-token"

// ValidateGrafanaSession retrieves and verifies the JWT token used by Grafana
// requests.
func (d *desktopAPI) ValidateGrafanaSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authToken := r.Header.Get(TokenHeader)
		fromHeader := authToken != ""
		if authToken == "" {
			if cookie, err := r.Cookie(grafanaTokenCookie); err == nil {
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

		apiutil.SetRequestUserSession(r, session)

		if fromHeader {
			http.SetCookie(w, &http.Cookie{
				Name:     grafanaTokenCookie,
				Value:    authToken,
				Path:     "/api/grafana",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				Secure:   requestIsSecure(r),
			})
		}

		next.ServeHTTP(w, r)
	})
}

func requestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	forwardedProto := strings.SplitN(r.Header.Get("X-Forwarded-Proto"), ",", 2)[0]
	return strings.EqualFold(strings.TrimSpace(forwardedProto), "https")
}
