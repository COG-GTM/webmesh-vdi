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
)

// GrafanaSessionCookie is the name of the cookie used to carry a session token
// on requests made from inside the embedded grafana iframe.
const GrafanaSessionCookie = "kvdi-grafana-token"

// requestIsHTTPS reports whether the request reached the client over HTTPS,
// accounting for TLS being terminated by a proxy in front of the app.
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		return false
	}
	// the header may be a comma separated list, the first value is the client
	return strings.EqualFold(strings.TrimSpace(strings.Split(proto, ",")[0]), "https")
}

// grafanaSession stores the session token from the iframe URL in a cookie scoped
// to the grafana proxy. The assets and API calls grafana makes from inside the
// iframe cannot set the session header themselves, so the cookie is what keeps
// them authenticated. The token is stripped from the request before it is
// forwarded to the sidecar.
func grafanaSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if token := query.Get("token"); token != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     GrafanaSessionCookie,
				Value:    token,
				Path:     "/api/grafana",
				HttpOnly: true,
				Secure:   requestIsHTTPS(r),
				SameSite: http.SameSiteStrictMode,
			})
			query.Del("token")
			r.URL.RawQuery = query.Encode()
		}
		next.ServeHTTP(w, r)
	})
}
