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

// grafanaProxyPath is the path the grafana dashboards are served on.
const grafanaProxyPath = "/api/grafana"

// GrafanaTokenCookie is the cookie carrying an already validated session token
// for the grafana proxy. The dashboards are loaded in an iframe, and the browser
// only sends the token on the initial navigation, not on the subresources
// grafana requests afterwards.
const GrafanaTokenCookie = "kvdi-grafana-token"

// requestIsTLS returns true when the request reached kvdi over TLS, either
// directly or through a proxy that terminated it.
func requestIsTLS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// grafanaTokenCookie builds the cookie carrying the given session token for the
// grafana proxy. An empty token expires the cookie.
func grafanaTokenCookie(r *http.Request, token string) *http.Cookie {
	cookie := &http.Cookie{
		Name:     GrafanaTokenCookie,
		Value:    token,
		Path:     grafanaProxyPath,
		HttpOnly: true,
		Secure:   requestIsTLS(r),
		SameSite: http.SameSiteStrictMode,
	}
	if token == "" {
		cookie.MaxAge = -1
	}
	return cookie
}

// ValidateGrafanaSession requires an authorized kvdi session on requests to the
// grafana proxy. The token can be provided in the session header, a token query
// argument, or the cookie set on a previously validated request. A token in the
// query is moved into the cookie with a redirect, so it is not carried on the
// requests grafana makes afterwards.
func (d *desktopAPI) ValidateGrafanaSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var authToken string
		var fromCookie, fromQuery bool

		if authToken = r.Header.Get(TokenHeader); authToken == "" {
			if keys, ok := r.URL.Query()["token"]; ok && len(keys) > 0 {
				authToken = keys[0]
				fromQuery = true
			}
		}
		if authToken == "" {
			if cookie, err := r.Cookie(GrafanaTokenCookie); err == nil {
				authToken = cookie.Value
				fromCookie = true
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

		if !fromCookie {
			http.SetCookie(w, grafanaTokenCookie(r, authToken))
		}

		if fromQuery {
			redirect := *r.URL
			query := redirect.Query()
			query.Del("token")
			redirect.RawQuery = query.Encode()
			http.Redirect(w, r, redirect.RequestURI(), http.StatusFound)
			return
		}

		apiutil.SetRequestUserSession(r, session)
		next.ServeHTTP(w, r)
	})
}
