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

// GrafanaTokenCookie is the name of the cookie used to carry the session token
// on requests the Grafana dashboards make for their own assets.
const GrafanaTokenCookie = "kvdi-grafana-token"

// GrafanaProxyPath is the path prefix the Grafana dashboards are served from.
const GrafanaProxyPath = "/api/grafana"

// getRequestToken extracts the session token from the request headers or, when
// absent, the token query argument.
func getRequestToken(r *http.Request) string {
	if authToken := r.Header.Get(TokenHeader); authToken != "" {
		return authToken
	}
	// the websocket route does not receive request headers from noVNC, so the token is passed
	// as a query argument. This effectively gives that option to all routes.
	if keys, ok := r.URL.Query()["token"]; ok {
		return keys[0]
	}
	return ""
}

// SetGrafanaSessionCookie pins the session token of the request to a cookie
// scoped to the Grafana proxy. The dashboards are loaded in an iframe and fetch
// their own assets, and neither can set the session header, so the UI calls this
// route to authenticate them. It is called again while the page is open to keep
// the cookie in step with token renewals.
func (d *desktopAPI) SetGrafanaSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     GrafanaTokenCookie,
		Value:    getRequestToken(r),
		Path:     GrafanaProxyPath,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// ValidateUserSession retrieves the JWT token from the X-Session-Token and
// verifies that it is valid.
func (d *desktopAPI) ValidateUserSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get the auth token
		authToken := getRequestToken(r)

		if authToken == "" {
			if cookie, err := r.Cookie(GrafanaTokenCookie); err == nil {
				authToken = cookie.Value
			}
		}

		// if we don't have a token we can't proceed
		if authToken == "" {
			apiutil.ReturnAPIForbidden(nil, "No token provided in request", w)
			return
		}

		// retrieve the jwt secret
		jwtSecret, err := d.secrets.ReadSecret(v1.JWTSecretKey, true)
		if err != nil {
			apiutil.ReturnAPIError(err, w)
			return
		}

		// verify the token and retrieve the claims
		session, err := apiutil.DecodeAndVerifyJWT(jwtSecret, authToken)
		if err != nil {
			apiutil.ReturnAPIUnauthorized(nil, err.Error(), w)
			return
		}

		// let requests to authorize a token with mfa to go through
		if !session.Authorized && apiutil.GetGorillaPath(r) != "/api/authorize" && r.Method != http.MethodPost {
			apiutil.ReturnAPIForbidden(nil, "User session is not authorized", w)
			return
		}

		// Set the request user object with a pointer to the decoded user session
		apiutil.SetRequestUserSession(r, session)

		// serve the next handler
		next.ServeHTTP(w, r)
	})
}
