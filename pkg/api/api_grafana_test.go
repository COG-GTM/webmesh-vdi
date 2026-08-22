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
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kvdi/kvdi/pkg/types"
)

// mustLogin retrieves an access token from a running test API.
func mustLogin(t *testing.T, addr, password string) string {
	t.Helper()
	body, err := json.Marshal(&types.LoginRequest{Username: "admin", Password: password})
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Post(addr+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatal("Expected to be able to login, got status", res.StatusCode)
	}
	session := &types.SessionResponse{}
	if err := json.NewDecoder(res.Body).Decode(session); err != nil {
		t.Fatal(err)
	}
	return session.Token
}

// TestGrafanaToken checks that the Grafana proxy requires a session and that
// its path prefix does not shadow the token exchange route.
func TestGrafanaToken(t *testing.T) {
	srvr, addr, passw, err := NewTestAPI()
	if err != nil {
		t.Fatal(err)
	}
	defer srvr.Close()

	// the proxy should not serve anonymous requests
	res, err := http.Get(addr + GrafanaProxyPath + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Error("Expected forbidden on anonymous grafana request, got", res.StatusCode)
	}

	// the token exchange route should hand back a cookie scoped to the proxy
	req, err := http.NewRequest(http.MethodGet, addr+"/api/grafana_token", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(TokenHeader, mustLogin(t, addr, passw))
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatal("Expected to be able to exchange the session token, got", res.StatusCode)
	}

	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == GrafanaTokenCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("Expected a grafana token cookie in the response")
	}
	if cookie.Path != GrafanaProxyPath {
		t.Error("Expected cookie scoped to the grafana proxy, got", cookie.Path)
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Error("Expected an HttpOnly, SameSite=Strict cookie, got", cookie)
	}
}
