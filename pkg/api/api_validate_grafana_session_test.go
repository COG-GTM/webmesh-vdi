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
	"time"

	"github.com/kvdi/kvdi/pkg/types"
	"github.com/kvdi/kvdi/pkg/util/apiutil"
)

func mustGrafanaTestToken(t *testing.T, addr, password string) string {
	t.Helper()

	body, err := json.Marshal(&types.LoginRequest{
		Username: "admin",
		Password: password,
		State:    "grafana-test",
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, addr+"/api/login", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login returned status %d", res.StatusCode)
	}

	session := &types.SessionResponse{}
	if err := json.NewDecoder(res.Body).Decode(session); err != nil {
		t.Fatal(err)
	}
	return session.Token
}

func TestGrafanaSessionMiddleware(t *testing.T) {
	server, addr, password, err := NewTestAPI()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	res, err := http.Get(addr + "/api/grafana/api/health")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("request without token returned status %d", res.StatusCode)
	}

	token := mustGrafanaTestToken(t, addr, password)
	req, err := http.NewRequest(http.MethodGet, addr+"/api/grafana/api/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(TokenHeader, token)

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized {
		t.Fatalf("request with valid token returned status %d", res.StatusCode)
	}

	var grafanaCookie *http.Cookie
	for _, cookie := range res.Cookies() {
		if cookie.Name == grafanaTokenCookie {
			grafanaCookie = cookie
			break
		}
	}
	if grafanaCookie == nil {
		t.Fatal("valid header request did not set Grafana session cookie")
	}
	if grafanaCookie.Value != token {
		t.Fatal("Grafana session cookie contains the wrong token")
	}
	if grafanaCookie.Path != "/api/grafana" {
		t.Fatalf("Grafana session cookie path is %q", grafanaCookie.Path)
	}
	if !grafanaCookie.HttpOnly {
		t.Fatal("Grafana session cookie is not HttpOnly")
	}
	if grafanaCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("Grafana session cookie SameSite is %v", grafanaCookie.SameSite)
	}
	if grafanaCookie.Secure {
		t.Fatal("Grafana session cookie is Secure for an HTTP request")
	}

	req, err = http.NewRequest(http.MethodGet, addr+"/api/grafana/api/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(grafanaCookie)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	for _, cookie := range res.Cookies() {
		if cookie.Name == grafanaTokenCookie {
			t.Fatal("valid cookie request reset the Grafana session cookie")
		}
	}

	req, err = http.NewRequest(http.MethodGet, addr+"/api/grafana/api/health?token="+token, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized {
		t.Fatalf("request with valid query token returned status %d", res.StatusCode)
	}

	_, unauthorizedToken, err := apiutil.GenerateJWT(
		[]byte("supersecret"),
		&types.AuthResult{User: &types.VDIUser{Name: "admin"}},
		false,
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	req, err = http.NewRequest(http.MethodGet, addr+"/api/grafana/api/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(TokenHeader, unauthorizedToken)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized session returned status %d", res.StatusCode)
	}
}
