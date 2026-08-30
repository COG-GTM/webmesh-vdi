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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kvdi/kvdi/pkg/types"
	"github.com/kvdi/kvdi/pkg/util/apiutil"
)

// mustNewUnauthorizedToken signs a JWT for the admin user that has not yet
// completed MFA verification.
func mustNewUnauthorizedToken(t *testing.T) string {
	t.Helper()
	_, token, err := apiutil.GenerateJWT([]byte("supersecret"), &types.AuthResult{
		User: &types.VDIUser{Name: "admin"},
	}, false, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func mustDo(t *testing.T, method, url, token, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(TokenHeader, token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, string(out)
}

// TestValidateUserSessionMFA checks that a token which has not completed MFA
// verification can only be used to authorize itself.
func TestValidateUserSessionMFA(t *testing.T) {
	srvr, opts := mustNewTestAPI(t)
	defer srvr.Close()

	token := mustNewUnauthorizedToken(t)

	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/sessions", `{"template":"test-template"}`},
		{http.MethodPost, "/api/users", `{"username":"evil","password":"evil","roles":["test-cluster-admin"]}`},
		{http.MethodPost, "/api/roles", `{"name":"evil"}`},
		{http.MethodGet, "/api/whoami", ""},
	} {
		code, body := mustDo(t, tc.method, opts.URL+tc.path, token, tc.body)
		if code != http.StatusForbidden || !strings.Contains(body, "User session is not authorized") {
			t.Errorf("Expected %s %s to be forbidden for an unauthorized session, got %d: %s", tc.method, tc.path, code, body)
		}
	}

	// the MFA verification route itself must remain reachable - the test user has
	// no MFA configured, so it hands back an authorized token
	code, body := mustDo(t, http.MethodPost, opts.URL+"/api/authorize", token, `{"otp":"000000"}`)
	if code != http.StatusOK {
		t.Fatalf("Expected POST /api/authorize to succeed with an unauthorized session, got %d: %s", code, body)
	}
	var res types.SessionResponse
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("Could not decode authorize response %q: %s", body, err)
	}
	claims, err := apiutil.DecodeAndVerifyJWT([]byte("supersecret"), res.Token)
	if err != nil {
		t.Fatalf("Could not verify the token returned by /api/authorize: %s", err)
	}
	if !claims.Authorized {
		t.Error("Expected the token returned by /api/authorize to be authorized")
	}
}
