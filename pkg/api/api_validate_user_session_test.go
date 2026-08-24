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
	"net/url"
	"testing"
	"time"

	"github.com/kvdi/kvdi/pkg/types"
	"github.com/kvdi/kvdi/pkg/util/apiutil"

	"github.com/xlzd/gotp"
)

func mustUnauthorizedToken(t *testing.T) string {
	t.Helper()

	_, token, err := apiutil.GenerateJWT(
		[]byte("supersecret"),
		&types.AuthResult{User: &types.VDIUser{Name: "admin"}},
		false,
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestUnauthorizedSessionPostAllowlist(t *testing.T) {
	server, addr, _, err := NewTestAPI()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	token := mustUnauthorizedToken(t)
	tests := []struct {
		name       string
		path       string
		body       string
		statusCode int
	}{
		{
			name:       "rejects other post routes",
			path:       "/api/sessions",
			body:       `{"template":"test-template"}`,
			statusCode: http.StatusForbidden,
		},
		{
			name:       "allows authorize",
			path:       "/api/authorize",
			body:       `{"otp":"000000"}`,
			statusCode: http.StatusOK,
		},
		{
			name:       "allows logout",
			path:       "/api/logout",
			statusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(
				http.MethodPost,
				addr+tt.path,
				bytes.NewBufferString(tt.body),
			)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(TokenHeader, token)
			req.Header.Set("Content-Type", "application/json")

			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != tt.statusCode {
				t.Fatalf("request returned status %d, want %d", res.StatusCode, tt.statusCode)
			}
		})
	}
}

func TestRefreshTokenHonorsMFA(t *testing.T) {
	server, addr, password, err := NewTestAPI()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client := &http.Client{}
	loginBody, err := json.Marshal(&types.LoginRequest{
		Username: "admin",
		Password: password,
	})
	if err != nil {
		t.Fatal(err)
	}
	loginReq, err := http.NewRequest(
		http.MethodPost,
		addr+"/api/login",
		bytes.NewReader(loginBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	loginReq.Header.Set("Content-Type", "application/json")
	loginRes, err := client.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	defer loginRes.Body.Close()
	if loginRes.StatusCode != http.StatusOK {
		t.Fatalf("login returned status %d", loginRes.StatusCode)
	}

	loginSession := &types.SessionResponse{}
	if err := json.NewDecoder(loginRes.Body).Decode(loginSession); err != nil {
		t.Fatal(err)
	}
	var refreshCookie *http.Cookie
	for _, cookie := range loginRes.Cookies() {
		if cookie.Name == RefreshTokenCookie {
			refreshCookie = cookie
			break
		}
	}
	if refreshCookie == nil {
		t.Fatal("login did not set a refresh token cookie")
	}

	enableBody := bytes.NewBufferString(`{"enabled":true}`)
	enableReq, err := http.NewRequest(
		http.MethodPut,
		addr+"/api/users/admin/mfa",
		enableBody,
	)
	if err != nil {
		t.Fatal(err)
	}
	enableReq.Header.Set(TokenHeader, loginSession.Token)
	enableReq.Header.Set("Content-Type", "application/json")
	enableRes, err := client.Do(enableReq)
	if err != nil {
		t.Fatal(err)
	}
	defer enableRes.Body.Close()
	if enableRes.StatusCode != http.StatusOK {
		t.Fatalf("enabling MFA returned status %d", enableRes.StatusCode)
	}

	mfaResponse := &types.MFAResponse{}
	if err := json.NewDecoder(enableRes.Body).Decode(mfaResponse); err != nil {
		t.Fatal(err)
	}
	provisioningURI, err := url.Parse(mfaResponse.ProvisioningURI)
	if err != nil {
		t.Fatal(err)
	}
	secret := provisioningURI.Query().Get("secret")
	if secret == "" {
		t.Fatal("MFA provisioning URI did not include a secret")
	}

	verifyBody, err := json.Marshal(&types.AuthorizeRequest{
		OTP: gotp.NewDefaultTOTP(secret).Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyReq, err := http.NewRequest(
		http.MethodPut,
		addr+"/api/users/admin/mfa/verify",
		bytes.NewReader(verifyBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	verifyReq.Header.Set(TokenHeader, loginSession.Token)
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyRes, err := client.Do(verifyReq)
	if err != nil {
		t.Fatal(err)
	}
	defer verifyRes.Body.Close()
	if verifyRes.StatusCode != http.StatusOK {
		t.Fatalf("verifying MFA returned status %d", verifyRes.StatusCode)
	}

	refreshReq, err := http.NewRequest(http.MethodGet, addr+"/api/refresh_token", nil)
	if err != nil {
		t.Fatal(err)
	}
	refreshReq.AddCookie(refreshCookie)
	refreshRes, err := client.Do(refreshReq)
	if err != nil {
		t.Fatal(err)
	}
	defer refreshRes.Body.Close()
	if refreshRes.StatusCode != http.StatusOK {
		t.Fatalf("refresh returned status %d", refreshRes.StatusCode)
	}

	refreshedSession := &types.SessionResponse{}
	if err := json.NewDecoder(refreshRes.Body).Decode(refreshedSession); err != nil {
		t.Fatal(err)
	}
	if refreshedSession.Authorized {
		t.Fatal("refresh returned an authorized session for an MFA-required user")
	}
}
