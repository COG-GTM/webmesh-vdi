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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appv1 "github.com/kvdi/kvdi/apis/app/v1"
	v1 "github.com/kvdi/kvdi/apis/meta/v1"
	"github.com/kvdi/kvdi/pkg/secrets"
	"github.com/kvdi/kvdi/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newRefreshTestAPI(t *testing.T) *desktopAPI {
	t.Helper()
	scheme, err := buildScheme()
	if err != nil {
		t.Fatal(err)
	}
	api := &desktopAPI{clusterName: "test-cluster"}
	api.client = fake.NewFakeClientWithScheme(scheme)
	api.vdiCluster = &appv1.VDICluster{}
	api.vdiCluster.Name = "test-cluster"
	if err := api.client.Create(context.TODO(), api.vdiCluster); err != nil {
		t.Fatal(err)
	}
	api.secrets = secrets.GetSecretEngine(api.vdiCluster)
	if err := api.secrets.Setup(api.client, api.vdiCluster); err != nil {
		t.Fatal(err)
	}
	return api
}

func TestRefreshTokenLifecycle(t *testing.T) {
	api := newRefreshTestAPI(t)
	user := &types.VDIUser{Name: "alice"}

	token, err := api.generateRefreshToken(user)
	if err != nil {
		t.Fatal(err)
	}
	got, err := api.lookupRefreshToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if got != "alice" {
		t.Fatalf("expected alice, got %q", got)
	}
	// single-use
	if _, err := api.lookupRefreshToken(token); err == nil {
		t.Fatal("expected redeemed token to be rejected")
	}
}

func TestRefreshTokenExpiry(t *testing.T) {
	api := newRefreshTestAPI(t)
	expired, err := json.Marshal(&refreshTokenRecord{User: "alice", ExpiresAt: time.Now().Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string][]byte{
		"expired": expired,
		"legacy":  []byte("alice"),
	}
	if err := api.secrets.WriteSecretMap(v1.RefreshTokensSecretKey, tokens); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"expired", "legacy"} {
		if _, err := api.lookupRefreshToken(tok); err == nil {
			t.Fatalf("expected %s token to be rejected", tok)
		}
	}
	stored, err := api.secrets.ReadSecretMap(v1.RefreshTokensSecretKey, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 0 {
		t.Fatalf("expected expired tokens to be pruned, got %d", len(stored))
	}
}

func TestRevokeUserRefreshTokens(t *testing.T) {
	api := newRefreshTestAPI(t)
	aliceTok, err := api.generateRefreshToken(&types.VDIUser{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	bobTok, err := api.generateRefreshToken(&types.VDIUser{Name: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.revokeUserRefreshTokens("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := api.lookupRefreshToken(aliceTok); err == nil {
		t.Fatal("expected alice's token to be revoked")
	}
	if got, err := api.lookupRefreshToken(bobTok); err != nil || got != "bob" {
		t.Fatalf("expected bob's token to remain valid, got %q, %v", got, err)
	}
}

func TestRefreshTokenCookieAttributes(t *testing.T) {
	rr := httptest.NewRecorder()
	http.SetCookie(rr, newRefreshTokenCookie("abc", int(v1.RefreshTokenLifetime.Seconds())))
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie missing hardening attributes: %+v", c)
	}
	if c.Path != RefreshTokenCookiePath || c.MaxAge != int(v1.RefreshTokenLifetime.Seconds()) {
		t.Fatalf("unexpected path/max-age: %+v", c)
	}
}
