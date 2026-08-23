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
	"net/http/httptest"
	"testing"
)

func TestStripSessionCredentials(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/grafana/?orgId=1&token=secret", nil)
	r.Header.Set(TokenHeader, "secret")
	r.AddCookie(&http.Cookie{Name: GrafanaTokenCookie, Value: "secret"})
	r.AddCookie(&http.Cookie{Name: "grafana_session", Value: "keep-me"})

	StripSessionCredentials(r)

	if got := r.Header.Get(TokenHeader); got != "" {
		t.Errorf("expected the session header to be removed, got %q", got)
	}
	if r.URL.Query().Has("token") {
		t.Errorf("expected the token query argument to be removed, got %q", r.URL.RawQuery)
	}
	if r.URL.Query().Get("orgId") != "1" {
		t.Errorf("expected other query arguments to be preserved, got %q", r.URL.RawQuery)
	}
	if _, err := r.Cookie(GrafanaTokenCookie); err == nil {
		t.Error("expected the session cookie to be removed")
	}
	cookie, err := r.Cookie("grafana_session")
	if err != nil {
		t.Fatalf("expected other cookies to be preserved: %s", err)
	}
	if cookie.Value != "keep-me" {
		t.Errorf("expected the cookie value to be preserved, got %q", cookie.Value)
	}
}
