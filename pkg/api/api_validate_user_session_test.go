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
	"time"

	"github.com/gorilla/mux"
	"github.com/kvdi/kvdi/pkg/types"
	"github.com/kvdi/kvdi/pkg/util/apiutil"
)

func TestSessionQueryTokenRejectedOnNormalRoutes(t *testing.T) {
	server, addr, _, err := NewTestAPI()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	_, token, err := apiutil.GenerateJWT(
		[]byte("supersecret"),
		&types.AuthResult{User: &types.VDIUser{Name: "admin"}},
		true,
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}

	res, err := http.Get(addr + "/api/whoami?token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("normal route with query token returned status %d", res.StatusCode)
	}
}

func TestSessionQueryTokenAllowedOnWebsocketRoutes(t *testing.T) {
	router := mux.NewRouter()
	router.Path("/api/desktops/ws/{namespace}/{name}/status").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowsWebsocketQueryToken(r) {
			t.Error("websocket route was not recognized as allowing query tokens")
		}
	})

	req := httptest.NewRequest(
		http.MethodGet,
		"/api/desktops/ws/default/example/status?token=test-token",
		nil,
	)
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("websocket route returned status %d", res.Code)
	}
}
