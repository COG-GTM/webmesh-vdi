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
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

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

	res, err := http.Get(addr + "/api/desktops/ws/default/example/status?token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "No token provided in request") {
		t.Fatal("websocket route with a valid query token was rejected by session validation")
	}

	res, err = http.Get(addr + "/api/desktops/ws/default/example/status")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("websocket route without a query token returned status %d", res.StatusCode)
	}
	body, err = io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "No token provided in request") {
		t.Fatalf("websocket route without a query token returned unexpected response: %s", body)
	}
}
