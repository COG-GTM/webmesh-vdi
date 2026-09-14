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
)

func TestLoginThrottle(t *testing.T) {
	now := time.Now()
	th := newLoginThrottle()
	th.now = func() time.Time { return now }

	for i := 0; i < loginMaxFailures-1; i++ {
		th.recordFailure("admin", "10.0.0.1")
	}
	if locked, _ := th.isLocked("admin", "10.0.0.1"); locked {
		t.Fatal("expected no lockout before threshold")
	}

	th.recordFailure("admin", "10.0.0.1")
	if locked, remaining := th.isLocked("admin", "10.0.0.1"); !locked || remaining != loginBaseLockout {
		t.Fatalf("expected lockout of %s, got locked=%v remaining=%s", loginBaseLockout, locked, remaining)
	}
	// the username is locked from any address, and the address is locked for any user
	if locked, _ := th.isLocked("admin", "10.0.0.2"); !locked {
		t.Fatal("expected username lockout to apply across addresses")
	}
	if locked, _ := th.isLocked("other", "10.0.0.1"); !locked {
		t.Fatal("expected address lockout to apply across usernames")
	}
	if locked, _ := th.isLocked("other", "10.0.0.2"); locked {
		t.Fatal("unrelated user/address should not be locked")
	}

	// lockout doubles with each additional failure
	th.recordFailure("admin", "10.0.0.1")
	if _, remaining := th.isLocked("admin", "10.0.0.1"); remaining != 2*loginBaseLockout {
		t.Fatalf("expected lockout of %s, got %s", 2*loginBaseLockout, remaining)
	}

	// lockout expires
	now = now.Add(2*loginBaseLockout + time.Second)
	if locked, _ := th.isLocked("admin", "10.0.0.1"); locked {
		t.Fatal("expected lockout to expire")
	}

	// success clears the username history but not the address history
	th.recordSuccess("admin")
	if _, ok := th.failures["user:admin"]; ok {
		t.Fatal("expected user failures to be cleared on success")
	}
	if _, ok := th.failures["addr:10.0.0.1"]; !ok {
		t.Fatal("expected address failures to be retained on success")
	}

	// stale records are pruned
	now = now.Add(loginFailureWindow + time.Second)
	th.isLocked("admin", "10.0.0.1")
	if len(th.failures) != 0 {
		t.Fatalf("expected stale failures to be pruned, got %d", len(th.failures))
	}
}

func TestClientAddrIgnoresForwardedHeaders(t *testing.T) {
	var got string
	h := PeerAddrHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// simulate ProxyHeaders rewriting RemoteAddr from client-controlled headers
		r.RemoteAddr = r.Header.Get("X-Forwarded-For")
		got = clientAddrFromRequest(r)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	req.RemoteAddr = "10.0.0.5:4444"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set(PeerAddrHeader, "9.9.9.9:1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != "10.0.0.5" {
		t.Errorf("expected peer address 10.0.0.5, got %q", got)
	}
}
