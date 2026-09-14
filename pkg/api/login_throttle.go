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
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// loginMaxFailures is the number of consecutive failed login attempts for a
	// single username before further attempts are throttled.
	loginMaxFailures = 5
	// loginMaxAddrFailures is the threshold for a single client address. It is
	// deliberately much higher since many users may share one address (NAT,
	// LoadBalancer SNAT); it only exists to bound password spraying.
	loginMaxAddrFailures = 50
	// loginBaseLockout is the initial lockout duration once the failure
	// threshold is reached. It doubles for every additional failure, up to
	// loginMaxLockout.
	loginBaseLockout = 30 * time.Second
	loginMaxLockout  = 15 * time.Minute
	// loginFailureWindow is how long a failure record is kept without further
	// failures before it is discarded.
	loginFailureWindow = time.Hour
)

type loginFailure struct {
	count       int
	lastFailure time.Time
	lockedUntil time.Time
}

// loginThrottle tracks failed login attempts per username and per client
// address and imposes an exponentially increasing lockout after repeated
// failures.
type loginThrottle struct {
	mu       sync.Mutex
	failures map[string]*loginFailure
	now      func() time.Time
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{failures: make(map[string]*loginFailure), now: time.Now}
}

type loginThrottleKey struct {
	key       string
	threshold int
}

func loginThrottleKeys(username, clientAddr string) []loginThrottleKey {
	keys := make([]loginThrottleKey, 0, 2)
	if username != "" {
		keys = append(keys, loginThrottleKey{"user:" + strings.ToLower(username), loginMaxFailures})
	}
	if clientAddr != "" {
		keys = append(keys, loginThrottleKey{"addr:" + clientAddr, loginMaxAddrFailures})
	}
	return keys
}

// isLocked returns whether login attempts for the given username or client
// address are currently blocked, and for how much longer.
func (t *loginThrottle) isLocked(username, clientAddr string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.prune(now)
	var remaining time.Duration
	for _, k := range loginThrottleKeys(username, clientAddr) {
		if f, ok := t.failures[k.key]; ok && f.lockedUntil.After(now) {
			if d := f.lockedUntil.Sub(now); d > remaining {
				remaining = d
			}
		}
	}
	return remaining > 0, remaining
}

// recordFailure registers a failed login attempt.
func (t *loginThrottle) recordFailure(username, clientAddr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, k := range loginThrottleKeys(username, clientAddr) {
		f, ok := t.failures[k.key]
		if !ok {
			f = &loginFailure{}
			t.failures[k.key] = f
		}
		f.count++
		f.lastFailure = now
		if f.count >= k.threshold {
			lockout := loginBaseLockout << uint(f.count-k.threshold)
			if lockout > loginMaxLockout || lockout <= 0 {
				lockout = loginMaxLockout
			}
			f.lockedUntil = now.Add(lockout)
		}
	}
}

// recordSuccess clears the failure history for a username after a successful
// login. Per-address history is intentionally retained.
func (t *loginThrottle) recordSuccess(username string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if username != "" {
		delete(t.failures, "user:"+strings.ToLower(username))
	}
}

func (t *loginThrottle) prune(now time.Time) {
	for key, f := range t.failures {
		if now.Sub(f.lastFailure) > loginFailureWindow && !f.lockedUntil.After(now) {
			delete(t.failures, key)
		}
	}
}

// PeerAddrHeader is set by the server entrypoint to the TCP peer address of a
// request before any proxy-header handling rewrites RemoteAddr. It must never
// be trusted from a client, so the entrypoint always overwrites it.
const PeerAddrHeader = "X-Kvdi-Peer-Addr"

// PeerAddrHandler records the direct peer address of every request in
// PeerAddrHeader so throttling can use it even when RemoteAddr is later
// replaced from client-supplied forwarding headers.
func PeerAddrHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(PeerAddrHeader, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

// clientAddrFromRequest returns the client IP for a request. Only the direct
// peer address is used; forwarded headers are not trusted.
func clientAddrFromRequest(r *http.Request) string {
	addr := r.Header.Get(PeerAddrHeader)
	if addr == "" {
		addr = r.RemoteAddr
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
