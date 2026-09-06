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
	"crypto/subtle"
	"sync"
	"time"

	"github.com/xlzd/gotp"
)

const (
	// otpMaxFailures is the number of consecutive invalid codes a user may submit
	// before further attempts are rejected for otpLockout.
	otpMaxFailures = 5
	// otpLockout is how long a user is locked out after otpMaxFailures.
	otpLockout = 5 * time.Minute
	// otpInterval is the time step used by gotp.NewDefaultTOTP.
	otpInterval = 30
)

type otpUserState struct {
	failures     int
	lockedUntil  time.Time
	lastUsedCode string
	lastUsedStep int64
}

// otpGuard enforces per-user throttling and single-use semantics for TOTP codes.
type otpGuard struct {
	mu    sync.Mutex
	users map[string]*otpUserState
	now   func() time.Time
}

func newOTPGuard() *otpGuard {
	return &otpGuard{users: make(map[string]*otpUserState), now: time.Now}
}

var mfaGuard = newOTPGuard()

// check verifies code against the user's TOTP secret. It returns ok=false when
// the code is wrong, has already been used in the current time step, or the
// user is currently locked out (locked=true in the latter case).
func (g *otpGuard) check(username, secret, code string) (ok bool, locked bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	st, exists := g.users[username]
	if !exists {
		st = &otpUserState{}
		g.users[username] = st
	}
	if now.Before(st.lockedUntil) {
		return false, true
	}

	step := now.Unix() / otpInterval
	expected := gotp.NewDefaultTOTP(secret).At(int(now.Unix()))
	match := subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1
	replayed := match && st.lastUsedStep == step && st.lastUsedCode == code

	if !match || replayed {
		st.failures++
		if st.failures >= otpMaxFailures {
			st.failures = 0
			st.lockedUntil = now.Add(otpLockout)
			return false, true
		}
		return false, false
	}

	st.failures = 0
	st.lockedUntil = time.Time{}
	st.lastUsedCode = code
	st.lastUsedStep = step
	return true, false
}
