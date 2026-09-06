package api

import (
	"testing"
	"time"

	"github.com/xlzd/gotp"
)

func TestOTPGuard(t *testing.T) {
	secret := gotp.RandomSecret(16)
	now := time.Unix(1_700_000_000, 0)
	g := newOTPGuard()
	g.now = func() time.Time { return now }
	valid := gotp.NewDefaultTOTP(secret).At(int(now.Unix()))

	if ok, locked := g.check("alice", secret, valid); !ok || locked {
		t.Fatalf("expected valid code to be accepted, got ok=%v locked=%v", ok, locked)
	}
	if ok, _ := g.check("alice", secret, valid); ok {
		t.Fatal("expected replayed code to be rejected")
	}

	for i := 0; i < otpMaxFailures-1; i++ {
		if _, locked := g.check("bob", secret, "000000"); locked {
			t.Fatalf("locked out too early after %d failures", i+2)
		}
	}
	if _, locked := g.check("bob", secret, "000000"); !locked {
		t.Fatal("expected lockout after max failures")
	}
	if ok, locked := g.check("bob", secret, valid); ok || !locked {
		t.Fatal("expected valid code to be rejected during lockout")
	}
	if ok, locked := g.check("alice", secret, valid); ok || locked {
		t.Fatal("lockout must not affect other users; replay should still be rejected")
	}

	now = now.Add(otpLockout + time.Second)
	valid = gotp.NewDefaultTOTP(secret).At(int(now.Unix()))
	if ok, locked := g.check("bob", secret, valid); !ok || locked {
		t.Fatalf("expected valid code accepted after lockout expiry, got ok=%v locked=%v", ok, locked)
	}
}
