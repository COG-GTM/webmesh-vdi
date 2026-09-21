package common

import "testing"

func TestValidatePassword(t *testing.T) {
	valid := []string{"abcdefgh", "éééééééé", "a longer passphrase"}
	for _, p := range valid {
		if err := ValidatePassword(p); err != nil {
			t.Errorf("expected %q to be valid, got: %v", p, err)
		}
	}
	invalid := []string{"", "abcdefg", "ééééééé", " abcdefgh", "abcdefgh "}
	for _, p := range invalid {
		if err := ValidatePassword(p); err == nil {
			t.Errorf("expected %q to be rejected", p)
		}
	}
}
