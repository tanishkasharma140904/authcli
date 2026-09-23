package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestValidateTOTP(t *testing.T) {
	setup, err := generateTOTP("Test", "alice")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	step := now.Unix() / totpPeriod

	code, _ := totp.GenerateCode(setup.Secret, now)
	if c, ok := validateTOTP(setup.Secret, code, now, 0); !ok || c != step {
		t.Errorf("current code: ok=%v counter=%d want %d", ok, c, step)
	}
	if _, ok := validateTOTP(setup.Secret, code[:3]+" "+code[3:], now, 0); !ok {
		t.Error("code with a space should be accepted")
	}

	// Clock drift of one step either way is tolerated; two steps is not.
	if _, ok := validateTOTP(setup.Secret, code, now.Add(30*time.Second), 0); !ok {
		t.Error("code from previous step should be accepted")
	}
	if _, ok := validateTOTP(setup.Secret, code, now.Add(90*time.Second), 0); ok {
		t.Error("code from 3 steps ago must be rejected")
	}

	// Replay protection: a step at or below lastCounter is refused.
	if _, ok := validateTOTP(setup.Secret, code, now, step); ok {
		t.Error("already-used step must be rejected")
	}

	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := validateTOTP(setup.Secret, bad, now, 0); ok {
			t.Errorf("malformed code %q accepted", bad)
		}
	}
}
