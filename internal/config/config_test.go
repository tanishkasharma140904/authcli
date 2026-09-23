package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	c, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.SessionTimeout != 30*time.Minute || c.MaxFailedAttempts != 5 || c.LockoutDuration != 15*time.Minute {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if want := filepath.Join("data", ".authcli_history"); c.HistoryFile != want {
		t.Errorf("history file = %q, want %q", c.HistoryFile, want)
	}
}

func TestEnvAndFlagPrecedence(t *testing.T) {
	t.Setenv("AUTH_SESSION_TIMEOUT", "10m")
	t.Setenv("AUTH_MAX_FAILED_ATTEMPTS", "7")

	c, err := Load([]string{"-session-timeout", "5m"})
	if err != nil {
		t.Fatal(err)
	}
	if c.SessionTimeout != 5*time.Minute {
		t.Errorf("flag should override env: got %s", c.SessionTimeout)
	}
	if c.MaxFailedAttempts != 7 {
		t.Errorf("env should override default: got %d", c.MaxFailedAttempts)
	}
}

func TestInvalidValues(t *testing.T) {
	t.Setenv("AUTH_SESSION_TIMEOUT", "soon")
	if _, err := Load(nil); err == nil {
		t.Error("expected error for unparsable duration")
	}
	t.Setenv("AUTH_SESSION_TIMEOUT", "")
	if _, err := Load([]string{"-max-failed-attempts", "0"}); err == nil {
		t.Error("expected error for zero max attempts")
	}
}
