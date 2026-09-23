// Package config loads runtime settings from command-line flags, falling
// back to AUTH_* environment variables and then to built-in defaults.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Config holds all tunable settings.
type Config struct {
	DBPath            string
	HistoryFile       string
	SessionTimeout    time.Duration
	MaxFailedAttempts int
	LockoutDuration   time.Duration
	TOTPIssuer        string
	BcryptCost        int
}

// Load parses args (usually os.Args[1:]). Environment variables provide the
// defaults, so flags always win.
func Load(args []string) (Config, error) {
	var c Config
	var errs []error

	fs := flag.NewFlagSet("authcli", flag.ContinueOnError)
	fs.StringVar(&c.DBPath, "db", envString("AUTH_DB_PATH", "data/auth.db"),
		"path to the SQLite database file [AUTH_DB_PATH]")
	fs.StringVar(&c.HistoryFile, "history", envString("AUTH_HISTORY_FILE", ""),
		"command history file; defaults to .authcli_history next to the database [AUTH_HISTORY_FILE]")
	fs.DurationVar(&c.SessionTimeout, "session-timeout", envDuration("AUTH_SESSION_TIMEOUT", 30*time.Minute, &errs),
		"how long a login session stays valid [AUTH_SESSION_TIMEOUT]")
	fs.IntVar(&c.MaxFailedAttempts, "max-failed-attempts", envInt("AUTH_MAX_FAILED_ATTEMPTS", 5, &errs),
		"consecutive failed logins before the account is locked [AUTH_MAX_FAILED_ATTEMPTS]")
	fs.DurationVar(&c.LockoutDuration, "lockout-duration", envDuration("AUTH_LOCKOUT_DURATION", 15*time.Minute, &errs),
		"how long a locked account stays locked [AUTH_LOCKOUT_DURATION]")
	fs.StringVar(&c.TOTPIssuer, "totp-issuer", envString("AUTH_TOTP_ISSUER", "AuthCLI"),
		"issuer name shown in authenticator apps [AUTH_TOTP_ISSUER]")
	fs.IntVar(&c.BcryptCost, "bcrypt-cost", envInt("AUTH_BCRYPT_COST", 12, &errs),
		"bcrypt work factor [AUTH_BCRYPT_COST]")

	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if len(errs) > 0 {
		return c, errors.Join(errs...)
	}
	if c.HistoryFile == "" {
		c.HistoryFile = filepath.Join(filepath.Dir(c.DBPath), ".authcli_history")
	}
	return c, c.Validate()
}

// Validate rejects nonsensical settings.
func (c Config) Validate() error {
	switch {
	case c.DBPath == "":
		return errors.New("database path must not be empty")
	case c.SessionTimeout < time.Minute:
		return fmt.Errorf("session timeout must be at least 1m, got %s", c.SessionTimeout)
	case c.MaxFailedAttempts < 1:
		return fmt.Errorf("max failed attempts must be at least 1, got %d", c.MaxFailedAttempts)
	case c.LockoutDuration <= 0:
		return fmt.Errorf("lockout duration must be positive, got %s", c.LockoutDuration)
	case c.BcryptCost < bcrypt.MinCost || c.BcryptCost > bcrypt.MaxCost:
		return fmt.Errorf("bcrypt cost must be between %d and %d, got %d", bcrypt.MinCost, bcrypt.MaxCost, c.BcryptCost)
	case c.TOTPIssuer == "":
		return errors.New("TOTP issuer must not be empty")
	}
	return nil
}

func envString(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int, errs *[]error) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: invalid integer %q", key, v))
		return def
	}
	return n
}

func envDuration(key string, def time.Duration, errs *[]error) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: invalid duration %q (examples: 30m, 1h)", key, v))
		return def
	}
	return d
}
