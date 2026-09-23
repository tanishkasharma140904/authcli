package auth

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors returned by Service. Messages are safe to show to users.
var (
	// ErrInvalidCredentials deliberately does not say whether the username
	// or the password was wrong, to avoid leaking which usernames exist.
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrIncorrectPassword  = errors.New("incorrect password")
	ErrInvalidTOTP        = errors.New("invalid or expired authentication code")
	ErrUsernameTaken      = errors.New("that username is already taken")
	ErrSessionExpired     = errors.New("your session has expired; please log in again")
	ErrMFAAlreadyEnabled  = errors.New("two-factor authentication is already enabled")
	ErrMFANotEnabled      = errors.New("two-factor authentication is not enabled")
	ErrLoginExpired       = errors.New("login attempt timed out; please start again")
)

// LockedError reports that an account is temporarily locked.
type LockedError struct {
	Until time.Time
}

func (e *LockedError) Error() string {
	return fmt.Sprintf("account locked due to too many failed attempts; try again after %s",
		e.Until.Format(time.RFC3339))
}

// ValidationError reports bad user input (e.g. a weak password).
type ValidationError struct {
	Msg string
}

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}
