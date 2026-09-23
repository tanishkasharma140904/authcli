package auth

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	MinUsernameLen = 3
	MaxUsernameLen = 32
	MinPasswordLen = 8
	// MaxPasswordBytes is bcrypt's input limit; longer input would be
	// silently truncated by most implementations, so we reject it.
	MaxPasswordBytes = 72
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// A small blocklist of passwords that satisfy the length rule but are
// among the most common in breach corpora (NIST SP 800-63B §5.1.1.2).
var commonPasswords = map[string]bool{
	"password": true, "password1": true, "password123": true, "12345678": true,
	"123456789": true, "1234567890": true, "qwerty123": true, "qwertyuiop": true,
	"11111111": true, "iloveyou": true, "letmein1": true, "welcome1": true,
	"admin123": true, "abc12345": true, "passw0rd": true, "00000000": true,
}

// NormalizeUsername trims whitespace and lower-cases the username so that
// "Alice" and "alice" are the same account.
func NormalizeUsername(u string) string {
	return strings.ToLower(strings.TrimSpace(u))
}

// ValidateUsername checks an already-normalized username.
func ValidateUsername(u string) error {
	n := utf8.RuneCountInString(u)
	switch {
	case n < MinUsernameLen || n > MaxUsernameLen:
		return invalid("username must be %d-%d characters long", MinUsernameLen, MaxUsernameLen)
	case !usernamePattern.MatchString(u):
		return invalid("username may only contain letters, digits, '.', '_' and '-', and must start with a letter or digit")
	}
	return nil
}

// ValidatePassword enforces the password policy for a given username.
func ValidatePassword(username, password string) error {
	switch {
	case utf8.RuneCountInString(password) < MinPasswordLen:
		return invalid("password must be at least %d characters long", MinPasswordLen)
	case len(password) > MaxPasswordBytes:
		return invalid("password must be at most %d bytes long", MaxPasswordBytes)
	case strings.TrimSpace(password) == "":
		return invalid("password must not be only whitespace")
	case strings.EqualFold(password, username):
		return invalid("password must not be the same as the username")
	case commonPasswords[strings.ToLower(password)]:
		return invalid("that password is too common; please choose another")
	}
	return nil
}
