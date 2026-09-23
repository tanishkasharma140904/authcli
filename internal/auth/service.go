// Package auth implements registration, login with optional TOTP 2FA,
// account lockout and session management on top of package store.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/tanishkasharma140904/authcli/internal/store"
)

// pendingLoginTTL bounds how long a user may take to enter their TOTP code
// after the password step succeeded.
const pendingLoginTTL = 3 * time.Minute

// Config controls security policy.
type Config struct {
	SessionTimeout    time.Duration
	MaxFailedAttempts int
	LockoutDuration   time.Duration
	TOTPIssuer        string
	BcryptCost        int
}

// Service is the authentication API used by the CLI.
type Service struct {
	store *store.Store
	cfg   Config
	now   func() time.Time
	// dummyHash is compared against when the username does not exist, so
	// that response time does not reveal whether an account exists.
	dummyHash []byte
}

// Option customizes a Service.
type Option func(*Service)

// WithClock overrides the time source (used by tests).
func WithClock(now func() time.Time) Option {
	return func(s *Service) { s.now = now }
}

// NewService builds a Service.
func NewService(st *store.Store, cfg Config, opts ...Option) (*Service, error) {
	s := &Service{store: st, cfg: cfg, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	h, err := bcrypt.GenerateFromPassword([]byte("timing-equalizer-not-a-real-password"), cfg.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("init dummy hash: %w", err)
	}
	s.dummyHash = h
	return s, nil
}

// Now returns the service's current time.
func (s *Service) Now() time.Time { return s.now() }

// Session is an authenticated login. Token is a random secret; only its
// SHA-256 hash is stored in the database.
type Session struct {
	Token           string
	UserID          int64
	Username        string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	PreviousLoginAt *time.Time // the login before this one, if any
}

// Expired reports whether the session is past its expiry at time t.
func (s *Session) Expired(t time.Time) bool { return !t.Before(s.ExpiresAt) }

// UserDetails is what whoami displays.
type UserDetails struct {
	Username         string
	RegisteredAt     time.Time
	MFAEnabled       bool
	SessionExpiresAt time.Time
	LastLoginAt      *time.Time
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// Register creates a new account after validating username and password.
func (s *Service) Register(ctx context.Context, username, password string) (*store.User, error) {
	username = NormalizeUsername(username)
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	if err := ValidatePassword(username, password); err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	u, err := s.store.CreateUser(ctx, username, string(hash), s.now())
	if errors.Is(err, store.ErrUsernameTaken) {
		return nil, ErrUsernameTaken
	}
	return u, err
}

// ---------------------------------------------------------------------------
// Login (two steps: password, then TOTP if enabled)
// ---------------------------------------------------------------------------

// PendingLogin is the state between a successful password check and the
// TOTP step. It is single-use and expires after pendingLoginTTL.
type PendingLogin struct {
	userID      int64
	expiresAt   time.Time
	used        bool
	MFARequired bool
}

// BeginLogin verifies username and password. When it succeeds the caller
// must call CompleteLogin, passing the TOTP code if MFARequired is set.
func (s *Service) BeginLogin(ctx context.Context, username, password string) (*PendingLogin, error) {
	u, err := s.store.GetUserByUsername(ctx, NormalizeUsername(username))
	if errors.Is(err, store.ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password))
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	now := s.now()
	if lockErr := s.checkLocked(u, now); lockErr != nil {
		return nil, lockErr
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return nil, s.registerFailure(ctx, u.ID, ErrInvalidCredentials)
	}
	return &PendingLogin{
		userID:      u.ID,
		expiresAt:   now.Add(pendingLoginTTL),
		MFARequired: u.TOTPEnabled,
	}, nil
}

// CompleteLogin finishes a login started by BeginLogin, verifying the TOTP
// code when 2FA is enabled, and opens a new session.
func (s *Service) CompleteLogin(ctx context.Context, p *PendingLogin, totpCode string) (*Session, error) {
	now := s.now()
	if p == nil || p.used || now.After(p.expiresAt) {
		return nil, ErrLoginExpired
	}
	p.used = true

	// Re-read the user: state may have changed since the password step.
	u, err := s.store.GetUserByID(ctx, p.userID)
	if err != nil {
		return nil, err
	}
	if lockErr := s.checkLocked(u, now); lockErr != nil {
		return nil, lockErr
	}

	if u.TOTPEnabled {
		counter, ok := validateTOTP(u.TOTPSecret, totpCode, now, u.TOTPLastCounter)
		if !ok {
			return nil, s.registerFailure(ctx, u.ID, ErrInvalidTOTP)
		}
		if err := s.store.UpdateTOTPCounter(ctx, u.ID, counter); err != nil {
			return nil, err
		}
	}

	previous := u.LastLoginAt
	if err := s.store.RecordSuccessfulLogin(ctx, u.ID, now); err != nil {
		return nil, err
	}

	token, err := newToken()
	if err != nil {
		return nil, err
	}
	sess := &Session{
		Token:           token,
		UserID:          u.ID,
		Username:        u.Username,
		CreatedAt:       now,
		ExpiresAt:       now.Add(s.cfg.SessionTimeout),
		PreviousLoginAt: previous,
	}
	if err := s.store.CreateSession(ctx, u.ID, hashToken(token), sess.CreatedAt, sess.ExpiresAt); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *Service) checkLocked(u *store.User, now time.Time) error {
	if u.LockedUntil != nil && now.Before(*u.LockedUntil) {
		return &LockedError{Until: *u.LockedUntil}
	}
	return nil
}

// registerFailure counts a failed attempt and locks the account once the
// threshold is reached. It returns the error to show the user.
func (s *Service) registerFailure(ctx context.Context, userID int64, cause error) error {
	n, err := s.store.IncrementFailedAttempts(ctx, userID)
	if err != nil {
		return err
	}
	if n >= s.cfg.MaxFailedAttempts {
		until := s.now().Add(s.cfg.LockoutDuration)
		if err := s.store.LockUser(ctx, userID, until); err != nil {
			return err
		}
		return &LockedError{Until: until}
	}
	return cause
}

// ---------------------------------------------------------------------------
// Session-protected operations
// ---------------------------------------------------------------------------

// authorize checks that sess is still valid in the database and returns
// the current user row.
func (s *Service) authorize(ctx context.Context, sess *Session) (*store.User, error) {
	if sess == nil {
		return nil, ErrSessionExpired
	}
	row, err := s.store.GetSessionByTokenHash(ctx, hashToken(sess.Token))
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrSessionExpired
	}
	if err != nil {
		return nil, err
	}
	if row.RevokedAt != nil || !s.now().Before(row.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	u, err := s.store.GetUserByID(ctx, row.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrSessionExpired
	}
	return u, err
}

// WhoAmI returns details about the logged-in user.
func (s *Service) WhoAmI(ctx context.Context, sess *Session) (*UserDetails, error) {
	u, err := s.authorize(ctx, sess)
	if err != nil {
		return nil, err
	}
	return &UserDetails{
		Username:         u.Username,
		RegisteredAt:     u.CreatedAt,
		MFAEnabled:       u.TOTPEnabled,
		SessionExpiresAt: sess.ExpiresAt,
		LastLoginAt:      sess.PreviousLoginAt,
	}, nil
}

// Logout revokes the session. Logging out an already-expired session is
// not an error.
func (s *Service) Logout(ctx context.Context, sess *Session) error {
	if sess == nil {
		return nil
	}
	return s.store.RevokeSession(ctx, hashToken(sess.Token), s.now())
}

// BeginEnableTOTP generates a fresh TOTP secret. Nothing is stored until
// ConfirmEnableTOTP proves the user's authenticator app has it.
func (s *Service) BeginEnableTOTP(ctx context.Context, sess *Session) (*TOTPSetup, error) {
	u, err := s.authorize(ctx, sess)
	if err != nil {
		return nil, err
	}
	if u.TOTPEnabled {
		return nil, ErrMFAAlreadyEnabled
	}
	setup, err := generateTOTP(s.cfg.TOTPIssuer, u.Username)
	if err != nil {
		return nil, fmt.Errorf("generate TOTP secret: %w", err)
	}
	return setup, nil
}

// ConfirmEnableTOTP verifies a code generated from setup.Secret and, if it
// is valid, turns on 2FA for the account.
func (s *Service) ConfirmEnableTOTP(ctx context.Context, sess *Session, setup *TOTPSetup, code string) error {
	u, err := s.authorize(ctx, sess)
	if err != nil {
		return err
	}
	if u.TOTPEnabled {
		return ErrMFAAlreadyEnabled
	}
	counter, ok := validateTOTP(setup.Secret, code, s.now(), 0)
	if !ok {
		return ErrInvalidTOTP
	}
	return s.store.EnableTOTP(ctx, u.ID, setup.Secret, counter)
}

// DisableTOTP turns off 2FA. It requires both the password and a current
// code so a briefly unattended session cannot silently weaken the account.
func (s *Service) DisableTOTP(ctx context.Context, sess *Session, password, code string) error {
	u, err := s.authorize(ctx, sess)
	if err != nil {
		return err
	}
	if !u.TOTPEnabled {
		return ErrMFANotEnabled
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return ErrIncorrectPassword
	}
	if _, ok := validateTOTP(u.TOTPSecret, code, s.now(), u.TOTPLastCounter); !ok {
		return ErrInvalidTOTP
	}
	return s.store.DisableTOTP(ctx, u.ID)
}

// MFAEnabled reports whether the logged-in user has 2FA turned on.
func (s *Service) MFAEnabled(ctx context.Context, sess *Session) (bool, error) {
	u, err := s.authorize(ctx, sess)
	if err != nil {
		return false, err
	}
	return u.TOTPEnabled, nil
}

// CleanupSessions deletes expired and revoked sessions.
func (s *Service) CleanupSessions(ctx context.Context) error {
	_, err := s.store.DeleteStaleSessions(ctx, s.now())
	return err
}

// newToken returns 256 bits of randomness, base64url-encoded.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
