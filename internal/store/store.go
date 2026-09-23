// Package store is the persistence layer: plain SQL over the users and
// sessions tables. It contains no business rules; those live in package auth.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrNotFound is returned when a requested row does not exist.
	ErrNotFound = errors.New("not found")
	// ErrUsernameTaken is returned when registering a duplicate username.
	ErrUsernameTaken = errors.New("username already exists")
)

// User is a row of the users table.
type User struct {
	ID              int64
	Username        string
	PasswordHash    string
	TOTPSecret      string // empty when 2FA has never been enabled
	TOTPEnabled     bool
	TOTPLastCounter int64
	FailedAttempts  int
	LockedUntil     *time.Time
	CreatedAt       time.Time
	LastLoginAt     *time.Time
}

// Session is a row of the sessions table.
type Session struct {
	ID        int64
	TokenHash string
	UserID    int64
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Store wraps a *sql.DB with typed queries.
type Store struct {
	db *sql.DB
}

// New returns a Store backed by db.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

const userColumns = `id, username, password_hash, totp_secret, totp_enabled, totp_last_counter,
	failed_attempts, locked_until, created_at, last_login_at`

// CreateUser inserts a new user and returns it.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash string, createdAt time.Time) (*User, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)`,
		username, passwordHash, createdAt.Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, ErrUsernameTaken
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}
	return s.GetUserByID(ctx, id)
}

// GetUserByUsername looks a user up case-insensitively.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE username = ?`, username)
	return scanUser(row)
}

// GetUserByID looks a user up by primary key.
func (s *Store) GetUserByID(ctx context.Context, id int64) (*User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	return scanUser(row)
}

// IncrementFailedAttempts bumps the consecutive-failure counter and returns
// the new value.
func (s *Store) IncrementFailedAttempts(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ? RETURNING failed_attempts`,
		userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("increment failed attempts: %w", err)
	}
	return n, nil
}

// LockUser locks the account until the given time and resets the failure
// counter so that a fresh set of attempts is allowed once the lock expires.
func (s *Store) LockUser(ctx context.Context, userID int64, until time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET locked_until = ?, failed_attempts = 0 WHERE id = ?`,
		until.Unix(), userID)
	if err != nil {
		return fmt.Errorf("lock user: %w", err)
	}
	return nil
}

// RecordSuccessfulLogin clears lockout state and stamps the login time.
func (s *Store) RecordSuccessfulLogin(ctx context.Context, userID int64, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?`,
		at.Unix(), userID)
	if err != nil {
		return fmt.Errorf("record login: %w", err)
	}
	return nil
}

// EnableTOTP stores the TOTP secret and turns 2FA on. counter is the time
// step of the code used to confirm enrollment, so it cannot be replayed.
func (s *Store) EnableTOTP(ctx context.Context, userID int64, secret string, counter int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_last_counter = ? WHERE id = ?`,
		secret, counter, userID)
	if err != nil {
		return fmt.Errorf("enable totp: %w", err)
	}
	return nil
}

// DisableTOTP turns 2FA off and discards the secret.
func (s *Store) DisableTOTP(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_counter = 0 WHERE id = ?`,
		userID)
	if err != nil {
		return fmt.Errorf("disable totp: %w", err)
	}
	return nil
}

// UpdateTOTPCounter records the most recently accepted TOTP time step.
func (s *Store) UpdateTOTPCounter(ctx context.Context, userID, counter int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_last_counter = ? WHERE id = ?`, counter, userID)
	if err != nil {
		return fmt.Errorf("update totp counter: %w", err)
	}
	return nil
}

// CreateSession inserts a new session row.
func (s *Store) CreateSession(ctx context.Context, userID int64, tokenHash string, createdAt, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		tokenHash, userID, createdAt.Unix(), expiresAt.Unix())
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// GetSessionByTokenHash fetches a session by the hash of its token.
func (s *Store) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	var (
		sess             Session
		created, expires int64
		revoked          sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, token_hash, user_id, created_at, expires_at, revoked_at FROM sessions WHERE token_hash = ?`,
		tokenHash).Scan(&sess.ID, &sess.TokenHash, &sess.UserID, &created, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	sess.CreatedAt = time.Unix(created, 0)
	sess.ExpiresAt = time.Unix(expires, 0)
	sess.RevokedAt = nullTime(revoked)
	return &sess, nil
}

// RevokeSession marks a session as ended.
func (s *Store) RevokeSession(ctx context.Context, tokenHash string, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL`,
		at.Unix(), tokenHash)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// DeleteStaleSessions removes sessions that expired or were revoked before now.
func (s *Store) DeleteStaleSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL`, now.Unix())
	if err != nil {
		return 0, fmt.Errorf("delete stale sessions: %w", err)
	}
	return res.RowsAffected()
}

func scanUser(row *sql.Row) (*User, error) {
	var (
		u                 User
		secret            sql.NullString
		enabled           int
		locked, lastLogin sql.NullInt64
		created           int64
	)
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &secret, &enabled, &u.TOTPLastCounter,
		&u.FailedAttempts, &locked, &created, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	u.TOTPSecret = secret.String
	u.TOTPEnabled = enabled == 1
	u.LockedUntil = nullTime(locked)
	u.CreatedAt = time.Unix(created, 0)
	u.LastLoginAt = nullTime(lastLogin)
	return &u, nil
}

func nullTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(v.Int64, 0)
	return &t
}
