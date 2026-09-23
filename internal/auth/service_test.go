package auth_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/tanishkasharma140904/authcli/internal/auth"
	"github.com/tanishkasharma140904/authcli/internal/db"
	"github.com/tanishkasharma140904/authcli/internal/store"
)

const goodPassword = "correct-horse-battery"

// fakeClock is a controllable time source.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

type fixture struct {
	svc   *auth.Service
	store *store.Store
	clock *fakeClock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := db.Migrate(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	st := store.New(conn)
	clock := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	svc, err := auth.NewService(st, auth.Config{
		SessionTimeout:    30 * time.Minute,
		MaxFailedAttempts: 3,
		LockoutDuration:   10 * time.Minute,
		TOTPIssuer:        "Test",
		BcryptCost:        bcrypt.MinCost, // keep tests fast
	}, auth.WithClock(clock.now))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, store: st, clock: clock}
}

func (f *fixture) register(t *testing.T, username string) {
	t.Helper()
	if _, err := f.svc.Register(context.Background(), username, goodPassword); err != nil {
		t.Fatalf("register %q: %v", username, err)
	}
}

func (f *fixture) login(t *testing.T, username, password, code string) (*auth.Session, error) {
	t.Helper()
	ctx := context.Background()
	p, err := f.svc.BeginLogin(ctx, username, password)
	if err != nil {
		return nil, err
	}
	return f.svc.CompleteLogin(ctx, p, code)
}

// enable2FA turns on 2FA for a logged-in user and returns the secret.
func (f *fixture) enable2FA(t *testing.T, sess *auth.Session) string {
	t.Helper()
	ctx := context.Background()
	setup, err := f.svc.BeginEnableTOTP(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(setup.Secret, f.clock.now())
	if err := f.svc.ConfirmEnableTOTP(ctx, sess, setup, code); err != nil {
		t.Fatalf("confirm 2FA: %v", err)
	}
	return setup.Secret
}

func TestRegister(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	u, err := f.svc.Register(ctx, "  Alice ", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" {
		t.Errorf("username not normalized: %q", u.Username)
	}
	if u.PasswordHash == goodPassword || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(goodPassword)) != nil {
		t.Error("password was not stored as a bcrypt hash")
	}
	if _, err := f.svc.Register(ctx, "ALICE", goodPassword); !errors.Is(err, auth.ErrUsernameTaken) {
		t.Errorf("duplicate username: got %v, want ErrUsernameTaken", err)
	}
}

func TestRegisterValidation(t *testing.T) {
	f := newFixture(t)
	cases := []struct{ name, user, pass string }{
		{"short username", "ab", goodPassword},
		{"bad chars", "bob smith", goodPassword},
		{"short password", "bob", "short"},
		{"too long password", "bob", string(make([]byte, 73))},
		{"password equals username", "bobbybobby", "BobbyBobby"},
		{"common password", "bob", "password123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.svc.Register(context.Background(), tc.user, tc.pass)
			var ve *auth.ValidationError
			if !errors.As(err, &ve) {
				t.Errorf("got %v, want ValidationError", err)
			}
		})
	}
}

func TestLoginSuccessAndDetails(t *testing.T) {
	f := newFixture(t)
	f.register(t, "alice")
	ctx := context.Background()

	sess, err := f.login(t, "alice", goodPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := f.clock.now().Add(30 * time.Minute); !sess.ExpiresAt.Equal(want) {
		t.Errorf("expires at %v, want %v", sess.ExpiresAt, want)
	}
	d, err := f.svc.WhoAmI(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	if d.Username != "alice" || d.MFAEnabled || d.LastLoginAt != nil {
		t.Errorf("unexpected details on first login: %+v", d)
	}

	// A second login reports the first one as "last login".
	first := f.clock.now()
	f.clock.advance(time.Hour)
	sess2, err := f.login(t, "Alice", goodPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	d, _ = f.svc.WhoAmI(ctx, sess2)
	if d.LastLoginAt == nil || !d.LastLoginAt.Equal(first) {
		t.Errorf("last login = %v, want %v", d.LastLoginAt, first)
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	f := newFixture(t)
	f.register(t, "alice")

	if _, err := f.login(t, "alice", "wrong-password", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("wrong password: got %v", err)
	}
	if _, err := f.login(t, "nobody", goodPassword, ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("unknown user: got %v (must be indistinguishable from wrong password)", err)
	}
}

func TestAccountLockout(t *testing.T) {
	f := newFixture(t)
	f.register(t, "alice")

	for i := 1; i < 3; i++ {
		if _, err := f.login(t, "alice", "wrong-password", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: got %v", i, err)
		}
	}
	// Third failure hits MaxFailedAttempts and locks the account.
	_, err := f.login(t, "alice", "wrong-password", "")
	var locked *auth.LockedError
	if !errors.As(err, &locked) {
		t.Fatalf("3rd failure: got %v, want LockedError", err)
	}
	if want := f.clock.now().Add(10 * time.Minute); !locked.Until.Equal(want) {
		t.Errorf("locked until %v, want %v", locked.Until, want)
	}

	// Even the correct password is refused while locked.
	if _, err := f.login(t, "alice", goodPassword, ""); !errors.As(err, &locked) {
		t.Errorf("correct password while locked: got %v", err)
	}

	// After the lock expires the correct password works again.
	f.clock.advance(10*time.Minute + time.Second)
	if _, err := f.login(t, "alice", goodPassword, ""); err != nil {
		t.Errorf("after lock expiry: %v", err)
	}
}

func TestSuccessfulLoginResetsFailures(t *testing.T) {
	f := newFixture(t)
	f.register(t, "alice")

	for i := 0; i < 2; i++ {
		f.login(t, "alice", "wrong-password", "") //nolint:errcheck
	}
	if _, err := f.login(t, "alice", goodPassword, ""); err != nil {
		t.Fatal(err)
	}
	// Counter was reset, so two more failures must not lock the account.
	for i := 0; i < 2; i++ {
		f.login(t, "alice", "wrong-password", "") //nolint:errcheck
	}
	if _, err := f.login(t, "alice", goodPassword, ""); err != nil {
		t.Errorf("expected login to succeed, got %v", err)
	}
}

func TestSessionExpiryAndLogout(t *testing.T) {
	f := newFixture(t)
	f.register(t, "alice")
	ctx := context.Background()

	sess, _ := f.login(t, "alice", goodPassword, "")
	f.clock.advance(29 * time.Minute)
	if _, err := f.svc.WhoAmI(ctx, sess); err != nil {
		t.Errorf("before timeout: %v", err)
	}
	f.clock.advance(time.Minute)
	if _, err := f.svc.WhoAmI(ctx, sess); !errors.Is(err, auth.ErrSessionExpired) {
		t.Errorf("after timeout: got %v, want ErrSessionExpired", err)
	}

	sess, _ = f.login(t, "alice", goodPassword, "")
	if err := f.svc.Logout(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.WhoAmI(ctx, sess); !errors.Is(err, auth.ErrSessionExpired) {
		t.Errorf("after logout: got %v, want ErrSessionExpired", err)
	}
}

func TestTOTPLoginFlow(t *testing.T) {
	f := newFixture(t)
	f.register(t, "alice")
	ctx := context.Background()

	sess, _ := f.login(t, "alice", goodPassword, "")
	secret := f.enable2FA(t, sess)
	if _, err := f.svc.BeginEnableTOTP(ctx, sess); !errors.Is(err, auth.ErrMFAAlreadyEnabled) {
		t.Errorf("enable twice: got %v", err)
	}

	f.clock.advance(time.Minute)
	p, err := f.svc.BeginLogin(ctx, "alice", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if !p.MFARequired {
		t.Fatal("MFARequired should be true once 2FA is enabled")
	}
	if _, err := f.svc.CompleteLogin(ctx, p, "000000"); !errors.Is(err, auth.ErrInvalidTOTP) {
		t.Errorf("wrong code: got %v", err)
	}
	// PendingLogin is single use.
	code, _ := totp.GenerateCode(secret, f.clock.now())
	if _, err := f.svc.CompleteLogin(ctx, p, code); !errors.Is(err, auth.ErrLoginExpired) {
		t.Errorf("reused pending login: got %v", err)
	}

	sess, err = f.login(t, "alice", goodPassword, code)
	if err != nil {
		t.Fatalf("valid code: %v", err)
	}
	d, _ := f.svc.WhoAmI(ctx, sess)
	if !d.MFAEnabled {
		t.Error("whoami should report MFA enabled")
	}

	// The same code cannot be replayed within its validity window.
	if _, err := f.login(t, "alice", goodPassword, code); !errors.Is(err, auth.ErrInvalidTOTP) {
		t.Errorf("replayed code: got %v, want ErrInvalidTOTP", err)
	}
}

func TestTOTPFailuresCountTowardLockout(t *testing.T) {
	f := newFixture(t)
	f.register(t, "alice")
	sess, _ := f.login(t, "alice", goodPassword, "")
	f.enable2FA(t, sess)

	var err error
	for i := 0; i < 3; i++ {
		_, err = f.login(t, "alice", goodPassword, "123456")
	}
	var locked *auth.LockedError
	if !errors.As(err, &locked) {
		t.Errorf("after 3 bad codes: got %v, want LockedError", err)
	}
}

func TestPendingLoginExpires(t *testing.T) {
	f := newFixture(t)
	f.register(t, "alice")
	ctx := context.Background()

	p, err := f.svc.BeginLogin(ctx, "alice", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.advance(10 * time.Minute)
	if _, err := f.svc.CompleteLogin(ctx, p, ""); !errors.Is(err, auth.ErrLoginExpired) {
		t.Errorf("got %v, want ErrLoginExpired", err)
	}
}

func TestEnableTOTPRejectsBadCode(t *testing.T) {
	f := newFixture(t)
	f.register(t, "alice")
	ctx := context.Background()
	sess, _ := f.login(t, "alice", goodPassword, "")

	setup, err := f.svc.BeginEnableTOTP(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ConfirmEnableTOTP(ctx, sess, setup, "000000"); !errors.Is(err, auth.ErrInvalidTOTP) {
		t.Errorf("got %v, want ErrInvalidTOTP", err)
	}
	if on, _ := f.svc.MFAEnabled(ctx, sess); on {
		t.Error("2FA must stay disabled after a failed confirmation")
	}
}

func TestDisableTOTP(t *testing.T) {
	f := newFixture(t)
	f.register(t, "alice")
	ctx := context.Background()
	sess, _ := f.login(t, "alice", goodPassword, "")

	if err := f.svc.DisableTOTP(ctx, sess, goodPassword, "123456"); !errors.Is(err, auth.ErrMFANotEnabled) {
		t.Errorf("disable when off: got %v", err)
	}

	secret := f.enable2FA(t, sess)
	f.clock.advance(time.Minute) // move past the enrollment code's time step
	code, _ := totp.GenerateCode(secret, f.clock.now())

	if err := f.svc.DisableTOTP(ctx, sess, "wrong-password", code); !errors.Is(err, auth.ErrIncorrectPassword) {
		t.Errorf("wrong password: got %v", err)
	}
	if err := f.svc.DisableTOTP(ctx, sess, goodPassword, "000000"); !errors.Is(err, auth.ErrInvalidTOTP) {
		t.Errorf("wrong code: got %v", err)
	}
	if err := f.svc.DisableTOTP(ctx, sess, goodPassword, code); err != nil {
		t.Fatalf("disable: %v", err)
	}

	// Login no longer asks for a code.
	p, err := f.svc.BeginLogin(ctx, "alice", goodPassword)
	if err != nil || p.MFARequired {
		t.Errorf("after disable: pending=%+v err=%v", p, err)
	}
}

func TestSessionTokenStoredHashed(t *testing.T) {
	f := newFixture(t)
	f.register(t, "alice")
	sess, _ := f.login(t, "alice", goodPassword, "")

	if _, err := f.store.GetSessionByTokenHash(context.Background(), sess.Token); !errors.Is(err, store.ErrNotFound) {
		t.Error("raw session token must not be stored in the database")
	}
}
