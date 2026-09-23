package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mdp/qrterminal/v3"

	"github.com/tanishkasharma140904/authcli/internal/auth"
)

// access says in which state a command may be run.
type access int

const (
	anyone    access = iota // before and after login
	guestOnly               // only when logged out
	userOnly                // only when logged in
)

type command struct {
	name   string
	usage  string
	desc   string
	access access
	run    func(ctx context.Context, args []string) error
}

// maxEnrollAttempts is how many times enable-2fa lets the user retry the
// confirmation code before giving up.
const maxEnrollAttempts = 3

func (a *App) buildCommands() []command {
	return []command{
		{name: "register", usage: "register [username]", desc: "Create a new account", access: guestOnly, run: a.cmdRegister},
		{name: "login", usage: "login [username]", desc: "Log in with username, password (+ 2FA code if enabled)", access: guestOnly, run: a.cmdLogin},
		{name: "whoami", usage: "whoami", desc: "Show details about the current user and session", access: userOnly, run: a.cmdWhoAmI},
		{name: "enable-2fa", usage: "enable-2fa", desc: "Enable TOTP two-factor authentication", access: userOnly, run: a.cmdEnable2FA},
		{name: "disable-2fa", usage: "disable-2fa", desc: "Disable two-factor authentication", access: userOnly, run: a.cmdDisable2FA},
		{name: "logout", usage: "logout", desc: "End the current session", access: userOnly, run: a.cmdLogout},
		{name: "help", usage: "help", desc: "Show available commands", access: anyone, run: a.cmdHelp},
		{name: "exit", usage: "exit", desc: "Quit the program (logs out first)", access: anyone, run: a.cmdExit},
	}
}

func (a *App) cmdHelp(_ context.Context, _ []string) error {
	state := "Not logged in"
	if a.session != nil {
		state = "Logged in as " + a.session.Username
	}
	a.out.println("%s  %s", a.out.paint(styleBold, "Available commands"), a.out.paint(styleDim, "("+state+")"))
	width := 0
	for _, c := range a.available() {
		if len(c.usage) > width {
			width = len(c.usage)
		}
	}
	for _, c := range a.available() {
		a.out.println("  %s%s  %s", a.out.paint(styleCyan, c.usage), strings.Repeat(" ", width-len(c.usage)), c.desc)
	}
	a.out.info("Tip: press Tab to complete commands, ↑/↓ for history, Ctrl-R to search history.")
	return nil
}

func (a *App) cmdRegister(ctx context.Context, args []string) error {
	username, err := a.argOrAsk(args, "Username: ")
	if err != nil {
		return err
	}
	username = auth.NormalizeUsername(username)
	// Validate early so the user isn't asked for a password in vain.
	if err := auth.ValidateUsername(username); err != nil {
		return err
	}

	a.out.info("Password must be %d-%d characters and not a common password.", auth.MinPasswordLen, auth.MaxPasswordBytes)
	password, err := a.askPassword("Password: ")
	if err != nil {
		return err
	}
	if err := auth.ValidatePassword(username, password); err != nil {
		return err
	}
	confirm, err := a.askPassword("Confirm password: ")
	if err != nil {
		return err
	}
	if password != confirm {
		return &auth.ValidationError{Msg: "passwords do not match"}
	}

	u, err := a.svc.Register(ctx, username, password)
	if err != nil {
		return err
	}
	a.out.success("Account %q created. Use 'login' to sign in.", u.Username)
	return nil
}

func (a *App) cmdLogin(ctx context.Context, args []string) error {
	username, err := a.argOrAsk(args, "Username: ")
	if err != nil {
		return err
	}
	password, err := a.askPassword("Password: ")
	if err != nil {
		return err
	}

	pending, err := a.svc.BeginLogin(ctx, username, password)
	if err != nil {
		return err
	}
	code := ""
	if pending.MFARequired {
		code, err = a.ask("Authentication code (from your authenticator app): ")
		if err != nil {
			return err
		}
	}
	sess, err := a.svc.CompleteLogin(ctx, pending, code)
	if err != nil {
		return err
	}

	a.setSession(sess)
	a.out.success("Welcome, %s! You are now logged in.", sess.Username)
	return a.showDetails(ctx)
}

func (a *App) cmdWhoAmI(ctx context.Context, _ []string) error {
	return a.showDetails(ctx)
}

func (a *App) showDetails(ctx context.Context) error {
	d, err := a.svc.WhoAmI(ctx, a.session)
	if err != nil {
		return err
	}
	mfa := a.out.paint(styleYellow, "disabled") + a.out.paint(styleDim, "  (run 'enable-2fa' to turn on)")
	if d.MFAEnabled {
		mfa = a.out.paint(styleGreen, "enabled")
	}
	lastLogin := "never (this is your first login)"
	if d.LastLoginAt != nil {
		lastLogin = formatTime(*d.LastLoginAt)
	}
	remaining := d.SessionExpiresAt.Sub(a.svc.Now())
	a.out.table([][2]string{
		{"Username", d.Username},
		{"Registered", formatTime(d.RegisteredAt)},
		{"MFA", mfa},
		{"Session expires", fmt.Sprintf("%s (in %s)", formatTime(d.SessionExpiresAt), humanDuration(remaining))},
		{"Last login", lastLogin},
	})
	return nil
}

func (a *App) cmdEnable2FA(ctx context.Context, _ []string) error {
	setup, err := a.svc.BeginEnableTOTP(ctx, a.session)
	if err != nil {
		return err
	}

	a.out.println("Scan this QR code with Google Authenticator (or any TOTP app):")
	a.out.println("")
	qrterminal.GenerateWithConfig(setup.URL, qrterminal.Config{
		Level:          qrterminal.L,
		Writer:         a.out.w,
		HalfBlocks:     true,
		BlackChar:      qrterminal.BLACK_BLACK,
		WhiteBlackChar: qrterminal.WHITE_BLACK,
		WhiteChar:      qrterminal.WHITE_WHITE,
		BlackWhiteChar: qrterminal.BLACK_WHITE,
		QuietZone:      2,
	})
	a.out.println("")
	a.out.println("Can't scan it? Add the account manually with this key (time-based, 6 digits):")
	a.out.println("  %s", a.out.paint(styleBold, groupSecret(setup.Secret)))
	a.out.println("")

	for attempt := 1; ; attempt++ {
		code, err := a.ask("Enter the 6-digit code shown in your app to confirm: ")
		if err != nil {
			return err
		}
		err = a.svc.ConfirmEnableTOTP(ctx, a.session, setup, code)
		if err == nil {
			break
		}
		if !errors.Is(err, auth.ErrInvalidTOTP) || attempt >= maxEnrollAttempts {
			if errors.Is(err, auth.ErrInvalidTOTP) {
				return fmt.Errorf("%w; 2FA was NOT enabled, run 'enable-2fa' to try again", err)
			}
			return err
		}
		a.out.fail("That code didn't match. Check your device's clock and try again (%d/%d).", attempt, maxEnrollAttempts)
	}
	a.out.success("Two-factor authentication enabled. You'll be asked for a code every time you log in.")
	return nil
}

func (a *App) cmdDisable2FA(ctx context.Context, _ []string) error {
	enabled, err := a.svc.MFAEnabled(ctx, a.session)
	if err != nil {
		return err
	}
	if !enabled {
		return auth.ErrMFANotEnabled
	}
	a.out.info("To disable 2FA, confirm your password and a current authentication code.")
	password, err := a.askPassword("Password: ")
	if err != nil {
		return err
	}
	code, err := a.ask("Authentication code: ")
	if err != nil {
		return err
	}
	if err := a.svc.DisableTOTP(ctx, a.session, password, code); err != nil {
		return err
	}
	a.out.success("Two-factor authentication disabled. You can remove the entry from your authenticator app.")
	return nil
}

func (a *App) cmdLogout(ctx context.Context, _ []string) error {
	name := a.session.Username
	err := a.svc.Logout(ctx, a.session)
	a.setSession(nil) // drop local state even if the DB update failed
	if err != nil {
		return err
	}
	a.out.success("Logged out %s. Goodbye for now!", name)
	return nil
}

func (a *App) cmdExit(ctx context.Context, _ []string) error {
	if a.session != nil {
		if err := a.svc.Logout(ctx, a.session); err != nil {
			a.out.warn("could not end session cleanly: %v", err)
		}
		a.setSession(nil)
	}
	a.out.println("Goodbye!")
	return errExit
}

// describeLock formats a lockout for display.
func (a *App) describeLock(e *auth.LockedError) string {
	wait := humanDuration(e.Until.Sub(a.svc.Now()))
	return fmt.Sprintf("Account locked due to too many failed attempts. Try again after %s (in %s).",
		formatTime(e.Until), wait)
}
