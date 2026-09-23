// Package cli implements the interactive shell: a readline-based prompt
// with history and tab completion that dispatches to package auth.
package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chzyer/readline"

	"github.com/tanishkasharma140904/authcli/internal/auth"
)

var (
	errExit      = errors.New("exit")
	errCancelled = errors.New("cancelled")
)

// Options configures the shell.
type Options struct {
	HistoryFile string
	Stdin       io.ReadCloser // nil means the process stdin
	Stdout      io.Writer     // nil means the process stdout
}

// App is the interactive shell. It holds at most one session at a time.
type App struct {
	svc      *auth.Service
	rl       *readline.Instance
	out      *printer
	commands []command
	session  *auth.Session

	// inPrompt is set while a command is reading input (username, password,
	// code), which disables command completion and expiry notices.
	inPrompt atomic.Bool

	timerMu     sync.Mutex
	expiryTimer *time.Timer
	closeOnce   sync.Once
}

// New creates the shell.
func New(svc *auth.Service, opts Options) (*App, error) {
	a := &App{svc: svc}
	a.commands = a.buildCommands()

	cfg := &readline.Config{
		Prompt:                 guestPrompt,
		HistoryFile:            opts.HistoryFile,
		HistoryLimit:           500,
		HistorySearchFold:      true,
		DisableAutoSaveHistory: true, // only commands are saved, never prompt answers
		AutoComplete:           &completer{app: a},
		InterruptPrompt:        "^C",
		EOFPrompt:              "exit",
	}
	if opts.Stdin != nil {
		cfg.Stdin = opts.Stdin
	}
	if opts.Stdout != nil {
		cfg.Stdout = opts.Stdout
	}
	rl, err := readline.NewEx(cfg)
	if err != nil {
		return nil, err
	}
	a.rl = rl
	a.out = newPrinter(rl.Stdout(), readline.DefaultIsTerminal() && opts.Stdout == nil)
	return a, nil
}

const guestPrompt = "auth> "

func (a *App) prompt() string {
	if a.session == nil {
		return a.out.paint(styleBold, "auth") + "> "
	}
	return a.out.paint(styleGreen, a.session.Username) + "@" + a.out.paint(styleBold, "auth") + "> "
}

// Close stops the shell; a pending Readline call returns io.EOF so Run can
// log out and return. Safe to call from another goroutine (e.g. on SIGTERM).
func (a *App) Close() {
	a.closeOnce.Do(func() { a.rl.Close() })
}

// Run executes the read-eval-print loop until exit or EOF.
func (a *App) Run(ctx context.Context) error {
	defer a.Close()
	a.out.println("%s", a.out.paint(styleBold, "Welcome to AuthCLI — secure login with optional 2FA."))
	a.out.info("Type 'help' to see available commands.")

	for {
		a.rl.SetPrompt(a.prompt())
		line, err := a.rl.Readline()
		if errors.Is(err, readline.ErrInterrupt) {
			if strings.TrimSpace(line) == "" {
				a.out.info("(Type 'exit' or press Ctrl-D to quit.)")
			}
			continue
		}
		if err != nil { // io.EOF: Ctrl-D, closed stdin or Close()
			_ = a.cmdExit(ctx, nil)
			return nil
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		_ = a.rl.SaveHistory(line)

		if err := a.dispatch(ctx, line); errors.Is(err, errExit) {
			return nil
		}
	}
}

// dispatch runs a single command line and reports errors to the user.
func (a *App) dispatch(ctx context.Context, line string) error {
	a.expireSessionIfNeeded()

	fields := strings.Fields(line)
	name := strings.ToLower(fields[0])
	cmd, ok := a.lookup(name)
	if !ok {
		a.out.fail("Unknown command %q. Type 'help' to see available commands.", name)
		return nil
	}
	switch {
	case cmd.access == userOnly && a.session == nil:
		a.out.fail("You must be logged in to use %q. Try 'login' or 'register'.", name)
		return nil
	case cmd.access == guestOnly && a.session != nil:
		a.out.fail("You are already logged in as %s. Use 'logout' first.", a.session.Username)
		return nil
	}

	err := cmd.run(ctx, fields[1:])
	a.report(err)
	return err
}

// report prints err in a user-friendly form.
func (a *App) report(err error) {
	var (
		locked  *auth.LockedError
		invalid *auth.ValidationError
	)
	switch {
	case err == nil, errors.Is(err, errExit):
	case errors.Is(err, errCancelled):
		a.out.info("Cancelled.")
	case errors.As(err, &locked):
		a.out.fail("%s", a.describeLock(locked))
	case errors.As(err, &invalid):
		a.out.fail("%s", capitalize(invalid.Msg))
	case errors.Is(err, auth.ErrSessionExpired):
		a.setSession(nil)
		a.out.fail("Your session has expired. Please log in again.")
	case isKnown(err):
		a.out.fail("%s", capitalize(err.Error()))
	default:
		a.out.fail("Something went wrong: %v", err)
	}
}

func isKnown(err error) bool {
	for _, known := range []error{
		auth.ErrInvalidCredentials, auth.ErrIncorrectPassword, auth.ErrInvalidTOTP,
		auth.ErrUsernameTaken, auth.ErrMFAAlreadyEnabled, auth.ErrMFANotEnabled, auth.ErrLoginExpired,
	} {
		if errors.Is(err, known) {
			return true
		}
	}
	return false
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func (a *App) lookup(name string) (command, bool) {
	for _, c := range a.commands {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// available lists the commands usable in the current state.
func (a *App) available() []command {
	var out []command
	for _, c := range a.commands {
		switch {
		case c.access == anyone,
			c.access == guestOnly && a.session == nil,
			c.access == userOnly && a.session != nil:
			out = append(out, c)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Session bookkeeping
// ---------------------------------------------------------------------------

// setSession replaces the current session and (re)arms the expiry notice.
func (a *App) setSession(s *auth.Session) {
	a.session = s

	a.timerMu.Lock()
	defer a.timerMu.Unlock()
	if a.expiryTimer != nil {
		a.expiryTimer.Stop()
		a.expiryTimer = nil
	}
	if s == nil {
		return
	}
	a.expiryTimer = time.AfterFunc(s.ExpiresAt.Sub(a.svc.Now()), func() {
		// Only print; state is cleared by the main loop on the next command
		// so that a.session is never touched from this goroutine.
		if a.inPrompt.Load() {
			return
		}
		a.out.warn("Your session has expired. Please log in again.")
		a.rl.SetPrompt(a.out.paint(styleBold, "auth") + "> ")
		a.rl.Refresh()
	})
}

// expireSessionIfNeeded drops a session that has passed its expiry time.
func (a *App) expireSessionIfNeeded() {
	if a.session != nil && a.session.Expired(a.svc.Now()) {
		a.out.warn("Your session for %s expired at %s. Please log in again.",
			a.session.Username, formatTime(a.session.ExpiresAt))
		_ = a.svc.Logout(context.Background(), a.session)
		a.setSession(nil)
	}
}

// ---------------------------------------------------------------------------
// Input helpers
// ---------------------------------------------------------------------------

// ask reads a line of plain input. Ctrl-C / Ctrl-D cancel the command.
func (a *App) ask(label string) (string, error) {
	a.inPrompt.Store(true)
	defer a.inPrompt.Store(false)
	a.rl.SetPrompt(label)
	line, err := a.rl.Readline()
	if err != nil {
		return "", errCancelled
	}
	return strings.TrimSpace(line), nil
}

// askPassword reads input without echoing it.
func (a *App) askPassword(label string) (string, error) {
	a.inPrompt.Store(true)
	defer a.inPrompt.Store(false)
	b, err := a.rl.ReadPassword(label)
	if err != nil {
		return "", errCancelled
	}
	return string(b), nil
}

// argOrAsk returns args[0] if present, otherwise prompts for it.
func (a *App) argOrAsk(args []string, label string) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	for {
		v, err := a.ask(label)
		if err != nil || v != "" {
			return v, err
		}
	}
}
