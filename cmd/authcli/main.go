// Command authcli is an interactive command-line login system with
// optional TOTP two-factor authentication, backed by SQLite.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/tanishkasharma140904/authcli/internal/auth"
	"github.com/tanishkasharma140904/authcli/internal/cli"
	"github.com/tanishkasharma140904/authcli/internal/config"
	"github.com/tanishkasharma140904/authcli/internal/db"
	"github.com/tanishkasharma140904/authcli/internal/store"
)

func main() {
	cfg, err := config.Load(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(2)
	}
	if err := run(context.Background(), cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg config.Config) error {
	// Keep the database and history private to the running user.
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	conn, err := db.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = os.Chmod(cfg.DBPath, 0o600)

	if err := db.Migrate(ctx, conn); err != nil {
		return err
	}

	svc, err := auth.NewService(store.New(conn), auth.Config{
		SessionTimeout:    cfg.SessionTimeout,
		MaxFailedAttempts: cfg.MaxFailedAttempts,
		LockoutDuration:   cfg.LockoutDuration,
		TOTPIssuer:        cfg.TOTPIssuer,
		BcryptCost:        cfg.BcryptCost,
	})
	if err != nil {
		return err
	}
	if err := svc.CleanupSessions(ctx); err != nil {
		return err
	}

	app, err := cli.New(svc, cli.Options{HistoryFile: cfg.HistoryFile})
	if err != nil {
		return fmt.Errorf("start shell: %w", err)
	}

	// On SIGTERM (e.g. `docker stop`) close the prompt so the session is
	// revoked before the process exits. SIGINT is handled by readline.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sig
		app.Close()
	}()

	return app.Run(ctx)
}
