# AuthCLI — Containerized CLI Login System with Optional 2FA

An interactive command-line login system written in Go. It supports user
registration, password login, optional TOTP two-factor authentication
(Google Authenticator compatible), account lockout, and session management
with a configurable timeout. Data is stored in SQLite on a Docker volume, so
it persists across container restarts.

---

## Quick start (Docker)

Requirements: Docker with Compose v2.

```bash
docker compose build
docker compose run --rm authcli
```

> Use `docker compose run` (not `up`). The CLI is interactive and needs your
> terminal attached. `stdin_open` and `tty` are already set in the compose file.

The database and command history live in the named volume `authcli-data`
(mounted at `/data`). Exiting or removing the container, rebuilding the image,
or restarting Docker keeps your data. To wipe it:

```bash
docker compose down -v
```

Makefile shortcuts: `make docker-run`, `make docker-test`, `make docker-reset`.

### Running locally without Docker (optional)

Requires Go 1.26+. There is no CGO or system SQLite dependency.

```bash
make run            # builds ./bin/authcli and starts it; DB goes to ./data/auth.db
make test           # go vet + unit tests
```

---

## Requirements checklist

Each assignment requirement mapped to where it is implemented.

### 1. Authentication system

| Requirement | Implementation |
|---|---|
| Registration with username + password | `Service.Register` in [`internal/auth/service.go`](internal/auth/service.go#L96), with the policy in [`validate.go`](internal/auth/validate.go) |
| Login with username + password | `Service.BeginLogin` / `CompleteLogin` in [`service.go`](internal/auth/service.go#L130) |
| Optional TOTP 2FA (Google Authenticator compatible) | [`internal/auth/totp.go`](internal/auth/totp.go) (RFC 6238, SHA-1, 6 digits, 30 s); QR code rendered in [`commands.go`](internal/cli/commands.go#L161) |
| Secure password storage | bcrypt, cost 12 by default (`AUTH_BCRYPT_COST`); see `Register` in [`service.go`](internal/auth/service.go#L96) |
| Account lockout after failed attempts | `registerFailure` in [`service.go`](internal/auth/service.go#L214): wrong passwords **and** wrong TOTP codes count |
| Session management with configurable timeout | Sessions table + `authorize` check in [`service.go`](internal/auth/service.go#L235); timeout set by `AUTH_SESSION_TIMEOUT` in [`config.go`](internal/config/config.go) |

### 2. Database

| Requirement | Implementation |
|---|---|
| SQLite / MySQL / PostgreSQL | SQLite via the pure-Go driver `modernc.org/sqlite`, see [`internal/db/db.go`](internal/db/db.go) |
| Runs in a container | Embedded in the `authcli` container (SQLite is serverless) |
| Persists across restarts | Named volume `authcli-data` mounted at `/data` in [`docker-compose.yml`](docker-compose.yml) |

### 3. Command-line interface

| Requirement | Implementation |
|---|---|
| Interactive prompt with history | readline REPL in [`internal/cli/cli.go`](internal/cli/cli.go); history saved to `/data/.authcli_history` (↑/↓, Ctrl-R) |
| Tab completion | [`internal/cli/completer.go`](internal/cli/completer.go): offers only the commands valid in the current state |
| Clear errors and success feedback | `report()` in [`cli.go`](internal/cli/cli.go) maps every error to a friendly ✔/✖ message |
| `help` command | `cmdHelp` in [`commands.go`](internal/cli/commands.go#L48) |

### 4. Commands

| Before login | After login |
|---|---|
| ✅ `register` · `cmdRegister` | ✅ `whoami` · `cmdWhoAmI` |
| ✅ `login` (+ TOTP if enabled) · `cmdLogin` | ✅ `enable-2fa` · `cmdEnable2FA` |
| ✅ `help` · `cmdHelp` | ✅ `disable-2fa` · `cmdDisable2FA` |
| ✅ `exit` · `cmdExit` | ✅ `logout` · `cmdLogout` |
| | ✅ `help` · `cmdHelp` |

All handlers are in [`internal/cli/commands.go`](internal/cli/commands.go).

### 5. User details shown automatically after login

`showDetails` in [`commands.go`](internal/cli/commands.go) runs right after a successful login and again on `whoami`:

- ✅ Username
- ✅ Registration date
- ✅ MFA status (enabled/disabled)
- ✅ Session expiration time, with the time remaining
- ✅ Last login time ("never" on the first login)

### Deliverables

| Deliverable | Location |
|---|---|
| Source code, well-structured and commented | [`cmd/`](cmd/), [`internal/`](internal/) (see [Project structure](#project-structure)) |
| Dockerfile + docker-compose.yml | [`Dockerfile`](Dockerfile), [`docker-compose.yml`](docker-compose.yml) |
| README with setup + usage | This file |
| Database schema / migrations | [`internal/db/migrations/0001_init.sql`](internal/db/migrations/0001_init.sql), applied automatically at startup |
| Unit tests (optional) | [`internal/auth/service_test.go`](internal/auth/service_test.go), [`totp_test.go`](internal/auth/totp_test.go), [`config_test.go`](internal/config/config_test.go) |

---

## Usage

```
auth> help
Available commands  (Not logged in)
  register [username]  Create a new account
  login [username]     Log in with username, password (+ 2FA code if enabled)
  help                 Show available commands
  exit                 Quit the program (logs out first)
```

### Example session

```
auth> register alice
Password must be 8-72 characters and not a common password.
Password:
Confirm password:
✔ Account "alice" created. Use 'login' to sign in.

auth> login alice
Password:
✔ Welcome, alice! You are now logged in.
  Username:         alice
  Registered:       2026-09-23 17:48:14 UTC
  MFA:              disabled  (run 'enable-2fa' to turn on)
  Session expires:  2026-09-23 18:18:17 UTC (in 30m0s)
  Last login:       never (this is your first login)

alice@auth> enable-2fa
Scan this QR code with Google Authenticator (or any TOTP app):
  ██▀▀▀▀▀██ ...                      <- QR code rendered in the terminal
Can't scan it? Add the account manually with this key (time-based, 6 digits):
  JBSW Y3DP EHPK 3PXP ...
Enter the 6-digit code shown in your app to confirm: 492039
✔ Two-factor authentication enabled. You'll be asked for a code every time you log in.

alice@auth> logout
✔ Logged out alice. Goodbye for now!

auth> login alice
Password:
Authentication code (from your authenticator app): 815204
✔ Welcome, alice! You are now logged in.
  ...
  Last login:       2026-09-23 17:48:17 UTC
```

### Commands

| Command | When | Description |
|---|---|---|
| `register [username]` | logged out | Create an account. The password is typed twice and never echoed. |
| `login [username]` | logged out | Password, then a TOTP code if 2FA is on. Shows user details on success. |
| `whoami` | logged in | Username, registration date, MFA status, session expiry, last login. |
| `enable-2fa` | logged in | Shows a QR code and secret. 2FA turns on only after you confirm a valid code. |
| `disable-2fa` | logged in | Requires your password **and** a current code. |
| `logout` | logged in | Revokes the session. |
| `help` | always | Lists the commands available in the current state. |
| `exit` | always | Logs out (if needed) and quits. `Ctrl-D` does the same. |

### Shell features

- **Tab completion** for command names. Only the commands valid in the current
  state are offered.
- **History** with ↑/↓ and reverse search with `Ctrl-R`. History is saved to
  `/data/.authcli_history`. Only command lines are recorded, never usernames,
  passwords or codes typed at prompts.
- `Ctrl-C` cancels the current prompt (for example, halfway through `register`).
- Colored `✔`/`✖` feedback. Set `NO_COLOR=1` to disable it.
- If your session expires while you're idle, a notice is printed and the
  prompt switches back to the logged-out state.

---

## Configuration

Every setting can be given as a flag or an environment variable. Flags take
precedence over environment variables. With Docker, set them in a `.env` file
(see `.env.example`) or in your shell before running `docker compose run`.

| Env var | Flag | Default | Meaning |
|---|---|---|---|
| `AUTH_DB_PATH` | `-db` | `data/auth.db` (`/data/auth.db` in Docker) | SQLite file |
| `AUTH_HISTORY_FILE` | `-history` | `.authcli_history` next to the DB | Command history file |
| `AUTH_SESSION_TIMEOUT` | `-session-timeout` | `30m` | Session lifetime (Go duration, min `1m`) |
| `AUTH_MAX_FAILED_ATTEMPTS` | `-max-failed-attempts` | `5` | Consecutive failures before lockout |
| `AUTH_LOCKOUT_DURATION` | `-lockout-duration` | `15m` | How long a lockout lasts |
| `AUTH_TOTP_ISSUER` | `-totp-issuer` | `AuthCLI` | Name shown in authenticator apps |
| `AUTH_BCRYPT_COST` | `-bcrypt-cost` | `12` | bcrypt work factor (4–31) |
| `TZ` | — | `UTC` | Time zone for displayed timestamps |

Example: a short session and a strict lockout:

```bash
AUTH_SESSION_TIMEOUT=5m AUTH_MAX_FAILED_ATTEMPTS=3 docker compose run --rm authcli
```

---

## Security design

| Concern | Approach |
|---|---|
| Password storage | bcrypt (cost 12 by default). Passwords over 72 bytes are rejected rather than silently truncated. |
| Password policy | 8–72 characters, not equal to the username, not on a common-password blocklist (following NIST SP 800-63B). |
| Username enumeration | Unknown user and wrong password return the same message. For unknown users a dummy bcrypt comparison runs so timing matches. |
| Brute force | After `MAX_FAILED_ATTEMPTS` consecutive failures (wrong password **or** wrong TOTP code) the account locks for `LOCKOUT_DURATION`. While locked, even the correct password is refused. A successful login resets the counter. |
| TOTP | RFC 6238, SHA-1, 6 digits, 30 s period, compatible with Google Authenticator, Authy and 1Password. ±1 step of clock drift is accepted. **Replay protection:** each time step can be used only once. |
| 2FA enrollment | The secret is stored only after the user proves their app works by entering a valid code. |
| Disabling 2FA | Requires the password and a fresh code, so a briefly unattended session can't downgrade the account. |
| Two-step login | The pending password→TOTP state is single-use and expires after 3 minutes. |
| Sessions | 256-bit random tokens. Only their SHA-256 hash is stored. There is an absolute expiry, checked against the DB before every protected action. Logout, `exit` and `docker stop` (SIGTERM) revoke the session. Stale sessions are purged on startup. |
| Container | Static binary running as non-root (UID 10001) with a read-only root filesystem, all capabilities dropped and `no-new-privileges`. The data dir and DB file are `0700`/`0600`. |
| SQL | All queries are parameterized. |

**Known limitations / possible improvements**

- TOTP secrets are stored in plaintext in the DB. In production, encrypt them
  at rest (e.g. AES-GCM with a key from a secrets manager).
- Lockout is per-account, so an attacker can deliberately lock out a known
  user. Real deployments usually add per-source rate limiting or CAPTCHAs.
- No 2FA recovery codes yet.

---

## Database schema

Migrations live in [`internal/db/migrations/`](internal/db/migrations/) and
are embedded into the binary. They run automatically at startup, and the
`schema_migrations` table tracks which ones have been applied. Timestamps are
stored as Unix seconds (UTC).

```sql
users (
  id INTEGER PK, username TEXT UNIQUE COLLATE NOCASE, password_hash TEXT,
  totp_secret TEXT NULL, totp_enabled INTEGER, totp_last_counter INTEGER,
  failed_attempts INTEGER, locked_until INTEGER NULL,
  created_at INTEGER, last_login_at INTEGER NULL
)
sessions (
  id INTEGER PK, token_hash TEXT UNIQUE, user_id INTEGER FK -> users ON DELETE CASCADE,
  created_at INTEGER, expires_at INTEGER, revoked_at INTEGER NULL
)
```

To inspect the live database:

```bash
docker run --rm -it -v project_authcli-data:/data alpine sh -c "apk add -q sqlite && sqlite3 /data/auth.db '.tables'"
```

(The volume name is prefixed with the compose project name, usually the
folder name. Check it with `docker volume ls`.)

---

## Project structure

```
cmd/authcli/          main: wires config → DB → service → CLI, handles SIGTERM
internal/config/      flags + AUTH_* env vars, validation
internal/db/          SQLite connection (pure-Go driver) + embedded migrations
internal/store/       SQL queries for users and sessions (no business logic)
internal/auth/        business rules: registration, login, lockout, TOTP, sessions
internal/cli/         readline REPL, commands, completion, output formatting
Dockerfile            multi-stage build (build / test / runtime)
docker-compose.yml    interactive service + persistent volume
```

The layers depend only downward (cli → auth → store → db), so the security
logic in `auth` is testable without a terminal.

## Tests

```bash
make docker-test     # runs go vet + go test inside the build image
# or locally:
make test
```

Unit tests cover registration and validation, case-insensitive usernames,
bcrypt storage, generic credential errors, lockout and its expiry, counter
reset on success, session timeout and logout, the full TOTP enrollment/login/
disable flow, TOTP replay and drift handling, TOTP failures counting toward
lockout, pending-login expiry, hashed token storage, and config precedence.
Tests use a fake clock and a temporary SQLite file.

## Dependencies

- [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite): pure-Go SQLite (no CGO)
- [`golang.org/x/crypto/bcrypt`](https://pkg.go.dev/golang.org/x/crypto/bcrypt): password hashing
- [`github.com/pquerna/otp`](https://github.com/pquerna/otp): TOTP/HOTP
- [`github.com/chzyer/readline`](https://github.com/chzyer/readline): prompt, history, completion, hidden input
- [`github.com/mdp/qrterminal`](https://github.com/mdp/qrterminal): QR codes in the terminal
