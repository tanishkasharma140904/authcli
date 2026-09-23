package auth

import (
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

// TOTP parameters compatible with Google Authenticator (RFC 6238 defaults).
const (
	totpPeriod = 30 // seconds per time step
	totpSkew   = 1  // accept codes one step before/after to tolerate clock drift
)

// TOTPSetup is the enrollment material shown to the user while enabling 2FA.
type TOTPSetup struct {
	Secret string // base32 secret for manual entry
	URL    string // otpauth:// URI, rendered as a QR code
}

func generateTOTP(issuer, account string) (*TOTPSetup, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		Period:      totpPeriod,
		SecretSize:  20, // 160 bits, as recommended by RFC 4226
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, err
	}
	return &TOTPSetup{Secret: key.Secret(), URL: key.URL()}, nil
}

// validateTOTP checks code against secret at time t, allowing ±totpSkew
// steps. Any step <= lastCounter is refused so a code can only be used once.
// On success it returns the matched time step, which the caller must persist.
func validateTOTP(secret, code string, t time.Time, lastCounter int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false
	}
	current := t.Unix() / totpPeriod
	for c := current - totpSkew; c <= current+totpSkew; c++ {
		if c <= lastCounter || c < 0 {
			continue
		}
		ok, err := hotp.ValidateCustom(code, uint64(c), secret, hotp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err == nil && ok {
			return c, true
		}
	}
	return 0, false
}
