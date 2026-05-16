// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"time"
)

// FactorType discriminates the three v0.2 MFA factor variants per ADR 0008.
type FactorType string

const (
	FactorTypeTotp     FactorType = "totp"
	FactorTypeWebAuthn FactorType = "webauthn"
	FactorTypeRecovery FactorType = "recovery"
)

// FactorStatus is the lifecycle status of a single MFA factor. TOTP +
// WebAuthn factors begin Pending and move to Active on confirmation;
// recovery codes start active.
type FactorStatus string

const (
	FactorStatusPending   FactorStatus = "pending"
	FactorStatusActive    FactorStatus = "active"
	FactorStatusSuspended FactorStatus = "suspended"
	FactorStatusRevoked   FactorStatus = "revoked"
)

// Factor is the union of the three v0.2 factor variants. Variant-
// specific fields are populated only when Type matches.
type Factor struct {
	ID         string
	UsrID      string
	Type       FactorType
	Identifier string // TOTP: human label; WebAuthn: base64url credential ID
	Status     FactorStatus
	Replaces   *string
	CreatedAt  time.Time
	UpdatedAt  time.Time

	// WebAuthn-specific (zero when Type != WebAuthn).
	RpID      string
	SignCount int64

	// Recovery-specific (zero when Type != Recovery).
	Remaining int
}

// TotpEnrollmentResult is returned by IdentityStore.EnrollTotpFactor.
// SecretB32 and OtpauthURI are returned ONCE for QR-code rendering;
// the SDK stores the raw secret internally and never re-emits it.
type TotpEnrollmentResult struct {
	Factor      Factor
	SecretB32   string
	OtpauthURI  string
}

// WebAuthnEnrollmentResult is returned by IdentityStore.EnrollWebAuthnFactor.
// The factor is created in Pending status with the caller-supplied
// public key and counter.
type WebAuthnEnrollmentResult struct {
	Factor Factor
}

// RecoveryEnrollmentResult is returned by IdentityStore.EnrollRecoveryFactor.
// The factor is active immediately. Codes is the plaintext set
// returned ONCE — the SDK stores only Argon2id hashes.
type RecoveryEnrollmentResult struct {
	Factor Factor
	Codes  []string
}

// MfaProof is one of TotpProof / WebAuthnProof / RecoveryProof. Only
// one field is populated per call.
type MfaProof struct {
	Totp     *TotpProof
	WebAuthn *WebAuthnProof
	Recovery *RecoveryProof
}

// TotpProof carries the candidate TOTP code.
type TotpProof struct {
	Code string
}

// WebAuthnProof is the input set for verifying a WebAuthn assertion.
type WebAuthnProof struct {
	CredentialID      string // base64url, matches WebAuthn factor.Identifier
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
	ExpectedChallenge []byte
	ExpectedOrigin    string
}

// RecoveryProof carries the candidate recovery code.
type RecoveryProof struct {
	Code string
}

// MfaVerifyResult is the success outcome of IdentityStore.VerifyMfa.
// NewSignCount is set only for WebAuthn proofs.
type MfaVerifyResult struct {
	MfaID         string
	Type          FactorType
	MfaVerifiedAt time.Time
	NewSignCount  *int64
}

// UserMfaPolicy is the per-user MFA enforcement policy. When Required
// is true and GraceUntil is nil-or-past, VerifyPassword surfaces an
// MFA-required signal instead of producing a usable session.
type UserMfaPolicy struct {
	UsrID      string
	Required   bool
	GraceUntil *time.Time
	UpdatedAt  time.Time
}

// IsActiveNow reports whether MFA enforcement is active for the user
// as of `now`.
func (p UserMfaPolicy) IsActiveNow(now time.Time) bool {
	if !p.Required {
		return false
	}
	if p.GraceUntil == nil {
		return true
	}
	return !now.Before(*p.GraceUntil)
}

// ─── TOTP (RFC 6238) ─────────────────────────────────────────────

// Default TOTP parameters per RFC 6238.
const (
	DefaultTotpPeriod    = 30
	DefaultTotpDigits    = 6
	DefaultTotpAlgorithm = "sha1"
)

// TotpComputeOptions holds optional parameters for [TotpCompute] /
// [TotpVerify]. The zero value is the recommended defaults (30s / 6
// digits / SHA-1).
type TotpComputeOptions struct {
	Period    int
	Digits    int
	Algorithm string // "sha1" | "sha256" | "sha512"
}

func (o TotpComputeOptions) period() int {
	if o.Period == 0 {
		return DefaultTotpPeriod
	}
	return o.Period
}

func (o TotpComputeOptions) digits() int {
	if o.Digits == 0 {
		return DefaultTotpDigits
	}
	return o.Digits
}

func (o TotpComputeOptions) hash() (func() hash.Hash, error) {
	alg := o.Algorithm
	if alg == "" {
		alg = DefaultTotpAlgorithm
	}
	switch alg {
	case "sha1":
		return sha1.New, nil
	case "sha256":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported TOTP algorithm %q", alg)
	}
}

// TotpCompute computes the TOTP code for a secret + timestamp using
// the RFC 6238 / RFC 4226 dynamic-truncation algorithm.
//
// secret is RAW bytes (not base32-encoded). timestamp is Unix seconds.
func TotpCompute(secret []byte, timestamp int64, opts TotpComputeOptions) (string, error) {
	period := opts.period()
	digits := opts.digits()
	newHash, err := opts.hash()
	if err != nil {
		return "", err
	}
	counter := timestamp / int64(period)
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], uint64(counter))
	mac := hmac.New(newHash, secret)
	mac.Write(counterBytes[:])
	digest := mac.Sum(nil)
	offset := int(digest[len(digest)-1] & 0x0F)
	codeInt := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7FFFFFFF

	modulus := uint32(1)
	for i := 0; i < digits; i++ {
		modulus *= 10
	}
	code := codeInt % modulus
	return fmt.Sprintf("%0*d", digits, code), nil
}

// TotpVerify verifies a candidate TOTP code with drift tolerance.
// driftWindows accepts the current window plus ±driftWindows
// surrounding windows. Defaults to 1 (one window each direction).
// Returns false on any verification failure; never raises on
// malformed input.
func TotpVerify(secret []byte, candidate string, timestamp int64, driftWindows int, opts TotpComputeOptions) (bool, error) {
	if driftWindows < 0 || driftWindows > 10 {
		return false, fmt.Errorf("driftWindows must be 0..10, got %d", driftWindows)
	}
	digits := opts.digits()
	period := opts.period()

	if len(candidate) != digits {
		return false, nil
	}
	for _, c := range candidate {
		if c < '0' || c > '9' {
			return false, nil
		}
	}
	for offset := -driftWindows; offset <= driftWindows; offset++ {
		ts := timestamp + int64(offset)*int64(period)
		expected, err := TotpCompute(secret, ts, opts)
		if err != nil {
			return false, err
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(candidate)) == 1 {
			return true, nil
		}
	}
	return false, nil
}

// GenerateTotpSecret returns a fresh TOTP shared secret. 20 bytes (160
// bits) is the RFC 6238 recommended minimum for SHA-1.
func GenerateTotpSecret(numBytes int) ([]byte, error) {
	if numBytes <= 0 {
		numBytes = 20
	}
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// TotpOtpauthURI builds the otpauth:// URI for QR-code rendering at
// enrollment. Follows the de-facto Google Authenticator key URI
// standard.
func TotpOtpauthURI(secret []byte, label, issuer string, opts TotpComputeOptions) string {
	secretB32 := strings.TrimRight(base32.StdEncoding.EncodeToString(secret), "=")
	digits := opts.digits()
	period := opts.period()
	alg := opts.Algorithm
	if alg == "" {
		alg = DefaultTotpAlgorithm
	}
	labelEsc := url.PathEscape(fmt.Sprintf("%s:%s", issuer, label))
	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", issuer)
	q.Set("algorithm", strings.ToUpper(alg))
	q.Set("digits", fmt.Sprintf("%d", digits))
	q.Set("period", fmt.Sprintf("%d", period))
	return fmt.Sprintf("otpauth://totp/%s?%s", labelEsc, q.Encode())
}

// ─── Recovery codes ──────────────────────────────────────────────

// recoveryAlphabet excludes 0/O/1/I/L for reading clarity. 31 characters.
const recoveryAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// RecoveryCodeCount is the number of codes minted per
// EnrollRecoveryFactor call.
const RecoveryCodeCount = 10

// RecoveryCodeLength is the raw character count per code (not
// including hyphens).
const RecoveryCodeLength = 12

// GenerateRecoveryCode produces one fresh 12-char recovery code,
// formatted XXXX-XXXX-XXXX.
func GenerateRecoveryCode() (string, error) {
	alphaLen := uint16(len(recoveryAlphabet))
	// Rejection threshold: largest multiple of alphaLen that fits in a
	// byte. Removes modulo bias when mapping random bytes onto a 31-
	// char alphabet.
	threshold := byte((256 / alphaLen) * alphaLen)
	chars := make([]byte, RecoveryCodeLength)
	buf := make([]byte, 1)
	for i := 0; i < RecoveryCodeLength; i++ {
		for {
			if _, err := rand.Read(buf); err != nil {
				return "", err
			}
			if buf[0] < threshold {
				chars[i] = recoveryAlphabet[uint16(buf[0])%alphaLen]
				break
			}
		}
	}
	return fmt.Sprintf("%s-%s-%s", chars[0:4], chars[4:8], chars[8:12]), nil
}

// GenerateRecoveryCodes returns a fresh set of 10 codes.
func GenerateRecoveryCodes() ([]string, error) {
	out := make([]string, RecoveryCodeCount)
	for i := 0; i < RecoveryCodeCount; i++ {
		c, err := GenerateRecoveryCode()
		if err != nil {
			return nil, err
		}
		out[i] = c
	}
	return out, nil
}

// NormalizeRecoveryInput uppercases + trims a user-input recovery
// code. Hyphens are preserved.
func NormalizeRecoveryInput(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}

// IsValidRecoveryCode reports whether code is in the canonical
// XXXX-XXXX-XXXX form with characters from the recovery alphabet.
func IsValidRecoveryCode(code string) bool {
	if len(code) != RecoveryCodeLength+2 {
		return false
	}
	parts := strings.Split(code, "-")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) != 4 {
			return false
		}
		for _, c := range p {
			if !strings.ContainsRune(recoveryAlphabet, c) {
				return false
			}
		}
	}
	return true
}

// ErrWebAuthnNotImplemented is returned by EnrollWebAuthnFactor /
// ConfirmWebAuthnFactor / VerifyMfa(WebAuthn) until the WebAuthn
// assertion verifier lands in a follow-up session.
//
// The factor record + lifecycle are usable; only the cryptographic
// assertion verification (ES256/RS256/EdDSA over authenticatorData +
// clientDataJSON) is deferred.
var ErrWebAuthnNotImplemented = errors.New("WebAuthn assertion verification not implemented in this Go SDK release (follow-up session); ES256/RS256/EdDSA verifier is pinned in ADR 0010")
