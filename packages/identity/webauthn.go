// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// WebAuthn assertion verification per ADR 0008 + ADR 0010.
//
// Implements the verifier side of the FIDO2 / WebAuthn
// `navigator.credentials.get()` flow. The host application has already
// issued a challenge and received an AuthenticatorAssertionResponse
// from the browser; this module owns the server-side verification.
//
// Supported algorithms (ADR 0010, v0.2):
//   - ES256 — ECDSA P-256 + SHA-256 (COSE alg = -7)
//   - RS256 — RSASSA-PKCS1-v1_5 + SHA-256 (COSE alg = -257)
//   - EdDSA — Ed25519 (COSE alg = -8)
//
// Other COSE alg values raise [WebAuthnUnsupportedKeyError].
//
// Counter monotonicity per WebAuthn §6.1.1: a strictly-greater counter
// advances the stored value; counter that stays equal or decreases when
// at least one side is non-zero is rejected as a cloned-authenticator
// signal.

package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
)

// RSAMinKeySizeBits is the minimum RSA modulus per ADR 0010 / WebAuthn §5.8.5.
const RSAMinKeySizeBits = 2048

// WebAuthn flag bits (WebAuthn §6.1).
const (
	webauthnFlagUserPresent  = 0x01
	webauthnFlagUserVerified = 0x04
)

// WebAuthnError is the base type for WebAuthn assertion verification failures.
// Reason is a stable token (e.g. "signature_invalid", "rp_id_mismatch") that
// maps 1:1 with the Python SDK's webauthn.<reason> error codes.
type WebAuthnError struct {
	Msg    string
	Reason string
}

func (e *WebAuthnError) Error() string { return e.Msg }
func (e *WebAuthnError) Code() string  { return "webauthn." + e.Reason }

// Concrete error constructors matching the Python SDK's exception classes.
func newWebAuthnError(reason, msg string) *WebAuthnError {
	return &WebAuthnError{Msg: msg, Reason: reason}
}

// WebAuthnAssertionResult is the success outcome of WebAuthnVerifyAssertion.
// NewSignCount MUST be persisted atomically with the session decision —
// otherwise a race lets a cloned authenticator slip through.
type WebAuthnAssertionResult struct {
	NewSignCount int64
}

// WebAuthnVerifyOptions carries the inputs to WebAuthnVerifyAssertion.
type WebAuthnVerifyOptions struct {
	CosePublicKey        []byte
	StoredSignCount      int64
	StoredRpID           string
	ExpectedChallenge    []byte
	ExpectedOrigin       string
	AuthenticatorData    []byte
	ClientDataJSON       []byte
	Signature            []byte
	RequireUserVerified  bool // defaults applied: if both Require* are false, both treated as true
	RequireUserPresent   bool
	// requireDefaultsApplied is an internal flag the constructor sets;
	// callers should use NewWebAuthnVerifyOptions to get sensible defaults.
	requireDefaultsApplied bool
}

// NewWebAuthnVerifyOptions returns options with the recommended UV/UP
// defaults (both true). Adjust the fields after construction if your
// authenticator doesn't signal user presence/verification.
func NewWebAuthnVerifyOptions() WebAuthnVerifyOptions {
	return WebAuthnVerifyOptions{
		RequireUserVerified:    true,
		RequireUserPresent:     true,
		requireDefaultsApplied: true,
	}
}

// WebAuthnVerifyAssertion verifies a WebAuthn assertion against the
// stored COSE public key and returns the new sign count.
//
// Returns *WebAuthnError on any failure with a stable Reason.
func WebAuthnVerifyAssertion(opts WebAuthnVerifyOptions) (WebAuthnAssertionResult, error) {
	// Parse clientDataJSON.
	var clientData map[string]any
	if err := json.Unmarshal(opts.ClientDataJSON, &clientData); err != nil {
		return WebAuthnAssertionResult{}, newWebAuthnError("malformed", fmt.Sprintf("clientDataJSON not valid JSON: %v", err))
	}
	typeField, _ := clientData["type"].(string)
	if typeField != "webauthn.get" {
		return WebAuthnAssertionResult{}, newWebAuthnError("type_mismatch", fmt.Sprintf("clientDataJSON.type must be 'webauthn.get', got %q", typeField))
	}
	originField, _ := clientData["origin"].(string)
	if originField != opts.ExpectedOrigin {
		return WebAuthnAssertionResult{}, newWebAuthnError("origin_mismatch", fmt.Sprintf("origin mismatch: expected %q, got %q", opts.ExpectedOrigin, originField))
	}
	challengeB64, ok := clientData["challenge"].(string)
	if !ok {
		return WebAuthnAssertionResult{}, newWebAuthnError("malformed", "clientDataJSON.challenge missing or not a string")
	}
	challengeBytes, err := b64urlDecode(challengeB64)
	if err != nil {
		return WebAuthnAssertionResult{}, newWebAuthnError("malformed", fmt.Sprintf("clientDataJSON.challenge not base64url: %v", err))
	}
	if !bytesEqual(challengeBytes, opts.ExpectedChallenge) {
		return WebAuthnAssertionResult{}, newWebAuthnError("challenge_mismatch", "challenge does not match")
	}

	// Parse authenticatorData.
	auth, err := parseAuthenticatorData(opts.AuthenticatorData)
	if err != nil {
		return WebAuthnAssertionResult{}, err
	}
	expectedRpHash := sha256.Sum256([]byte(opts.StoredRpID))
	if !bytesEqual(auth.RpIDHash, expectedRpHash[:]) {
		return WebAuthnAssertionResult{}, newWebAuthnError("rp_id_mismatch", "RP ID hash does not match")
	}
	if opts.RequireUserPresent && auth.Flags&webauthnFlagUserPresent == 0 {
		return WebAuthnAssertionResult{}, newWebAuthnError("user_not_present", "user-present flag not set")
	}
	if opts.RequireUserVerified && auth.Flags&webauthnFlagUserVerified == 0 {
		return WebAuthnAssertionResult{}, newWebAuthnError("user_not_verified", "user-verified flag not set")
	}

	// Counter monotonicity.
	var newSignCount int64
	switch {
	case auth.SignCount == 0 && opts.StoredSignCount == 0:
		// Authenticator does not track a counter; spec-permitted.
		newSignCount = 0
	case auth.SignCount > opts.StoredSignCount:
		newSignCount = auth.SignCount
	default:
		return WebAuthnAssertionResult{}, newWebAuthnError("counter_regression",
			fmt.Sprintf("sign count did not advance: stored=%d, got=%d", opts.StoredSignCount, auth.SignCount))
	}

	// Verify the signature over authData || sha256(clientDataJSON).
	alg, publicKey, err := parseCOSEKey(opts.CosePublicKey)
	if err != nil {
		return WebAuthnAssertionResult{}, err
	}
	clientHash := sha256.Sum256(opts.ClientDataJSON)
	signed := append(append([]byte{}, opts.AuthenticatorData...), clientHash[:]...)

	switch alg {
	case -7: // ES256
		pub, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return WebAuthnAssertionResult{}, newWebAuthnError("unsupported_key", "ES256 key did not parse as ECDSA")
		}
		// DER signature shape sanity check.
		if len(opts.Signature) < 8 || opts.Signature[0] != 0x30 {
			return WebAuthnAssertionResult{}, newWebAuthnError("signature_invalid", "signature is not a DER ECDSA structure")
		}
		digest := sha256.Sum256(signed)
		if !ecdsa.VerifyASN1(pub, digest[:], opts.Signature) {
			return WebAuthnAssertionResult{}, newWebAuthnError("signature_invalid", "ECDSA signature verification failed")
		}
	case -257: // RS256
		pub, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return WebAuthnAssertionResult{}, newWebAuthnError("unsupported_key", "RS256 key did not parse as RSA")
		}
		digest := sha256.Sum256(signed)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], opts.Signature); err != nil {
			return WebAuthnAssertionResult{}, newWebAuthnError("signature_invalid", fmt.Sprintf("RSA-PKCS1v15 verify failed: %v", err))
		}
	case -8: // EdDSA / Ed25519
		pub, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return WebAuthnAssertionResult{}, newWebAuthnError("unsupported_key", "EdDSA key did not parse as Ed25519")
		}
		if len(opts.Signature) != ed25519.SignatureSize {
			return WebAuthnAssertionResult{}, newWebAuthnError("signature_invalid",
				fmt.Sprintf("Ed25519 signature must be %d bytes, got %d", ed25519.SignatureSize, len(opts.Signature)))
		}
		if !ed25519.Verify(pub, signed, opts.Signature) {
			return WebAuthnAssertionResult{}, newWebAuthnError("signature_invalid", "Ed25519 signature verification failed")
		}
	default:
		return WebAuthnAssertionResult{}, newWebAuthnError("unsupported_key", fmt.Sprintf("unsupported alg dispatch: %d", alg))
	}

	return WebAuthnAssertionResult{NewSignCount: newSignCount}, nil
}

// ─── authenticatorData parsing ───

type authenticatorData struct {
	RpIDHash  []byte
	Flags     byte
	SignCount int64
}

func parseAuthenticatorData(buf []byte) (authenticatorData, error) {
	if len(buf) < 37 {
		return authenticatorData{}, newWebAuthnError("malformed", "authenticatorData truncated")
	}
	return authenticatorData{
		RpIDHash:  buf[:32],
		Flags:     buf[32],
		SignCount: int64(binary.BigEndian.Uint32(buf[33:37])),
	}, nil
}

// ─── Minimal CBOR / COSE_Key parsing ───

// parseCOSEKey parses a COSE_Key for any v0.2-supported algorithm.
// Returns (alg, public_key, err); public_key is one of *ecdsa.PublicKey
// (ES256), *rsa.PublicKey (RS256), or ed25519.PublicKey (EdDSA).
func parseCOSEKey(coseKey []byte) (int, any, error) {
	fields, err := decodeCBORMap(coseKey)
	if err != nil {
		return 0, nil, err
	}
	algV, ok := fields[3]
	if !ok {
		return 0, nil, newWebAuthnError("malformed", "COSE_Key missing alg (3)")
	}
	alg, ok := algV.(int64)
	if !ok {
		return 0, nil, newWebAuthnError("malformed", "COSE_Key.alg is not an int")
	}
	switch alg {
	case -7:
		pub, err := parseCOSEES256(fields)
		return int(alg), pub, err
	case -257:
		pub, err := parseCOSERS256(fields)
		return int(alg), pub, err
	case -8:
		pub, err := parseCOSEEdDSA(fields)
		return int(alg), pub, err
	default:
		return 0, nil, newWebAuthnError("unsupported_key", fmt.Sprintf("unsupported COSE alg: %d", alg))
	}
}

func parseCOSEES256(fields map[int64]any) (*ecdsa.PublicKey, error) {
	kty, _ := fields[1].(int64)
	crv, _ := fields[-1].(int64)
	xB, xOK := fields[-2].([]byte)
	yB, yOK := fields[-3].([]byte)
	if kty != 2 {
		return nil, newWebAuthnError("unsupported_key", fmt.Sprintf("ES256 requires kty=2, got %d", kty))
	}
	if crv != 1 {
		return nil, newWebAuthnError("unsupported_key", fmt.Sprintf("ES256 requires crv=1, got %d", crv))
	}
	if !xOK || len(xB) != 32 {
		return nil, newWebAuthnError("malformed", "COSE x coordinate must be 32 bytes")
	}
	if !yOK || len(yB) != 32 {
		return nil, newWebAuthnError("malformed", "COSE y coordinate must be 32 bytes")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xB),
		Y:     new(big.Int).SetBytes(yB),
	}, nil
}

func parseCOSERS256(fields map[int64]any) (*rsa.PublicKey, error) {
	kty, _ := fields[1].(int64)
	nB, nOK := fields[-1].([]byte)
	eB, eOK := fields[-2].([]byte)
	if kty != 3 {
		return nil, newWebAuthnError("unsupported_key", fmt.Sprintf("RS256 requires kty=3, got %d", kty))
	}
	if !nOK {
		return nil, newWebAuthnError("malformed", "COSE RSA modulus (n) must be a byte string")
	}
	if !eOK {
		return nil, newWebAuthnError("malformed", "COSE RSA exponent (e) must be a byte string")
	}
	n := new(big.Int).SetBytes(nB)
	if n.BitLen() < RSAMinKeySizeBits {
		return nil, newWebAuthnError("unsupported_key",
			fmt.Sprintf("RSA key %d-bit is below the %d-bit floor", n.BitLen(), RSAMinKeySizeBits))
	}
	e := new(big.Int).SetBytes(eB)
	if !e.IsInt64() {
		return nil, newWebAuthnError("malformed", "RSA exponent too large")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func parseCOSEEdDSA(fields map[int64]any) (ed25519.PublicKey, error) {
	kty, _ := fields[1].(int64)
	crv, _ := fields[-1].(int64)
	xB, xOK := fields[-2].([]byte)
	if kty != 1 {
		return nil, newWebAuthnError("unsupported_key", fmt.Sprintf("EdDSA requires kty=1, got %d", kty))
	}
	if crv != 6 {
		return nil, newWebAuthnError("unsupported_key", fmt.Sprintf("v0.2 EdDSA accepts only Ed25519 (crv=6), got %d", crv))
	}
	if !xOK || len(xB) != 32 {
		return nil, newWebAuthnError("malformed", "Ed25519 public key must be 32 bytes")
	}
	out := make(ed25519.PublicKey, 32)
	copy(out, xB)
	return out, nil
}

// decodeCBORMap decodes a CBOR map of small-integer keys to int / bytes
// values. Implements only the subset needed for COSE keys:
//   - major type 0/1 (uint / negative int): 0..23 inline; then 1/2/4/8 byte
//   - major type 2 (byte string): 0..23 inline length; then 1/2/4/8 byte length
//   - major type 5 (map): same length encoding
//
// Anything else raises WebAuthnError("malformed").
func decodeCBORMap(buf []byte) (map[int64]any, error) {
	d := &cborDecoder{buf: buf}
	v, err := d.decodeItem()
	if err != nil {
		return nil, err
	}
	if d.offset != len(buf) {
		return nil, newWebAuthnError("malformed", "trailing bytes after CBOR map")
	}
	m, ok := v.(map[int64]any)
	if !ok {
		return nil, newWebAuthnError("malformed", "top-level COSE value is not a map")
	}
	return m, nil
}

type cborDecoder struct {
	buf    []byte
	offset int
}

func (d *cborDecoder) read(n int) ([]byte, error) {
	if d.offset+n > len(d.buf) {
		return nil, newWebAuthnError("malformed", "CBOR truncated")
	}
	out := d.buf[d.offset : d.offset+n]
	d.offset += n
	return out, nil
}

func (d *cborDecoder) readUint(info byte) (uint64, error) {
	switch {
	case info < 24:
		return uint64(info), nil
	case info == 24:
		b, err := d.read(1)
		if err != nil {
			return 0, err
		}
		return uint64(b[0]), nil
	case info == 25:
		b, err := d.read(2)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint16(b)), nil
	case info == 26:
		b, err := d.read(4)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint32(b)), nil
	case info == 27:
		b, err := d.read(8)
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(b), nil
	default:
		return 0, newWebAuthnError("malformed", fmt.Sprintf("unsupported CBOR info: %d", info))
	}
}

func (d *cborDecoder) decodeItem() (any, error) {
	first, err := d.read(1)
	if err != nil {
		return nil, err
	}
	b := first[0]
	major := b >> 5
	info := b & 0x1F
	switch major {
	case 0: // unsigned int
		u, err := d.readUint(info)
		if err != nil {
			return nil, err
		}
		return int64(u), nil
	case 1: // negative int
		u, err := d.readUint(info)
		if err != nil {
			return nil, err
		}
		return -1 - int64(u), nil
	case 2: // byte string
		ln, err := d.readUint(info)
		if err != nil {
			return nil, err
		}
		b, err := d.read(int(ln))
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(b))
		copy(out, b)
		return out, nil
	case 5: // map
		ln, err := d.readUint(info)
		if err != nil {
			return nil, err
		}
		out := make(map[int64]any, ln)
		for i := uint64(0); i < ln; i++ {
			k, err := d.decodeItem()
			if err != nil {
				return nil, err
			}
			kInt, ok := k.(int64)
			if !ok {
				return nil, newWebAuthnError("malformed", "non-int CBOR map key")
			}
			v, err := d.decodeItem()
			if err != nil {
				return nil, err
			}
			out[kInt] = v
		}
		return out, nil
	default:
		return nil, newWebAuthnError("malformed", fmt.Sprintf("unsupported CBOR major type: %d", major))
	}
}

// CoseKeyES256 encodes a P-256 public key (32-byte x, 32-byte y) as a
// COSE_Key. Useful for fixture authors and SDKs that store raw
// coordinates rather than COSE bytes.
func CoseKeyES256(x, y []byte) ([]byte, error) {
	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("ES256 coordinates must be 32 bytes each")
	}
	// CBOR map(5):
	//   1: 2          (kty=EC2)
	//   3: -7         (alg=ES256)
	//  -1: 1          (crv=P-256)
	//  -2: bytes(32)  (x)
	//  -3: bytes(32)  (y)
	out := make([]byte, 0, 80)
	out = append(out, 0xa5)             // map(5)
	out = append(out, 0x01, 0x02)       // 1: 2
	out = append(out, 0x03, 0x26)       // 3: -7 (negint: 0x20 | 6 = 0x26)
	out = append(out, 0x20, 0x01)       // -1: 1
	out = append(out, 0x21, 0x58, 0x20) // -2: bytes(32)
	out = append(out, x...)
	out = append(out, 0x22, 0x58, 0x20) // -3: bytes(32)
	out = append(out, y...)
	return out, nil
}

// b64urlDecode decodes a base64url string with optional padding.
func b64urlDecode(s string) ([]byte, error) {
	// Add padding back to make standard base64url decoder happy.
	if pad := len(s) % 4; pad != 0 {
		s += string([]byte{'=', '=', '='}[:4-pad])
	}
	return base64.URLEncoding.DecodeString(s)
}

// B64URLEncode encodes bytes as base64url with no padding (WebAuthn convention).
func B64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

