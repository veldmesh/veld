// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
)

// ParsePolicyVersionFromPayload extracts the version from a canonical TOML policy payload.
// The version is the first field in the canonical TOML format: "version = <int>".
// Returns the version and an error if the format is invalid.
func ParsePolicyVersionFromPayload(payload []byte) (int, error) {
	return ParsePolicyVersionFromString(string(payload))
}

// ParsePolicyVersionFromString extracts the version from a canonical TOML policy string.
// The version is the first field in the canonical TOML format: "version = <int>".
// Only accepts the canonical first line format: "version = <1-9 digits>\n".
// Returns the version and an error if the format is invalid.
func ParsePolicyVersionFromString(tomlStr string) (int, error) {
	const prefix = "version = "
	idx := 0
	// Skip leading whitespace (space, tab, newline, carriage return)
	for idx < len(tomlStr) && (tomlStr[idx] == ' ' || tomlStr[idx] == '\t' || tomlStr[idx] == '\n' || tomlStr[idx] == '\r') {
		idx++
	}
	if idx+len(prefix) > len(tomlStr) {
		return 0, errors.New("version field not found")
	}
	if tomlStr[idx:idx+len(prefix)] != prefix {
		return 0, errors.New("version field not found")
	}
	idx += len(prefix)
	if idx >= len(tomlStr) {
		return 0, errors.New("version value missing")
	}
	// Must have at least one digit
	if tomlStr[idx] < '0' || tomlStr[idx] > '9' {
		return 0, errors.New("version value missing digits")
	}
	// Parse integer with range check (max 9 digits to prevent overflow)
	var v int
	digits := 0
	for idx < len(tomlStr) && tomlStr[idx] >= '0' && tomlStr[idx] <= '9' {
		if digits >= 9 {
			return 0, errors.New("version value too large")
		}
		d := int(tomlStr[idx] - '0')
		// Check for overflow
		if v > (1<<31-1-d)/10 {
			return 0, errors.New("version value overflow")
		}
		v = v*10 + d
		digits++
		idx++
	}
	if digits == 0 {
		return 0, errors.New("version value missing digits")
	}
	if v <= 0 {
		return 0, errors.New("version must be positive")
	}
	// Next character must be newline (canonical format) or end of string
	if idx < len(tomlStr) && tomlStr[idx] != '\n' && tomlStr[idx] != '\r' {
		return 0, errors.New("version line must end with newline")
	}
	return v, nil
}

// ExtractPolicyVersionFromEnvelope parses the version from a network policy envelope
// without verifying the signature or admin keys. The envelope format is:
// magic(4) | format_version(1) | payload_len(4) | payload | signer_pubkey(32) | signature(64)
// Returns the version and an error if the envelope is malformed.
func ExtractPolicyVersionFromEnvelope(envelope []byte) (int, error) {
	if len(envelope) < 9 {
		return 0, errors.New("envelope too small")
	}
	magic := binary.BigEndian.Uint32(envelope[0:4])
	if magic != networkPolicyMagic {
		return 0, errors.New("invalid magic")
	}
	formatVer := envelope[4]
	if formatVer != networkPolicyFormatVer {
		return 0, fmt.Errorf("unsupported envelope format version %d", formatVer)
	}
	payloadLen := binary.BigEndian.Uint32(envelope[5:9])
	if len(envelope) < 9+int(payloadLen) {
		return 0, errors.New("envelope truncated")
	}
	payload := envelope[9 : 9+int(payloadLen)]
	return ParsePolicyVersionFromPayload(payload)
}

// VerifyEnvelopeSignatureAndSigner verifies that the envelope is signed by a pinned admin key.
// Returns the signer public key and an error if verification fails.
func VerifyEnvelopeSignatureAndSigner(envelope []byte, adminKeys map[[32]byte]struct{}) ([32]byte, error) {
	var signerPubKey [32]byte

	if len(adminKeys) == 0 {
		return signerPubKey, errors.New("no admin keys pinned; network policies are ignored")
	}

	payloadLen, signerOffset, sigOffset, err := parseNetworkPolicyHeader(envelope)
	if err != nil {
		return signerPubKey, err
	}

	signerPubKeyBytes := envelope[signerOffset:sigOffset]
	signatureBytes := envelope[sigOffset : sigOffset+networkPolicySignatureLen]

	// Verify signer is pinned
	copy(signerPubKey[:], signerPubKeyBytes)
	if _, ok := adminKeys[signerPubKey]; !ok {
		return signerPubKey, fmt.Errorf("signer %s not pinned", FormatPeerKey(signerPubKey))
	}

	// Verify signature covers magic || format_version || payload_len || payload
	signedData := envelope[:9+payloadLen]
	if !ed25519.Verify(signerPubKey[:], signedData, signatureBytes) {
		return signerPubKey, errors.New("invalid signature")
	}

	return signerPubKey, nil
}
