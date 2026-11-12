// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fsnotify/fsnotify"
)

// NetworkPolicyEnvelope is the on-disk format for a signed network policy.
// Format: magic(4) | format_version(1) | payload_len(4) | payload | signer_pubkey(32) | signature(64)
//
// Payload is the canonical TOML encoding of the policy (version, default, peers, tags, rules, outbound_only).
// The signature covers: magic || format_version || payload_len || payload
const (
	networkPolicyMagic        = 0x56454C44 // "VELD" in ASCII
	networkPolicyFormatVer    = 1
	networkPolicySignerLen    = 32
	networkPolicySignatureLen = 64
	networkPolicyHeaderSize   = 4 + 1 + 4 + networkPolicySignerLen + networkPolicySignatureLen
	maxNetworkPolicyFileSize  = 1024 * 1024 // 1MB max file size for defense-in-depth
)

// NetworkPolicyEnvelope represents a parsed and verified signed policy envelope.
type NetworkPolicyEnvelope struct {
	Policy       *Policy
	SignerPubKey [32]byte
	Version      int
	RawPayload   []byte // The canonical TOML bytes that were signed
	RawEnvelope  []byte // The full envelope bytes
}

// parseNetworkPolicyHeader parses and validates the envelope header.
// Returns (payloadLen, signerOffset, sigOffset, error).
// Uses uint64 arithmetic to avoid overflow/wrapping.
func parseNetworkPolicyHeader(data []byte) (payloadLen int, signerOffset int, sigOffset int, err error) {
	if len(data) < networkPolicyHeaderSize {
		return 0, 0, 0, errors.New("envelope too small")
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != networkPolicyMagic {
		return 0, 0, 0, errors.New("invalid magic")
	}

	formatVer := data[4]
	if formatVer != networkPolicyFormatVer {
		return 0, 0, 0, fmt.Errorf("unsupported envelope format version %d", formatVer)
	}

	// Use uint64 to avoid wrapping on malformed payloadLen
	payloadLen64 := uint64(binary.BigEndian.Uint32(data[5:9]))
	// Total expected length: header (9) + payload + signer (32) + signature (64)
	expectedLen := uint64(9) + payloadLen64 + uint64(networkPolicySignerLen) + uint64(networkPolicySignatureLen)
	if uint64(len(data)) != expectedLen {
		return 0, 0, 0, errors.New("envelope length mismatch")
	}

	return int(payloadLen64), 9 + int(payloadLen64), 9 + int(payloadLen64) + networkPolicySignerLen, nil
}

// ParseNetworkPolicyEnvelope parses and verifies a signed network policy envelope.
// adminKeys is the set of pinned admin public keys.
// Returns the envelope if valid and signed by a pinned key.
// If adminKeys is empty, network policies are not accepted (returns error).
func ParseNetworkPolicyEnvelope(data []byte, adminKeys map[[32]byte]struct{}) (*NetworkPolicyEnvelope, error) {
	if len(adminKeys) == 0 {
		return nil, errors.New("no admin keys pinned; network policies are ignored")
	}

	payloadLen, signerOffset, sigOffset, err := parseNetworkPolicyHeader(data)
	if err != nil {
		return nil, err
	}

	payload := data[9:signerOffset]
	signerPubKeyBytes := data[signerOffset:sigOffset]
	signatureBytes := data[sigOffset : sigOffset+networkPolicySignatureLen]

	// Verify signer is pinned
	var signerPubKey [32]byte
	copy(signerPubKey[:], signerPubKeyBytes)
	if _, ok := adminKeys[signerPubKey]; !ok {
		return nil, fmt.Errorf("signer %s not pinned", formatPeerKey(signerPubKey))
	}

	// Verify signature covers magic || format_version || payload_len || payload
	signedData := data[:9+payloadLen]
	if !ed25519.Verify(signerPubKey[:], signedData, signatureBytes) {
		return nil, errors.New("invalid signature")
	}

	// Parse the policy from canonical TOML payload
	p, _, err := ParsePolicy(string(payload))
	if err != nil {
		return nil, fmt.Errorf("parse policy payload: %w", err)
	}

	return &NetworkPolicyEnvelope{
		Policy:       p,
		SignerPubKey: signerPubKey,
		Version:      p.Version,
		RawPayload:   payload,
		RawEnvelope:  data,
	}, nil
}

// ParseNetworkPolicyEnvelopeUnverified parses a network policy envelope without verifying the signature or admin keys.
// Used for reading the version from an existing file.
func ParseNetworkPolicyEnvelopeUnverified(data []byte) (*NetworkPolicyEnvelope, error) {
	_, signerOffset, sigOffset, err := parseNetworkPolicyHeader(data)
	if err != nil {
		return nil, err
	}

	payload := data[9:signerOffset]
	signerPubKeyBytes := data[signerOffset:sigOffset]
	_ = data[sigOffset : sigOffset+networkPolicySignatureLen]

	// Parse the policy from canonical TOML payload
	p, _, err := ParsePolicy(string(payload))
	if err != nil {
		return nil, fmt.Errorf("parse policy payload: %w", err)
	}

	var signerPubKey [32]byte
	copy(signerPubKey[:], signerPubKeyBytes)

	return &NetworkPolicyEnvelope{
		Policy:       p,
		SignerPubKey: signerPubKey,
		Version:      p.Version,
		RawPayload:   payload,
		RawEnvelope:  data,
	}, nil
}

// SignPolicy creates a signed network policy envelope from a policy TOML string.
// adminKey is the Ed25519 private key (64 bytes).
// Returns the full envelope bytes.
func SignPolicy(policyTOML string, adminKey ed25519.PrivateKey) ([]byte, error) {
	// Parse and validate the policy first
	p, _, err := ParsePolicy(policyTOML)
	if err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	// Canonicalize the policy TOML (re-encode to ensure consistent format)
	canonicalTOML, err := canonicalizePolicy(p)
	if err != nil {
		return nil, fmt.Errorf("canonicalize policy: %w", err)
	}

	payload := []byte(canonicalTOML)

	// Build the signed data: magic || format_version || payload_len || payload
	signedData := make([]byte, 9+len(payload))
	binary.BigEndian.PutUint32(signedData[0:4], networkPolicyMagic)
	signedData[4] = networkPolicyFormatVer
	binary.BigEndian.PutUint32(signedData[5:9], uint32(len(payload)))
	copy(signedData[9:], payload)

	// Sign
	signature := ed25519.Sign(adminKey, signedData)

	// Get public key from private key
	pubKey := adminKey.Public().(ed25519.PublicKey)

	// Build full envelope: signedData || signer_pubkey || signature
	envelope := make([]byte, len(signedData)+networkPolicySignerLen+networkPolicySignatureLen)
	copy(envelope, signedData)
	copy(envelope[len(signedData):], pubKey)
	copy(envelope[len(signedData)+networkPolicySignerLen:], signature)

	return envelope, nil
}

// canonicalizePolicy re-encodes a Policy to a deterministic TOML format for signing.
// This ensures the same policy always produces the same signature.
func canonicalizePolicy(p *Policy) (string, error) {
	type canonicalRule struct {
		From  string   `toml:"from"`
		To    string   `toml:"to"`
		Ports []string `toml:"ports"`
	}
	type canonicalOutboundOnly struct {
		Peers []string `toml:"peers"`
	}
	type canonicalPolicy struct {
		Version      int                   `toml:"version"`
		Default      string                `toml:"default"`
		Peers        map[string]string     `toml:"peers"`
		Tags         map[string][]string   `toml:"tags"`
		Rules        []canonicalRule       `toml:"rule"`
		OutboundOnly canonicalOutboundOnly `toml:"outbound_only"`
	}

	cp := canonicalPolicy{
		Version:      p.Version,
		Default:      p.Default.String(),
		Peers:        make(map[string]string, len(p.Peers)),
		Tags:         make(map[string][]string, len(p.Tags)),
		Rules:        make([]canonicalRule, len(p.Rules)),
		OutboundOnly: canonicalOutboundOnly{Peers: slices.Clone(p.OutboundOnly)},
	}

	// Peers need to be serialized with ed25519: prefix (base64) - sort keys for determinism
	peerNames := slices.Sorted(maps.Keys(p.Peers))
	for _, name := range peerNames {
		cp.Peers[name] = formatPeerKey(p.Peers[name])
	}

	// Tags - sort keys and values for determinism
	tagNames := slices.Sorted(maps.Keys(p.Tags))
	for _, tagName := range tagNames {
		peers := p.Tags[tagName]
		cp.Tags[tagName] = slices.Clone(peers)
		slices.Sort(cp.Tags[tagName])
	}

	// Sort OutboundOnly peers for determinism
	slices.Sort(cp.OutboundOnly.Peers)

	// Rules need ports formatted
	for i, rule := range p.Rules {
		ports := make([]string, len(rule.Ports))
		for j, pr := range rule.Ports {
			ports[j] = formatPortRange(pr)
		}
		cp.Rules[i] = canonicalRule{
			From:  rule.From,
			To:    rule.To,
			Ports: ports,
		}
	}

	var buf strings.Builder
	enc := toml.NewEncoder(&buf)
	if err := enc.Encode(cp); err != nil {
		return "", fmt.Errorf("encode canonical policy: %w", err)
	}
	return buf.String(), nil
}

// atomicWriteFile writes data to a file atomically (write to temp, then rename).
// On Windows, removes the destination file first since os.Rename fails if it exists.
// Also handles read-only files on Windows by removing the read-only attribute.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	// On Windows, os.Rename fails if destination exists. Remove first.
	// Also handle read-only files by removing the read-only attribute.
	if runtime.GOOS == "windows" {
		// Remove read-only attribute if present, then remove the file.
		_ = os.Chmod(path, 0o600)
		_ = os.Remove(path)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename file: %w", err)
	}
	return nil
}

// WriteNetworkPolicyFile writes a signed policy envelope to a file with 0600 permissions.
// Refuses to overwrite if the existing file has a version >= the new policy's version.
func WriteNetworkPolicyFile(path string, envelope []byte, newVersion int) error {
	// Check existing file version
	if _, err := os.Stat(path); err == nil {
		existingData, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read existing policy: %w", err)
		}
		existingEnv, err := ParseNetworkPolicyEnvelopeUnverified(existingData)
		if err == nil && existingEnv.Version >= newVersion {
			return fmt.Errorf("existing policy version %d >= new version %d; refusing to overwrite", existingEnv.Version, newVersion)
		}
	}

	// Write with 0600 permissions atomically
	if err := atomicWriteFile(path, envelope, 0o600); err != nil {
		return fmt.Errorf("write policy file: %w", err)
	}
	return nil
}

// ReadNetworkPolicyFile reads and parses a signed network policy file.
// Returns the envelope if valid and signed by a pinned key.
func ReadNetworkPolicyFile(path string, adminKeys map[[32]byte]struct{}) (*NetworkPolicyEnvelope, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat policy file: %w", err)
	}

	// Defense-in-depth: limit file size to prevent OOM from maliciously large files
	if info.Size() > maxNetworkPolicyFileSize {
		return nil, fmt.Errorf("policy file too large: %d bytes (max %d)", info.Size(), maxNetworkPolicyFileSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return ParseNetworkPolicyEnvelope(data, adminKeys)
}

// NetworkPolicyStore persists the highest accepted network policy version and envelope.
// It lives next to the identity file (0600).
type NetworkPolicyStore struct {
	path string
	mu   sync.Mutex
}

// NewNetworkPolicyStore creates a new store at the given path (directory containing identity file).
func NewNetworkPolicyStore(identityPath string) *NetworkPolicyStore {
	dir := filepath.Dir(identityPath)
	return &NetworkPolicyStore{
		path: filepath.Join(dir, "network-policy.bin"),
	}
}

// Load loads the stored network policy envelope.
// Returns (nil, nil) if no stored policy exists.
// If the stored policy's signer is not in current adminKeys, returns (nil, nil) to allow graceful admin key rotation.
func (s *NetworkPolicyStore) Load(adminKeys map[[32]byte]struct{}) (*NetworkPolicyEnvelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read network policy store: %w", err)
	}

	// Parse without verifying admin keys first to get the signer
	env, err := ParseNetworkPolicyEnvelopeUnverified(data)
	if err != nil {
		return nil, fmt.Errorf("parse stored network policy: %w", err)
	}

	// Verify signer is currently pinned; if not, treat as no stored policy (graceful admin key rotation)
	if _, ok := adminKeys[env.SignerPubKey]; !ok {
		log.Printf("network policy: stored policy signer %s not in current admin keys, ignoring (admin key rotation)", formatPeerKey(env.SignerPubKey))
		return nil, nil
	}

	// Now verify the full envelope with admin keys
	env, err = ParseNetworkPolicyEnvelope(data, adminKeys)
	if err != nil {
		return nil, fmt.Errorf("parse stored network policy: %w", err)
	}
	return env, nil
}

// Store atomically stores a new network policy envelope if its version is higher than the stored one.
// Returns true if stored, false if rejected (version not higher).
func (s *NetworkPolicyStore) Store(env *NetworkPolicyEnvelope, adminKeys map[[32]byte]struct{}) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verify the envelope is valid and signed by a pinned key
	if _, err := ParseNetworkPolicyEnvelope(env.RawEnvelope, adminKeys); err != nil {
		return false, fmt.Errorf("invalid envelope: %w", err)
	}

	// Check existing version
	existingData, err := os.ReadFile(s.path)
	if err == nil {
		existingEnv, err := ParseNetworkPolicyEnvelope(existingData, adminKeys)
		if err == nil && existingEnv.Version >= env.Version {
			return false, fmt.Errorf("version %d not higher than stored version %d", env.Version, existingEnv.Version)
		}
	}

	// Write atomically (write to temp, then rename)
	if err := atomicWriteFile(s.path, env.RawEnvelope, 0o600); err != nil {
		return false, fmt.Errorf("store network policy: %w", err)
	}
	return true, nil
}

// GetPath returns the store file path.
func (s *NetworkPolicyStore) GetPath() string {
	return s.path
}

// LoadedNetworkPolicy represents a loaded and verified network policy ready for enforcement.
type LoadedNetworkPolicy struct {
	Envelope  *NetworkPolicyEnvelope
	Compiled  *CompiledPolicy
	SignerStr string // "ed25519:<base64>"
	Age       string // human-readable age
}

// LoadNetworkPolicy loads a network policy from a file, verifies it against admin keys,
// checks version against the store, and persists if accepted.
// Returns the loaded policy and whether it was newly stored (vs already stored).
func LoadNetworkPolicy(policyPath, identityPath string, adminKeys map[[32]byte]struct{}) (*LoadedNetworkPolicy, bool, error) {
	store := NewNetworkPolicyStore(identityPath)

	// Read and verify the new policy file
	newEnv, err := ReadNetworkPolicyFile(policyPath, adminKeys)
	if err != nil {
		return nil, false, fmt.Errorf("read network policy file: %w", err)
	}

	// Load existing stored policy
	storedEnv, err := store.Load(adminKeys)
	if err != nil {
		return nil, false, fmt.Errorf("load stored policy: %w", err)
	}

	// If we have a stored policy and the new one is not higher version, check if it's the same version
	if storedEnv != nil && newEnv.Version <= storedEnv.Version {
		if newEnv.Version == storedEnv.Version {
			// Same version already stored - use the stored one
			compiled := storedEnv.Policy.Compile()
			signerStr := formatPeerKey(storedEnv.SignerPubKey)
			age := computeAge(policyPath)
			return &LoadedNetworkPolicy{
				Envelope:  storedEnv,
				Compiled:  compiled,
				SignerStr: signerStr,
				Age:       age,
			}, false, nil
		}
		// Lower version - reject as rollback
		return nil, false, fmt.Errorf("policy version %d not higher than stored version %d (possible rollback)", newEnv.Version, storedEnv.Version)
	}

	// Store the new policy
	stored, err := store.Store(newEnv, adminKeys)
	if err != nil {
		return nil, false, fmt.Errorf("store network policy: %w", err)
	}

	// Use the stored envelope (either newly stored or existing)
	env := newEnv
	if !stored {
		env = storedEnv
	}

	// Compile the policy
	compiled := env.Policy.Compile()

	signerStr := formatPeerKey(env.SignerPubKey)
	age := computeAge(policyPath)

	return &LoadedNetworkPolicy{
		Envelope:  env,
		Compiled:  compiled,
		SignerStr: signerStr,
		Age:       age,
	}, stored, nil
}

// LoadNetworkPolicyFromStore loads the highest-version network policy from the store.
// Returns the loaded policy or (nil, nil) if no stored policy exists or admin keys are empty.
// Does not read from the network policy file - only from the store.
// This is called at daemon startup to enforce the stored policy before the tunnel comes up.
func LoadNetworkPolicyFromStore(identityPath string, adminKeys map[[32]byte]struct{}) (*LoadedNetworkPolicy, error) {
	if len(adminKeys) == 0 {
		return nil, nil
	}
	store := NewNetworkPolicyStore(identityPath)
	storedEnv, err := store.Load(adminKeys)
	if err != nil {
		return nil, fmt.Errorf("load stored network policy: %w", err)
	}
	if storedEnv == nil {
		return nil, nil
	}
	compiled := storedEnv.Policy.Compile()
	signerStr := formatPeerKey(storedEnv.SignerPubKey)
	// Age is unknown since we don't have the policy file path; use "stored"
	age := "stored"
	return &LoadedNetworkPolicy{
		Envelope:  storedEnv,
		Compiled:  compiled,
		SignerStr: signerStr,
		Age:       age,
	}, nil
}

// computeAge returns a human-readable age string from the file's modification time.
func computeAge(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "unknown"
	}
	return humanizeDuration(time.Since(info.ModTime()))
}

// humanizeDuration returns a human-readable duration string.
// Uses precise calendar arithmetic for months/years.
func humanizeDuration(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	// For days and beyond, use precise calendar arithmetic
	now := time.Now()
	then := now.Add(-d)

	// Calculate years, months, days precisely using date arithmetic
	years, months, days := dateDiff(then, now)

	if years > 0 {
		if months > 0 {
			return fmt.Sprintf("%dy%dmo", years, months)
		}
		return fmt.Sprintf("%dy", years)
	}
	if months > 0 {
		if days > 0 {
			return fmt.Sprintf("%dmo%dd", months, days)
		}
		return fmt.Sprintf("%dmo", months)
	}
	return fmt.Sprintf("%dd", days)
}

// dateDiff calculates the difference between two dates in years, months, and days.
// start must be before or equal to end.
// Uses precise calendar arithmetic that handles leap years and month-end boundaries correctly.
func dateDiff(start, end time.Time) (years, months, days int) {
	// Normalize to UTC for consistent day boundaries
	start = start.UTC()
	end = end.UTC()

	// Add years using clamped month addition
	for addMonthsClamped(start, (years+1)*12).Before(end) || addMonthsClamped(start, (years+1)*12).Equal(end) {
		years++
	}

	// Add months - use intermediate date after years
	afterYears := addMonthsClamped(start, years*12)
	for addMonthsClamped(afterYears, months+1).Before(end) || addMonthsClamped(afterYears, months+1).Equal(end) {
		months++
	}

	// Add days - use intermediate date after years and months
	afterMonths := addMonthsClamped(afterYears, months)
	for afterMonths.AddDate(0, 0, days+1).Before(end) || afterMonths.AddDate(0, 0, days+1).Equal(end) {
		days++
	}

	return years, months, days
}

// addMonthsClamped adds months to a time, clamping the day to the month's last day if needed.
// e.g., Jan 31 + 1 month = Feb 28 (or 29 in leap year), not Mar 2.
func addMonthsClamped(t time.Time, months int) time.Time {
	year := t.Year()
	month := int(t.Month()) + months
	day := t.Day()

	// Normalize year and month
	year += (month - 1) / 12
	month = (month-1)%12 + 1

	// Clamp day to month length
	maxDay := daysInMonthFor(year, month)
	if day > maxDay {
		day = maxDay
	}

	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
}

// daysInMonthFor returns the number of days in the given year and month.
func daysInMonthFor(year int, month int) int {
	return time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// NetworkPolicyLoader manages the network policy file (static mode).
// It watches the file for changes and reloads on SIGHUP/IPC.
type NetworkPolicyLoader struct {
	path            string
	identityPath    string
	adminKeys       map[[32]byte]struct{}
	swap            *PolicySwap
	stopCh          chan struct{}
	stopOnce        sync.Once // for idempotent Wait()
	watcher         *fsnotify.Watcher
	wg              sync.WaitGroup
	mu              sync.RWMutex
	current         *LoadedNetworkPolicy
	dropCounters    *DropCounters
	loggedEmptyKeys bool      // whether we've logged the "no admin keys" message
	lastModTime     time.Time // for debouncing file events
}

// NewNetworkPolicyLoader creates a new network policy loader for static mode.
// policyPath is the path to the signed policy file.
// identityPath is the path to the node's identity file (store lives next to it).
// adminKeys is the set of pinned admin public keys.
// swap is the PolicySwap to update with the compiled network policy.
func NewNetworkPolicyLoader(policyPath, identityPath string, adminKeys map[[32]byte]struct{}, swap *PolicySwap) *NetworkPolicyLoader {
	return &NetworkPolicyLoader{
		path:         policyPath,
		identityPath: identityPath,
		adminKeys:    adminKeys,
		swap:         swap,
		stopCh:       make(chan struct{}),
		dropCounters: NewDropCounters(),
	}
}

// Load loads the network policy from the file and updates the PolicySwap.
// If the file does not exist or is invalid, logs the error and keeps the current policy.
// If adminKeys is empty, network policies are ignored (logged once).
func (l *NetworkPolicyLoader) Load() error {
	if len(l.adminKeys) == 0 {
		// No admin keys pinned = network policies ignored (log once)
		if !l.loggedEmptyKeys {
			log.Printf("network policy: no admin keys pinned, ignoring network policy")
			l.loggedEmptyKeys = true
		}
		l.swap.Store(nil)
		l.mu.Lock()
		l.current = nil
		l.mu.Unlock()
		return nil
	}

	// Try to load from the file
	info, err := os.Stat(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// File doesn't exist - keep current policy (from store)
			log.Printf("network policy: file %s not found, keeping stored policy", l.path)
			return nil
		}
		// Other stat error - keep current policy
		log.Printf("network policy: stat error: %v, keeping stored policy", err)
		return nil
	}

	// Validate file permissions (same as local policy)
	if err := validatePolicyFilePermissions(l.path, info); err != nil {
		log.Printf("network policy: permission error: %v, keeping stored policy", err)
		return nil
	}

	loaded, _, err := LoadNetworkPolicy(l.path, l.identityPath, l.adminKeys)
	if err != nil {
		// Invalid file - log error and keep current policy
		log.Printf("network policy: load error: %v, keeping stored policy", err)
		return nil
	}

	// Store the compiled network policy
	l.swap.Store(loaded.Compiled)

	l.mu.Lock()
	l.current = loaded
	l.mu.Unlock()

	return nil
}

// LoadStoredPolicy loads the network policy from the store (not the file).
// This is called at daemon startup to enforce the stored policy before the tunnel comes up.
func (l *NetworkPolicyLoader) LoadStoredPolicy() error {
	if len(l.adminKeys) == 0 {
		// No admin keys pinned = network policies ignored (log once)
		if !l.loggedEmptyKeys {
			log.Printf("network policy: no admin keys pinned, ignoring network policy")
			l.loggedEmptyKeys = true
		}
		l.swap.Store(nil)
		l.mu.Lock()
		l.current = nil
		l.mu.Unlock()
		return nil
	}

	loaded, err := LoadNetworkPolicyFromStore(l.identityPath, l.adminKeys)
	if err != nil {
		log.Printf("network policy: load stored policy error: %v", err)
		return nil // Don't fail startup
	}
	if loaded == nil {
		// No stored policy
		l.swap.Store(nil)
		l.mu.Lock()
		l.current = nil
		l.mu.Unlock()
		return nil
	}

	// Store the compiled network policy
	l.swap.Store(loaded.Compiled)

	l.mu.Lock()
	l.current = loaded
	l.mu.Unlock()

	return nil
}

// StartWatcher starts watching the network policy file for changes.
func (l *NetworkPolicyLoader) StartWatcher() error {
	if l.path == "" {
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create file watcher: %w", err)
	}
	l.watcher = watcher

	dir := filepath.Dir(l.path)
	if err := watcher.Add(dir); err != nil {
		if closeErr := watcher.Close(); closeErr != nil {
			return fmt.Errorf("watch policy dir: %w (close watcher: %v)", err, closeErr)
		}
		return fmt.Errorf("watch policy dir: %w", err)
	}

	l.wg.Add(1)
	go l.watchLoop()
	return nil
}

// Wait blocks until the watcher goroutine exits. Idempotent.
func (l *NetworkPolicyLoader) Wait() {
	l.stopOnce.Do(func() {
		close(l.stopCh)
		if l.watcher != nil {
			_ = l.watcher.Close()
		}
		l.wg.Wait()
	})
}

func (l *NetworkPolicyLoader) watchLoop() {
	defer l.wg.Done()
	for {
		select {
		case <-l.stopCh:
			return
		case event, ok := <-l.watcher.Events:
			if !ok {
				return
			}
			if filepath.Clean(event.Name) != filepath.Clean(l.path) {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}

			// Debounce: ignore rapid successive events (100ms, same as local policy)
			l.mu.Lock()
			now := time.Now()
			if now.Sub(l.lastModTime) < 100*time.Millisecond {
				l.mu.Unlock()
				continue
			}
			l.lastModTime = now
			l.mu.Unlock()

			// Reload policy
			if err := l.Load(); err != nil {
				log.Printf("network policy error: %v", err)
			} else {
				log.Printf("network policy: reloaded from %s", l.path)
			}
		case err, ok := <-l.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("network policy watcher error: %v", err)
		}
	}
}

// Reload triggers a manual network policy reload (e.g., on SIGHUP/IPC).
func (l *NetworkPolicyLoader) Reload() error {
	if err := l.Load(); err != nil {
		return err
	}
	log.Printf("network policy: reloaded from %s", l.path)
	return nil
}

// Current returns the currently loaded network policy.
func (l *NetworkPolicyLoader) Current() *LoadedNetworkPolicy {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.current
}

// DropCounters returns the drop counters.
func (l *NetworkPolicyLoader) DropCounters() *DropCounters {
	return l.dropCounters
}

// NetworkPolicyStatus returns the status of the network policy for the IPC endpoint.
func (l *NetworkPolicyLoader) NetworkPolicyStatus() NetworkPolicyStatus {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.current == nil {
		return NetworkPolicyStatus{}
	}

	return NetworkPolicyStatus{
		Version: l.current.Envelope.Version,
		Signer:  l.current.SignerStr,
		Age:     l.current.Age,
	}
}

// NetworkPolicyStatus represents the status of a network policy.
type NetworkPolicyStatus struct {
	Version int    `json:"version"`
	Signer  string `json:"signer"`
	Age     string `json:"age"`
}

// ParseAdminKeys parses a list of "ed25519:<base64 or hex>" strings into a set of PeerKeys.
// Tries base64 first (matches CLI output format), then hex.
func ParseAdminKeys(keys []string) (map[[32]byte]struct{}, error) {
	result := make(map[[32]byte]struct{}, len(keys))
	for _, k := range keys {
		if !strings.HasPrefix(k, "ed25519:") {
			return nil, fmt.Errorf("admin key must start with \"ed25519:\": %q", k)
		}
		encoded := k[len("ed25519:"):]
		var key [32]byte
		// Try base64 first (matches CLI output format)
		if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
			if len(decoded) == 32 {
				copy(key[:], decoded)
			} else {
				// Not a valid 32-byte base64 key, try hex
				if decoded, err := hex.DecodeString(encoded); err == nil {
					if len(decoded) != 32 {
						return nil, fmt.Errorf("ed25519 key must be 32 bytes, got %d", len(decoded))
					}
					copy(key[:], decoded)
				} else {
					return nil, fmt.Errorf("admin key must be base64 or hex encoded 32-byte ed25519 public key: %q", k)
				}
			}
		} else if decoded, err := hex.DecodeString(encoded); err == nil {
			if len(decoded) != 32 {
				return nil, fmt.Errorf("ed25519 key must be 32 bytes, got %d", len(decoded))
			}
			copy(key[:], decoded)
		} else {
			return nil, fmt.Errorf("admin key must be base64 or hex encoded 32-byte ed25519 public key: %q", k)
		}
		result[key] = struct{}{}
	}
	return result, nil
}

// GenerateAdminKey generates a new Ed25519 key pair for network policy signing.
// Returns the private key (64 bytes) and public key (32 bytes).
func GenerateAdminKey() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate admin key: %w", err)
	}
	return priv, pub, nil
}

// WriteAdminKeyFile writes an admin private key to a file with 0600 permissions.
// Refuses to overwrite if the file already exists.
func WriteAdminKeyFile(path string, privKey ed25519.PrivateKey) error {
	// Check if file already exists
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("admin key file %s already exists, refusing to overwrite", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}
	// Encode as base64
	encoded := base64.StdEncoding.EncodeToString(privKey)
	return atomicWriteFile(path, []byte(encoded), 0o600)
}

// ReadAdminKeyFile reads an admin private key from a file.
func ReadAdminKeyFile(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read admin key file: %w", err)
	}
	encoded := strings.TrimSpace(string(data))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode admin key: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("admin key must be %d bytes, got %d", ed25519.PrivateKeySize, len(decoded))
	}
	return ed25519.PrivateKey(decoded), nil
}

// formatPeerKey formats a PeerKey as "ed25519:<base64>"
func formatPeerKey(key [32]byte) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(key[:])
}

// formatPortRange formats a PortRange as a string.
func formatPortRange(pr PortRange) string {
	if pr.Proto == ProtoAny {
		return "*"
	}
	if pr.Proto == ProtoICMP && pr.MatchesICMPv6() {
		return "icmp"
	}
	var protoStr string
	switch pr.Proto {
	case ProtoTCP:
		protoStr = "tcp"
	case ProtoUDP:
		protoStr = "udp"
	case ProtoICMP:
		protoStr = "icmp"
	case ProtoICMPv6:
		protoStr = "icmpv6"
	default:
		protoStr = fmt.Sprintf("proto%d", pr.Proto)
	}
	if pr.Start == 0 && pr.End == 65535 {
		return protoStr + "/*"
	}
	if pr.Start == pr.End {
		return fmt.Sprintf("%s/%d", protoStr, pr.Start)
	}
	return fmt.Sprintf("%s/%d-%d", protoStr, pr.Start, pr.End)
}
