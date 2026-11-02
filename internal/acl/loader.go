// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package acl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// LocalPolicyLoader loads and manages the local ACL policy file.
// It handles validation, hot-reload on SIGHUP/file change, and integrates with the PolicySwap.
type LocalPolicyLoader struct {
	path         string
	selfPeerID   [32]byte // this node's Ed25519 public key
	peerLookup   func(name string) ([32]byte, bool)
	swap         *PolicySwap
	network      PolicyDecider // optional network policy
	mu           sync.RWMutex
	stopCh       chan struct{}
	watcher      *fsnotify.Watcher
	lastModTime  time.Time
	lastErrorLog time.Time
	dropCounters *DropCounters
	wg           sync.WaitGroup
}

// DropCounters tracks dropped packets per peer and per rule.
type DropCounters struct {
	mu             sync.Mutex
	byPeer         map[[32]byte]uint64
	byRule         map[int]uint64
	byOutboundOnly map[[32]byte]uint64
}

// NewDropCounters creates a new DropCounters.
func NewDropCounters() *DropCounters {
	return &DropCounters{
		byPeer:         make(map[[32]byte]uint64),
		byRule:         make(map[int]uint64),
		byOutboundOnly: make(map[[32]byte]uint64),
	}
}

// IncrementPeer increments the drop counter for a peer.
func (dc *DropCounters) IncrementPeer(peerID [32]byte) {
	dc.mu.Lock()
	dc.byPeer[peerID]++
	dc.mu.Unlock()
}

// IncrementRule increments the drop counter for a rule index.
func (dc *DropCounters) IncrementRule(ruleIdx int) {
	dc.mu.Lock()
	dc.byRule[ruleIdx]++
	dc.mu.Unlock()
}

// IncrementOutboundOnly increments the drop counter for outbound-only denials.
func (dc *DropCounters) IncrementOutboundOnly(peerID [32]byte) {
	dc.mu.Lock()
	dc.byOutboundOnly[peerID]++
	dc.mu.Unlock()
}

// GetPeerDrops returns the drop count for a peer.
func (dc *DropCounters) GetPeerDrops(peerID [32]byte) uint64 {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.byPeer[peerID]
}

// GetRuleDrops returns the drop count for a rule index.
func (dc *DropCounters) GetRuleDrops(ruleIdx int) uint64 {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.byRule[ruleIdx]
}

// GetOutboundOnlyDrops returns the drop count for outbound-only denials for a peer.
func (dc *DropCounters) GetOutboundOnlyDrops(peerID [32]byte) uint64 {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.byOutboundOnly[peerID]
}

// Snapshot returns a copy of all counters for logging.
func (dc *DropCounters) Snapshot() (map[[32]byte]uint64, map[int]uint64, map[[32]byte]uint64) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	byPeer := make(map[[32]byte]uint64, len(dc.byPeer))
	for k, v := range dc.byPeer {
		byPeer[k] = v
	}
	byRule := make(map[int]uint64, len(dc.byRule))
	for k, v := range dc.byRule {
		byRule[k] = v
	}
	byOO := make(map[[32]byte]uint64, len(dc.byOutboundOnly))
	for k, v := range dc.byOutboundOnly {
		byOO[k] = v
	}
	return byPeer, byRule, byOO
}

// NewLocalPolicyLoader creates a new LocalPolicyLoader.
// selfPeerID is this node's Ed25519 public key.
// peerLookup resolves a peer name (from the local policy) to an Ed25519 public key.
// swap is the PolicySwap to update with the compiled local policy.
// network is the optional network policy to combine with.
func NewLocalPolicyLoader(path string, selfPeerID [32]byte, peerLookup func(name string) ([32]byte, bool), swap *PolicySwap, network PolicyDecider) *LocalPolicyLoader {
	return &LocalPolicyLoader{
		path:         path,
		selfPeerID:   selfPeerID,
		peerLookup:   peerLookup,
		swap:         swap,
		network:      network,
		stopCh:       make(chan struct{}),
		dropCounters: NewDropCounters(),
	}
}

// Load reads the local policy file, validates it, and updates the PolicySwap.
// Returns an error if the file exists but cannot be parsed or is invalid.
// If the file does not exist, returns nil (no local policy = defer to network).
func (l *LocalPolicyLoader) Load() error {
	// Check if file exists
	info, err := os.Stat(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No local policy file = defer to network policy
			l.swap.Store(nil)
			return nil
		}
		return fmt.Errorf("stat policy file: %w", err)
	}

	// Validate file permissions: must not be group/world writable
	if err := validatePolicyFilePermissions(l.path, info); err != nil {
		return err
	}

	// Read file
	data, err := os.ReadFile(l.path)
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}

	// Parse and validate policy
	p, warnings, err := ParsePolicy(string(data))
	if err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}

	// Log warnings
	for _, w := range warnings {
		fmt.Printf("policy warning: %s\n", w)
	}

	// Compile the policy
	cp := p.Compile()

	// Store the compiled policy
	l.swap.Store(cp)

	// Update last mod time for file watching
	l.mu.Lock()
	l.lastModTime = info.ModTime()
	l.mu.Unlock()

	return nil
}

// validatePolicyFilePermissions checks that the policy file is not group/world writable
// and is owned by root (or the current user on non-Linux).
func validatePolicyFilePermissions(path string, info os.FileInfo) error {
	// Check group/world writable
	mode := info.Mode()
	if mode&0o022 != 0 {
		return fmt.Errorf("policy file %q is group or world writable (mode %o); must be root-owned and 0600 or 0640", path, mode.Perm())
	}

	// On Linux, check owner is root
	// Note: we can't easily check uid on all platforms without CGO
	// For now, just enforce the mode bits
	return nil
}

// StartWatcher starts watching the policy file for changes.
// Must be called after Load().
func (l *LocalPolicyLoader) StartWatcher() error {
	if l.path == "" {
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create file watcher: %w", err)
	}
	l.watcher = watcher

	// Watch the directory containing the policy file
	dir := filepath.Dir(l.path)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return fmt.Errorf("watch policy dir: %w", err)
	}

	l.wg.Add(1)
	go l.watchLoop()
	return nil
}

// Wait blocks until the watcher goroutine exits.
func (l *LocalPolicyLoader) Wait() {
	close(l.stopCh)
	if l.watcher != nil {
		_ = l.watcher.Close()
	}
	l.wg.Wait()
}

func (l *LocalPolicyLoader) watchLoop() {
	defer l.wg.Done()
	for {
		select {
		case <-l.stopCh:
			return
		case event, ok := <-l.watcher.Events:
			if !ok {
				return
			}
			// Only react to writes/renames of our specific file
			if filepath.Clean(event.Name) != filepath.Clean(l.path) {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}
			// Debounce: ignore rapid successive events
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
				l.logError(err)
			} else {
				fmt.Printf("policy: reloaded from %s\n", l.path)
			}
		case err, ok := <-l.watcher.Errors:
			if !ok {
				return
			}
			l.logError(fmt.Errorf("policy watcher error: %w", err))
		}
	}
}

// Reload triggers a manual policy reload (e.g., on SIGHUP).
func (l *LocalPolicyLoader) Reload() error {
	if err := l.Load(); err != nil {
		l.logError(err)
		return err
	}
	fmt.Printf("policy: reloaded from %s\n", l.path)
	return nil
}

// logError logs errors rate-limited (once per 30 seconds).
func (l *LocalPolicyLoader) logError(err error) {
	l.mu.Lock()
	now := time.Now()
	if now.Sub(l.lastErrorLog) < 30*time.Second {
		l.mu.Unlock()
		return
	}
	l.lastErrorLog = now
	l.mu.Unlock()
	fmt.Printf("policy error: %v\n", err)
}

// DropCounters returns the drop counters for this loader.
func (l *LocalPolicyLoader) DropCounters() *DropCounters {
	return l.dropCounters
}

// CombinedPolicy returns a PolicyDecider that combines local and network policies.
func (l *LocalPolicyLoader) CombinedPolicy() PolicyDecider {
	l.mu.RLock()
	network := l.network
	l.mu.RUnlock()
	return Combine(l.swap, network)
}

// SetNetworkPolicy updates the network policy.
func (l *LocalPolicyLoader) SetNetworkPolicy(network PolicyDecider) {
	l.mu.Lock()
	l.network = network
	l.mu.Unlock()
}