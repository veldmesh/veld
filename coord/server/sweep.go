// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// DefaultPeerTTL is the default peer time-to-live used by StartPeerSweeper
// when the operator does not configure one: 30 days.
const DefaultPeerTTL = 30 * 24 * time.Hour

// DefaultSweepInterval is how often the stale-peer sweep runs by default.
// Smaller intervals are useful in tests but spin the registry write path in
// production — operators should keep this at minutes, not milliseconds.
const DefaultSweepInterval = time.Hour

// SweepStalePeers removes all peers whose last-seen timestamp is older than
// ttl and returns the removed records. Peers that have never sent a heartbeat
// (LastSeen == 0) are aged by their RegisteredAt timestamp instead. Peers for
// which skip returns true (e.g. peers with an active Watch stream) are never
// removed, so a daemon that is still connected cannot be swept out from under
// its peers. skip may be nil. The on-disk schema is unchanged: this only
// deletes existing keys.
func (r *Registry) SweepStalePeers(ttl time.Duration, skip func(peerID string) bool) ([]peerRecord, error) {
	if ttl <= 0 {
		return nil, nil
	}
	cutoff := time.Now().Add(-ttl).Unix()
	var removed []peerRecord
	err := r.db.Update(func(tx *bolt.Tx) error {
		pb := tx.Bucket(bucketPeers)
		nb := tx.Bucket(bucketNetworks)

		// Collect stale records first; mutating a bucket mid-cursor is unsafe.
		var stale []peerRecord
		if err := pb.ForEach(func(k, v []byte) error {
			var rec peerRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return nil // skip undecodable records; never break the sweep
			}
			ts := rec.LastSeen
			if ts == 0 {
				ts = rec.RegisteredAt
			}
			if ts < cutoff {
				stale = append(stale, rec)
			}
			return nil
		}); err != nil {
			return err
		}

		for _, rec := range stale {
			if skip != nil && skip(rec.ID) {
				continue // peer is currently connected; not actually stale
			}
			if err := pb.Delete([]byte(rec.ID)); err != nil {
				return err
			}
			removed = append(removed, rec)
			if netData := nb.Get([]byte(rec.NetworkID)); netData != nil {
				var netRec networkRecord
				if err := json.Unmarshal(netData, &netRec); err == nil && netRec.MachineCount > 0 {
					netRec.MachineCount--
					if updated, err := json.Marshal(netRec); err == nil {
						if err := nb.Put([]byte(rec.NetworkID), updated); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	})
	return removed, err
}

// Sweeper is anything that can expel stale peers with full leave semantics.
// *Server implements it.
type Sweeper interface {
	ExpelStalePeers(ctx context.Context, ttl time.Duration) (int, error)
}

// StartPeerSweeper launches a background goroutine that calls
// s.ExpelStalePeers every interval until ctx is cancelled. A ttl <= 0
// disables the sweeper entirely (no goroutine is started). interval <= 0
// falls back to DefaultSweepInterval. Note: intervals below a minute are
// intended for tests; in production they needlessly spin the registry write
// path. logf may be nil.
func StartPeerSweeper(ctx context.Context, s Sweeper, ttl, interval time.Duration, logf func(format string, args ...any)) {
	if ttl <= 0 {
		return
	}
	if interval <= 0 {
		interval = DefaultSweepInterval
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				removed, err := s.ExpelStalePeers(ctx, ttl)
				if err != nil {
					logf("peer sweep error: %v", err)
				} else if removed > 0 {
					logf("peer sweep: removed %d stale peer(s) (ttl %s)", removed, ttl)
				}
			}
		}
	}()
}
