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

// SweepStalePeers removes all peers whose last-seen timestamp is older than
// ttl. Peers that have never sent a heartbeat (LastSeen == 0) are aged by
// their RegisteredAt timestamp instead. Returns the number of peers removed.
// The on-disk schema is unchanged: this only deletes existing keys.
func (r *Registry) SweepStalePeers(ttl time.Duration) (int, error) {
	if ttl <= 0 {
		return 0, nil
	}
	cutoff := time.Now().Add(-ttl).Unix()
	removed := 0
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
			if err := pb.Delete([]byte(rec.ID)); err != nil {
				return err
			}
			removed++
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

// StartPeerSweeper launches a background goroutine that calls
// SweepStalePeers every interval until ctx is cancelled. A ttl <= 0 disables
// the sweeper entirely (no goroutine is started). logf may be nil.
func StartPeerSweeper(ctx context.Context, reg *Registry, ttl, interval time.Duration, logf func(format string, args ...any)) {
	if ttl <= 0 {
		return
	}
	if interval <= 0 {
		interval = time.Hour
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
				removed, err := reg.SweepStalePeers(ttl)
				if err != nil {
					logf("peer sweep error: %v", err)
				} else if removed > 0 {
					logf("peer sweep: removed %d stale peer(s) (ttl %s)", removed, ttl)
				}
			}
		}
	}()
}
