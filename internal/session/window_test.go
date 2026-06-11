// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package session

import (
	"testing"
)

func TestReplayWindow_HappyPath(t *testing.T) {
	w := &replayWindow{}

	if !w.checkAndMark(100) {
		t.Error("checkAndMark(100) should return true")
	}

	if !w.checkAndMark(101) {
		t.Error("checkAndMark(101) should return true")
	}

	if !w.checkAndMark(99) {
		t.Error("checkAndMark(99) should return true")
	}
}

func TestReplayWindow_Duplicate(t *testing.T) {
	w := &replayWindow{}

	if !w.checkAndMark(42) {
		t.Error("first checkAndMark(42) should return true")
	}

	if w.checkAndMark(42) {
		t.Error("second checkAndMark(42) should return false (replay)")
	}
}

func TestReplayWindow_TooOld(t *testing.T) {
	w := &replayWindow{}
	w.max = 3000
	w.inited = true
	w.setBit(3000)

	if w.checkAndMark(3000 - WindowSize) {
		t.Error("checkAndMark at boundary (max - WindowSize) should return false")
	}

	if !w.checkAndMark(3000 - WindowSize + 1) {
		t.Error("checkAndMark(max - WindowSize + 1) should return true")
	}
}

func TestReplayWindow_Advance_ClearsStale(t *testing.T) {
	w := &replayWindow{}

	if !w.checkAndMark(0) {
		t.Error("checkAndMark(0) should return true")
	}

	if !w.checkAndMark(WindowSize) {
		t.Error("checkAndMark(WindowSize) should return true")
	}

	if w.checkAndMark(0) {
		t.Error("checkAndMark(0) after advance should return false (too old)")
	}
}

func TestReplayWindow_LargeJump(t *testing.T) {
	w := &replayWindow{}

	if !w.checkAndMark(0) {
		t.Error("checkAndMark(0) should return true")
	}

	if !w.checkAndMark(WindowSize * 3) {
		t.Error("checkAndMark(WindowSize * 3) should return true (large jump)")
	}

	if w.checkAndMark(WindowSize * 3) {
		t.Error("checkAndMark(WindowSize * 3) should return false (replay of same nonce)")
	}
}
