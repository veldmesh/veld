// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package session

const (
	WindowSize  = 2048
	bitmapWords = WindowSize / 64
)

type replayWindow struct {
	max    uint64
	bitmap [bitmapWords]uint64
	inited bool
}

func (w *replayWindow) checkAndMark(n uint64) bool {
	if !w.inited {
		w.max = n
		w.inited = true
		w.setBit(n)
		return true
	}

	if n > w.max {
		advance := n - w.max
		if advance >= WindowSize {
			for i := range w.bitmap {
				w.bitmap[i] = 0
			}
		} else {
			for i := uint64(1); i <= advance; i++ {
				w.clearBit(w.max + i)
			}
		}
		w.max = n
		w.setBit(n)
		return true
	}

	if w.max-n >= WindowSize {
		return false
	}
	if w.getBit(n) {
		return false
	}
	w.setBit(n)
	return true
}

func (w *replayWindow) setBit(n uint64) {
	pos := n % WindowSize
	w.bitmap[pos/64] |= 1 << (pos % 64)
}

func (w *replayWindow) clearBit(n uint64) {
	pos := n % WindowSize
	w.bitmap[pos/64] &^= 1 << (pos % 64)
}

func (w *replayWindow) getBit(n uint64) bool {
	pos := n % WindowSize
	return w.bitmap[pos/64]&(1<<(pos%64)) != 0
}
