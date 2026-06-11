// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
)

// iconConnected and iconDisconnected are placeholder 22x22 icons generated at
// startup. Replace with embedded .png / .ico assets before shipping.
var (
	iconConnected    []byte
	iconDisconnected []byte
)

func init() {
	iconConnected = makeCircleIcon(color.RGBA{R: 52, G: 199, B: 89, A: 255})    // green
	iconDisconnected = makeCircleIcon(color.RGBA{R: 142, G: 142, B: 147, A: 255}) // gray
}

// makeCircleIcon renders a 22x22 filled circle on a transparent background.
func makeCircleIcon(fill color.RGBA) []byte {
	const size = 22
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(img, img.Bounds(), image.Transparent, image.Point{}, draw.Src)

	cx, cy := float64(size)/2, float64(size)/2
	r := float64(size)/2 - 1.5

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) + 0.5 - cx
			dy := float64(y) + 0.5 - cy
			dist := math.Sqrt(dx*dx + dy*dy)
			if dist <= r {
				alpha := 1.0
				if dist > r-1 {
					alpha = r - dist
				}
				c := fill
				c.A = uint8(alpha * float64(fill.A))
				img.SetRGBA(x, y, c)
			}
		}
	}

	var buf bytes.Buffer
	png.Encode(&buf, img) //nolint:errcheck
	return buf.Bytes()
}
