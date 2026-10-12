// Copyright (c) 2026 Veld Authors.
// SPDX-License-Identifier: MIT
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"slices"
	"testing"
)

// vectorClaims is the fixed input of the RegisterSignedMessage test vector.
// It deliberately lists the subnet routes unsorted — the encoder must sign
// them in sorted order — and uses a recognizable timestamp
// (2025-01-01T00:00:00Z). Name is empty to match the v1 test vector and
// prove the empty-string encoding.
var vectorClaims = RegisterClaims{
	NetworkID:     "net-3f0b8a2c",
	Name:          "",
	Ed25519Public: "rU3j0Q9yJdBhpIS4Iac2BSGFciXqSm0CVBkNJGyzXBk=",
	X25519Public:  "bEc9LidcTNF4gJpA2tJvJlIaSafqiIMmqtTIKYtEqzU=",
	Endpoint:      "203.0.113.7:51820",
	SubnetRoutes:  []string{"10.42.0.0/24", "192.168.1.0/24"},
	TimestampUnix: 1735689600,
}

// TestRegisterSignedMessage_Vector locks the wire encoding of the Register
// proof-of-possession message: any change to the domain prefix, the field
// order, the length prefixes or the route sorting breaks this test. The
// expected bytes are the golden vector shared with the protocol docs.
func TestRegisterSignedMessage_Vector(t *testing.T) {
	got := hex.EncodeToString(RegisterSignedMessage(vectorClaims))
	want := "76656c642d636f6f72642d72656769737465722d7632000000000c6e65742d3366306238613263000000000000002c7255336a305139794a64426870495334496163324253474663695871536d304356426b4e4a47797a58426b3d0000002c624563394c696463544e4634674a704132744a764a6c49615361667169494d6d717454494b597445717a553d000000113230332e302e3131332e373a3531383230000000020000000c31302e34322e302e302f32340000000e3139322e3136382e312e302f32340000000067748580"
	if got != want {
		t.Fatalf("RegisterSignedMessage vector:\n got  %s\n want %s", got, want)
	}
}

// TestRegisterSignedMessage_SortsRoutes verifies the encoding is independent
// of the order the subnet routes are listed in: routes are signed sorted, so
// the same set in any order produces the same message.
func TestRegisterSignedMessage_SortsRoutes(t *testing.T) {
	sorted := slices.Clone(vectorClaims.SubnetRoutes)
	slices.Sort(sorted)

	a := RegisterSignedMessage(vectorClaims)
	reordered := vectorClaims
	slices.Reverse(reordered.SubnetRoutes)
	b := RegisterSignedMessage(reordered)

	if !slices.Equal(a, b) {
		t.Errorf("route order changed the message:\n sorted-first %x\n sorted-last  %x", a, b)
	}
}

// TestRegisterSignedMessage_DoesNotMutateRoutes verifies the encoder sorts a
// copy, never the caller's slice.
func TestRegisterSignedMessage_DoesNotMutateRoutes(t *testing.T) {
	before := slices.Clone(vectorClaims.SubnetRoutes)
	_ = RegisterSignedMessage(vectorClaims)
	if !slices.Equal(before, vectorClaims.SubnetRoutes) {
		t.Errorf("encoder mutated SubnetRoutes: got %v, want %v", vectorClaims.SubnetRoutes, before)
	}
}

// signedFixture generates a fresh identity and returns it with a signature
// over vectorClaims.
func signedFixture(t *testing.T) (*Identity, []byte) {
	t.Helper()
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return id, SignRegister(id.Ed25519Private, vectorClaims)
}

func TestSignRegister_Verify(t *testing.T) {
	id, sig := signedFixture(t)

	if err := VerifyRegisterSignature(id.Ed25519Public, sig, vectorClaims, vectorClaims.TimestampUnix); err != nil {
		t.Fatalf("VerifyRegisterSignature: %v", err)
	}
}

func TestVerifyRegisterSignature_WrongKey(t *testing.T) {
	_, sig := signedFixture(t)
	other, err := Generate()
	if err != nil {
		t.Fatalf("Generate other: %v", err)
	}

	err = VerifyRegisterSignature(other.Ed25519Public, sig, vectorClaims, vectorClaims.TimestampUnix)
	if err == nil {
		t.Fatal("signature by a different key verified")
	}
}

// TestVerifyRegisterSignature_TamperedField verifies every signed field is
// bound: changing any one of them after signing must fail verification.
func TestVerifyRegisterSignature_TamperedField(t *testing.T) {
	id, sig := signedFixture(t)
	now := vectorClaims.TimestampUnix

	tampered := []struct {
		name string
		mod  func(c *RegisterClaims)
	}{
		{"network_id", func(c *RegisterClaims) { c.NetworkID = "net-other" }},
		{"name", func(c *RegisterClaims) { c.Name = "different-name" }},
		{"ed25519_public", func(c *RegisterClaims) { c.Ed25519Public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }},
		{"x25519_public", func(c *RegisterClaims) { c.X25519Public = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" }},
		{"endpoint", func(c *RegisterClaims) { c.Endpoint = "198.51.100.9:51820" }},
		{"subnet_routes", func(c *RegisterClaims) { c.SubnetRoutes = []string{"10.42.0.0/25"} }},
		{"extra_subnet_route", func(c *RegisterClaims) { c.SubnetRoutes = append(slices.Clone(c.SubnetRoutes), "172.16.0.0/12") }},
		{"timestamp", func(c *RegisterClaims) { c.TimestampUnix++ }},
	}

	for _, tc := range tampered {
		t.Run(tc.name, func(t *testing.T) {
			claims := vectorClaims
			tc.mod(&claims)
			if err := VerifyRegisterSignature(id.Ed25519Public, sig, claims, now); err == nil {
				t.Fatalf("tampered %s verified", tc.name)
			}
		})
	}
}

// TestVerifyRegisterSignature_TimestampWindow verifies the ±120 s replay
// window: signatures dated exactly at the window edge verify, one second
// beyond it (stale or future) do not. The timestamp is signed, so each case
// signs its own claims.
func TestVerifyRegisterSignature_TimestampWindow(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	const now = int64(1800000000)

	cases := []struct {
		name    string
		ts      int64
		wantErr bool
	}{
		{"now", now, false},
		{"exactly 120 s stale", now - 120, false},
		{"exactly 120 s in the future", now + 120, false},
		{"121 s stale", now - 121, true},
		{"121 s in the future", now + 121, true},
		{"an hour stale", now - 3600, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := vectorClaims
			claims.TimestampUnix = tc.ts
			sig := SignRegister(id.Ed25519Private, claims)
			err := VerifyRegisterSignature(id.Ed25519Public, sig, claims, now)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("timestamp %d (now %d): err = %v, wantErr %v", tc.ts, now, err, tc.wantErr)
			}
		})
	}

	// A request whose timestamp was never set (an unsigned client) is
	// outside the window no matter which key would have signed it.
	claims := vectorClaims
	claims.TimestampUnix = 0
	sig := SignRegister(id.Ed25519Private, claims)
	if err := VerifyRegisterSignature(id.Ed25519Public, sig, claims, now); err == nil {
		t.Fatal("zero timestamp verified")
	}
}

// TestVerifyRegisterSignature_MalformedSignature verifies malformed
// signatures fail cleanly instead of panicking.
func TestVerifyRegisterSignature_MalformedSignature(t *testing.T) {
	id, _ := signedFixture(t)

	cases := []struct {
		name string
		sig  []byte
	}{
		{"missing", nil},
		{"empty", []byte{}},
		{"truncated", []byte{1, 2, 3}},
		{"wrong length", make([]byte, 63)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyRegisterSignature(id.Ed25519Public, tc.sig, vectorClaims, vectorClaims.TimestampUnix); err == nil {
				t.Fatalf("malformed signature (%s) verified", tc.name)
			}
		})
	}

	// A valid 64-byte signature of a different message must also fail.
	other := SignRegister(id.Ed25519Private, RegisterClaims{NetworkID: "other"})
	if err := VerifyRegisterSignature(id.Ed25519Public, other, vectorClaims, vectorClaims.TimestampUnix); err == nil {
		t.Fatal("signature over a different message verified")
	}
}

// TestSignRegister_RealPrimitives signs with the raw stdlib call and verifies
// through the package helpers, proving they use plain Ed25519 over the
// shared encoding — no bespoke crypto.
func TestSignRegister_RealPrimitives(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig := ed25519.Sign(priv, RegisterSignedMessage(vectorClaims))
	if err := VerifyRegisterSignature(pub, sig, vectorClaims, vectorClaims.TimestampUnix); err != nil {
		t.Fatalf("stdlib-signed message did not verify: %v", err)
	}

	pkgSig := SignRegister(priv, vectorClaims)
	if !slices.Equal(sig, pkgSig) {
		t.Fatal("SignRegister does not match a raw stdlib signature over RegisterSignedMessage")
	}
}