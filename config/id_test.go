package config

import (
	"encoding/hex"
	"testing"
)

// TestRandomIDIsStableLength pins the shape every server-assigned id depends
// on: mesh nodes, TRP proxies and policy groups all address themselves with an
// 8-character hex token.
func TestRandomIDIsStableLength(t *testing.T) {
	id := RandomID()
	if len(id) != 8 {
		t.Fatalf("RandomID() = %q, want 8 chars", id)
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("RandomID() = %q is not hex: %v", id, err)
	}
}
