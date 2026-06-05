package security

import (
	"testing"

	"go53/types"
)

func TestKeyLifecycleSemantics(t *testing.T) {
	now := int64(1000)

	prePublished := &types.StoredKey{
		State:      KeyStatePublished,
		Flags:      256,
		PublishAt:  now - 10,
		ActivateAt: now + 10,
	}
	if !keyPublishedAt(prePublished, now) {
		t.Fatalf("pre-published key should be published")
	}
	if keySignsAt(prePublished, now) {
		t.Fatalf("pre-published key must not sign before activate_at")
	}

	active := &types.StoredKey{
		State:      KeyStateActive,
		Flags:      256,
		PublishAt:  now - 20,
		ActivateAt: now - 10,
	}
	if !keySignsAt(active, now) {
		t.Fatalf("active key should sign")
	}

	retired := &types.StoredKey{
		State:      KeyStateRetired,
		Flags:      256,
		PublishAt:  now - 30,
		ActivateAt: now - 20,
		RetireAt:   now - 10,
		RemoveAt:   now + 10,
	}
	if !keyPublishedAt(retired, now) {
		t.Fatalf("retired key should remain published until remove_at")
	}
	if keySignsAt(retired, now) {
		t.Fatalf("retired key must not sign after retire_at")
	}

	revoked := &types.StoredKey{
		State:      KeyStateRevoked,
		Flags:      257,
		PublishAt:  now - 30,
		ActivateAt: now - 20,
		Revoke:     true,
		RevokedAt:  now - 10,
		RemoveAt:   now + 10,
	}
	if DNSKEYFlags(revoked) != 385 {
		t.Fatalf("revoked KSK flags = %d, want 385", DNSKEYFlags(revoked))
	}
	if !keyPublishedAt(revoked, now) {
		t.Fatalf("revoked key should remain published until remove_at")
	}
	if keySignsAt(revoked, now) {
		t.Fatalf("revoked key must not sign")
	}
}

func TestKeyStateAt(t *testing.T) {
	now := int64(1000)
	key := &types.StoredKey{CreatedAt: now - 100, PublishAt: now - 50, ActivateAt: now + 50}
	if state := keyStateAt(key, now); state != KeyStatePublished {
		t.Fatalf("state = %q, want %q", state, KeyStatePublished)
	}
	key.ActivateAt = now - 10
	if state := keyStateAt(key, now); state != KeyStateActive {
		t.Fatalf("state = %q, want %q", state, KeyStateActive)
	}
	key.RetireAt = now - 1
	key.RemoveAt = now + 100
	if state := keyStateAt(key, now); state != KeyStateRetired {
		t.Fatalf("state = %q, want %q", state, KeyStateRetired)
	}
	key.RemoveAt = now
	if state := keyStateAt(key, now); state != KeyStateRemoved {
		t.Fatalf("state = %q, want %q", state, KeyStateRemoved)
	}
}
