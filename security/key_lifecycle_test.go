package security

import (
	"testing"
	"time"

	"go53/storage"
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

func TestStoredKeyLifecycleStoragePaths(t *testing.T) {
	storage.Backend = &storage.MockStorage{Zones: map[string][]byte{}, Tables: map[string]map[string][]byte{}}
	if err := storage.Backend.Init(); err != nil {
		t.Fatalf("storage init: %v", err)
	}
	if err := InitDNSSECKeyCache(); err != nil {
		t.Fatalf("InitDNSSECKeyCache: %v", err)
	}

	now := time.Now().Unix()
	keyID, key, err := GenerateRolloverKey("life.test.", "ksk", "ED25519", now-20, now-10)
	if err != nil {
		t.Fatalf("GenerateRolloverKey: %v", err)
	}
	if keyID == "" || key == nil {
		t.Fatalf("missing generated key")
	}
	stored, err := LoadStoredKey(keyID)
	if err != nil {
		t.Fatalf("LoadStoredKey: %v", err)
	}
	if stored.Zone != "life.test" || stored.State != KeyStateActive {
		t.Fatalf("stored key = %#v", stored)
	}
	if DNSKEYKeyTag(stored) == 0 {
		t.Fatalf("DNSKEYKeyTag returned 0")
	}

	listed, err := ListStoredKeys()
	if err != nil {
		t.Fatalf("ListStoredKeys: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("ListStoredKeys len = %d", len(listed))
	}
	zoneKeys, err := LoadAllKeysForZone("life.test")
	if err != nil || len(zoneKeys) != 1 {
		t.Fatalf("LoadAllKeysForZone len=%d err=%v", len(zoneKeys), err)
	}
	if ids, err := GetDNSSECKeyNamesForRRSet("life.test", true); err != nil || len(ids) != 1 || ids[0] != keyID {
		t.Fatalf("GetDNSSECKeyNamesForRRSet ids=%#v err=%v", ids, err)
	}

	updated, err := UpdateKeyLifecycle(keyID, types.StoredKey{PublishAt: now - 30, ActivateAt: now - 20})
	if err != nil {
		t.Fatalf("UpdateKeyLifecycle: %v", err)
	}
	if updated.PublishAt != now-30 || updated.ActivateAt != now-20 {
		t.Fatalf("updated key = %#v", updated)
	}
	retired, err := RetireKey(keyID, time.Hour)
	if err != nil {
		t.Fatalf("RetireKey: %v", err)
	}
	if retired.State != KeyStateRetired || retired.RemoveAt == 0 {
		t.Fatalf("retired key = %#v", retired)
	}
	revoked, err := RevokeKey(keyID, time.Hour)
	if err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if revoked.State != KeyStateRevoked || !revoked.Revoke || revoked.RevokedAt == 0 {
		t.Fatalf("revoked key = %#v", revoked)
	}
	if err := DeleteStoredKey(keyID); err != nil {
		t.Fatalf("DeleteStoredKey: %v", err)
	}
	if _, err := LoadStoredKey(keyID); err == nil {
		t.Fatalf("LoadStoredKey found deleted key")
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
