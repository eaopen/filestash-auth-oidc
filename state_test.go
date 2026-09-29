// SPDX-License-Identifier: MIT

package oidcauth

import (
	"testing"
	"time"
)

func TestStateStoreConsumeIsOneTime(t *testing.T) {
	store := newStateStore(time.Minute, 8)
	login := pendingLogin{CreatedAt: time.Now(), Nonce: "n"}
	if err := store.put("state", login); err != nil {
		t.Fatal(err)
	}
	got, ok := store.consume("state")
	if !ok || got.Nonce != "n" {
		t.Fatalf("first consume failed: ok=%v got=%+v", ok, got)
	}
	if _, ok := store.consume("state"); ok {
		t.Fatal("state must not be reusable")
	}
}

func TestStateStoreRejectsExpired(t *testing.T) {
	store := newStateStore(time.Second, 8)
	if err := store.put("state", pendingLogin{CreatedAt: time.Now().Add(-2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.consume("state"); ok {
		t.Fatal("expired state must be rejected")
	}
}

func TestRandomTokenIsURLSafeAndUnique(t *testing.T) {
	a, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if a == b || a == "" || b == "" {
		t.Fatalf("unexpected random tokens: %q %q", a, b)
	}
}
