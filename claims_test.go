// SPDX-License-Identifier: AGPL-3.0-or-later

package oidcauth

import (
	"reflect"
	"testing"
)

func TestExposeClaims(t *testing.T) {
	claims := map[string]any{
		"sub":                "subject-1",
		"preferred_username": "alice",
		"email":              "alice@example.com",
		"groups":             []any{"engineering", "filestash-users"},
		"email_verified":     true,
	}
	got := exposeClaims(claims, "preferred_username", "groups")
	if got["user"] != "alice" || got["username"] != "alice" {
		t.Fatalf("unexpected username mapping: %+v", got)
	}
	if got["groups"] != "engineering,filestash-users" {
		t.Fatalf("unexpected groups: %q", got["groups"])
	}
	if got["groups_json"] != `["engineering","filestash-users"]` {
		t.Fatalf("unexpected groups_json: %q", got["groups_json"])
	}
	if got["email_verified"] != "true" {
		t.Fatalf("boolean claim not flattened: %+v", got)
	}
}

func TestUsernameFallsBackToSubject(t *testing.T) {
	got := exposeClaims(map[string]any{"sub": "subject-1"}, "preferred_username", "groups")
	if got["user"] != "subject-1" {
		t.Fatalf("expected sub fallback, got %q", got["user"])
	}
}

func TestNormalizeScopes(t *testing.T) {
	got := normalizeScopes("profile,email openid groups profile")
	want := []string{"openid", "profile", "email", "groups"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}
