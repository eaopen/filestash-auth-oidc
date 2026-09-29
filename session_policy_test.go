// SPDX-License-Identifier: MIT

package oidcauth

import (
	"testing"
	"time"
)

func TestOIDCSessionCurrent(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		timestamp string
		current   bool
	}{
		{"recent", now.Add(-time.Minute).Format(time.RFC3339), true},
		{"before limit", now.Add(-maxOIDCSessionAge + time.Second).Format(time.RFC3339), true},
		{"at limit", now.Add(-maxOIDCSessionAge).Format(time.RFC3339), false},
		{"future", now.Add(time.Second).Format(time.RFC3339), false},
		{"missing", "", false},
		{"invalid", "yesterday", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := oidcSessionCurrent(tc.timestamp, now); got != tc.current {
				t.Fatalf("current=%v, want %v", got, tc.current)
			}
		})
	}
}
