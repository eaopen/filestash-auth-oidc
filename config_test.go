// SPDX-License-Identifier: AGPL-3.0-or-later

package oidcauth

import "testing"

func TestValidateRedirectURI(t *testing.T) {
	for _, tc := range []struct {
		uri   string
		valid bool
	}{
		{"https://files.example.com/api/session/auth/", true},
		{"http://localhost:8334/api/session/auth/", true},
		{"http://127.0.0.1:8334/api/session/auth/", true},
		{"http://files.example.com/api/session/auth/", false},
		{"/api/session/auth/", false},
	} {
		err := validateRedirectURI(tc.uri)
		if (err == nil) != tc.valid {
			t.Fatalf("uri=%q valid=%v err=%v", tc.uri, tc.valid, err)
		}
	}
}
