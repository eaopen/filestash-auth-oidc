// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 eaopen contributors

package oidcauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

type pendingLogin struct {
	CreatedAt    time.Time
	Issuer       string
	ClientID     string
	RedirectURI  string
	Nonce        string
	CodeVerifier string
}

type stateStore struct {
	mu      sync.Mutex
	entries map[string]pendingLogin
	ttl     time.Duration
	max     int
}

func newStateStore(ttl time.Duration, maxEntries int) *stateStore {
	return &stateStore{
		entries: make(map[string]pendingLogin),
		ttl:     ttl,
		max:     maxEntries,
	}
}

func (s *stateStore) put(state string, login pendingLogin) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupLocked(time.Now())
	if len(s.entries) >= s.max {
		return errors.New("oidc pending login store is full")
	}
	s.entries[state] = login
	return nil
}

func (s *stateStore) consume(state string) (pendingLogin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	login, ok := s.entries[state]
	if !ok {
		return pendingLogin{}, false
	}
	delete(s.entries, state)
	if time.Since(login.CreatedAt) > s.ttl {
		return pendingLogin{}, false
	}
	return login, true
}

func (s *stateStore) cleanupLocked(now time.Time) {
	for state, login := range s.entries {
		if now.Sub(login.CreatedAt) > s.ttl {
			delete(s.entries, state)
		}
	}
}

func randomToken(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
