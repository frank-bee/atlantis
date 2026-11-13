// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"strings"
	"testing"
	"time"

	. "github.com/runatlantis/atlantis/testing"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func newTestSigner(t *testing.T) *TokenSigner {
	t.Helper()
	s, err := NewTokenSigner(testSecret, time.Hour)
	Ok(t, err)
	return s
}

func TestNewTokenSigner_RejectsWeakConfig(t *testing.T) {
	_, err := NewTokenSigner("short", time.Hour)
	Assert(t, err != nil, "expected error for short secret")
	_, err = NewTokenSigner(testSecret, 0)
	Assert(t, err != nil, "expected error for zero lifetime")
}

func TestTokenSigner_RoundTrip(t *testing.T) {
	s := newTestSigner(t)
	token, issued, err := s.Issue("octocat", 42)
	Ok(t, err)
	Assert(t, strings.HasPrefix(token, TokenPrefix+"."), "token %q lacks prefix", token)

	claims, err := s.Verify(token)
	Ok(t, err)
	Equals(t, issued, claims)
	Equals(t, "octocat", claims.Username)
	Equals(t, int64(42), claims.UserID)
}

func TestTokenSigner_Verify_Rejects(t *testing.T) {
	s := newTestSigner(t)
	token, _, err := s.Issue("octocat", 42)
	Ok(t, err)
	parts := strings.Split(token, ".")

	other, err := NewTokenSigner(strings.Repeat("x", MinTokenSecretLength), time.Hour)
	Ok(t, err)
	forged, _, err := other.Issue("octocat", 42)
	Ok(t, err)
	// Claims for another user under the original signature.
	swapped, _, err := s.Issue("mallory", 7)
	Ok(t, err)
	swappedPayload := strings.Split(swapped, ".")[1]

	cases := map[string]string{
		"empty":             "",
		"garbage":           "not-a-token",
		"wrong prefix":      "other." + parts[1] + "." + parts[2],
		"missing signature": parts[0] + "." + parts[1],
		"other secret":      forged,
		"swapped payload":   parts[0] + "." + swappedPayload + "." + parts[2],
		"extra part":        token + ".x",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := s.Verify(tok)
			Equals(t, ErrInvalidToken, err)
		})
	}
}

func TestTokenSigner_Verify_Expired(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	token, _, err := s.Issue("octocat", 42)
	Ok(t, err)

	s.now = func() time.Time { return now.Add(59 * time.Minute) }
	_, err = s.Verify(token)
	Ok(t, err)

	s.now = func() time.Time { return now.Add(time.Hour) }
	_, err = s.Verify(token)
	Equals(t, ErrInvalidToken, err)
}
