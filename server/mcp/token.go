// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

// Package mcp implements the optional, experimental Model Context Protocol
// server and the personal access tokens that authenticate its callers.
package mcp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// TokenPrefix marks a string as an Atlantis personal MCP token. It makes
	// leaked tokens recognizable to secret scanners.
	TokenPrefix = "atlmcp_v1" // nolint: gosec
	// MinTokenSecretLength is the shortest signing secret Atlantis accepts.
	MinTokenSecretLength = 32
)

// ErrInvalidToken is returned for every token that fails verification. The
// reason is deliberately not exposed to the caller.
var ErrInvalidToken = errors.New("invalid or expired token")

// Claims identify the VCS user a personal token was issued to.
type Claims struct {
	// Username is the VCS login of the token's owner.
	Username string `json:"sub"`
	// UserID is the numeric VCS id of the owner. A login can be renamed and
	// later taken by somebody else; the id cannot.
	UserID int64 `json:"uid"`
	// IssuedAt and ExpiresAt are unix timestamps in seconds.
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
	// ID is a random identifier used to tell tokens apart in logs.
	ID string `json:"jti"`
}

// Expiry returns the expiry as a time.
func (c Claims) Expiry() time.Time {
	return time.Unix(c.ExpiresAt, 0)
}

// TokenSigner issues and verifies personal tokens. Tokens are stateless: they
// carry their claims and an HMAC-SHA256 signature, so every replica that
// shares the secret can verify them without a database. The trade-off is that
// a single token cannot be revoked before it expires; rotating the secret
// revokes all of them.
type TokenSigner struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

// NewTokenSigner returns a signer for the given secret and token lifetime.
func NewTokenSigner(secret string, ttl time.Duration) (*TokenSigner, error) {
	if len(secret) < MinTokenSecretLength {
		return nil, fmt.Errorf("token secret must be at least %d characters", MinTokenSecretLength)
	}
	if ttl <= 0 {
		return nil, errors.New("token lifetime must be positive")
	}
	return &TokenSigner{secret: []byte(secret), ttl: ttl, now: time.Now}, nil
}

// Issue creates a token for the given user.
func (s *TokenSigner) Issue(username string, userID int64) (string, Claims, error) {
	if username == "" {
		return "", Claims{}, errors.New("username must not be empty")
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return "", Claims{}, fmt.Errorf("generating token id: %w", err)
	}
	now := s.now()
	claims := Claims{
		Username:  username,
		UserID:    userID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(s.ttl).Unix(),
		ID:        hex.EncodeToString(id),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", Claims{}, fmt.Errorf("encoding token claims: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return strings.Join([]string{TokenPrefix, encoded, s.sign(encoded)}, "."), claims, nil
}

// Verify checks the signature and expiry of a token and returns its claims.
func (s *TokenSigner) Verify(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != TokenPrefix {
		return Claims{}, ErrInvalidToken
	}
	if !hmac.Equal([]byte(parts[2]), []byte(s.sign(parts[1]))) {
		return Claims{}, ErrInvalidToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, ErrInvalidToken
	}
	if claims.Username == "" || !s.now().Before(claims.Expiry()) {
		return Claims{}, ErrInvalidToken
	}
	return claims, nil
}

func (s *TokenSigner) sign(encodedPayload string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(TokenPrefix + "." + encodedPayload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
