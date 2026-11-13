// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"mime"
	"net/http"
	"regexp"
)

type oauthGrant struct {
	Claims
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri,omitempty"`
	Challenge   string `json:"code_challenge,omitempty"`
	Family      string `json:"family,omitempty"`
}

type refreshFamily struct {
	ActiveID  string
	ExpiresAt int64
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// Token exchanges a one-use code or rotates a refresh token for public clients.
func (c *OAuthController) Token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBody)
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if media != "application/x-www-form-urlencoded" || r.ParseForm() != nil || !singleValues(r.PostForm) || r.URL.RawQuery != "" {
		oauthError(w, "invalid_request", "expected a bounded form without duplicate parameters")
		return
	}
	if r.Header.Get("Authorization") != "" || r.PostForm.Get("client_secret") != "" {
		oauthError(w, "invalid_client", "only public clients without client authentication are supported")
		return
	}
	if _, err := c.client(r.PostForm.Get("client_id")); err != nil {
		oauthError(w, "invalid_client", "invalid client identifier")
		return
	}
	if !c.validResource(r.PostForm.Get("resource")) {
		oauthError(w, "invalid_target", "resource must identify this MCP endpoint")
		return
	}
	if r.PostForm.Get("scope") != "" {
		oauthError(w, "invalid_scope", "this server does not use OAuth scopes")
		return
	}
	var kind, token string
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		kind, token = "code", r.PostForm.Get("code")
	case "refresh_token":
		kind, token = "refresh", r.PostForm.Get("refresh_token")
	default:
		oauthError(w, "unsupported_grant_type", "use authorization_code or refresh_token")
		return
	}
	var grant oauthGrant
	if c.signer.decode(token, &grant) != nil || grant.Kind != kind || grant.ClientID != r.PostForm.Get("client_id") ||
		grant.Audience != c.resource || grant.Username == "" || !c.signer.now().Before(grant.Expiry()) {
		oauthError(w, "invalid_grant", "invalid or expired grant")
		return
	}
	if kind == "code" {
		verifier := r.PostForm.Get("code_verifier")
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		if !verifierPattern.MatchString(verifier) || subtle.ConstantTimeCompare([]byte(challenge), []byte(grant.Challenge)) != 1 || grant.RedirectURI != r.PostForm.Get("redirect_uri") {
			oauthError(w, "invalid_grant", "invalid code verifier or redirect URI")
			return
		}
	}
	out, err := c.redeem(grant)
	if errors.Is(err, ErrInvalidToken) {
		oauthError(w, "invalid_grant", "grant already used or invalidated")
		return
	}
	if err != nil {
		oauthError(w, "server_error", "issuing tokens, try again later")
		return
	}
	oauthJSON(w, http.StatusOK, out)
}

func (c *OAuthController) redeem(grant oauthGrant) (tokenResponse, error) {
	// Validation and rotation are atomic. Release the lock before writing any
	// HTTP response so a slow client cannot block other token exchanges.
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune()
	if grant.Kind == "code" {
		if _, ok := c.codes[grant.ID]; !ok {
			return tokenResponse{}, ErrInvalidToken
		}
		if len(c.families) >= maxOAuthEntries {
			return tokenResponse{}, errors.New("too many active authorizations")
		}
		delete(c.codes, grant.ID)
		grant.Family = rand.Text()
		grant.ExpiresAt = c.signer.now().Add(c.refreshTTL).Unix()
	} else {
		family, ok := c.families[grant.Family]
		if !ok || family.ActiveID != grant.ID {
			// Reuse indicates theft. Revoke the entire refresh family, including the
			// replacement, rather than letting either party keep refreshing it.
			delete(c.families, grant.Family)
			return tokenResponse{}, ErrInvalidToken
		}
	}
	access, _, err := c.signer.issue(grant.Username, grant.UserID, "access", c.resource, c.accessTTL)
	if err != nil {
		return tokenResponse{}, err
	}
	grant.Kind, grant.ID = "refresh", rand.Text()
	grant.IssuedAt = c.signer.now().Unix()
	grant.RedirectURI, grant.Challenge = "", ""
	refresh, err := c.signer.encode(grant)
	if err != nil {
		return tokenResponse{}, err
	}
	// Rotation does not extend the family's absolute lifetime.
	c.families[grant.Family] = refreshFamily{ActiveID: grant.ID, ExpiresAt: grant.ExpiresAt}
	return tokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(c.accessTTL.Seconds()), RefreshToken: refresh}, nil
}
