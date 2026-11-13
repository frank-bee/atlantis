// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"html/template"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const consentCookieName = "atlantis_mcp_consent"

type authorizationRequest struct {
	Issuer      string
	ClientID    string
	RedirectURI string
	Challenge   string
	State       string
	ExpiresAt   int64
	Approved    bool
}

// Authorize validates the client before displaying consent or redirecting.
func (c *OAuthController) Authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// Do not restrict form-action to self: browsers can apply it to the
	// subsequent GitHub and client redirects as well as the consent POST.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	if r.Method == http.MethodPost {
		c.consent(w, r)
		return
	}
	if len(r.URL.RawQuery) > maxOAuthBody {
		oauthError(w, "invalid_request", "authorization request is too large")
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !singleValues(q) {
		oauthError(w, "invalid_request", "malformed or duplicate parameters")
		return
	}
	client, err := c.client(q.Get("client_id"))
	if err != nil || !slices.ContainsFunc(client.RedirectURIs, func(uri string) bool { return matchesRedirect(uri, q.Get("redirect_uri")) }) {
		oauthError(w, "invalid_request", "invalid client or redirect URI")
		return
	}
	req := authorizationRequest{Issuer: c.issuer, ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"), Challenge: q.Get("code_challenge"), State: q.Get("state"), ExpiresAt: c.signer.now().Add(stateLifetime).Unix()}
	if q.Get("response_type") != "code" {
		authorizationError(w, r, req, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	challenge, err := base64.RawURLEncoding.DecodeString(req.Challenge)
	if q.Get("code_challenge_method") != "S256" || err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != req.Challenge {
		authorizationError(w, r, req, "invalid_request", "a valid S256 PKCE challenge is required")
		return
	}
	if !c.validResource(q.Get("resource")) {
		authorizationError(w, r, req, "invalid_target", "resource must identify this MCP endpoint")
		return
	}
	if q.Get("scope") != "" {
		authorizationError(w, r, req, "invalid_scope", "this server does not use OAuth scopes")
		return
	}
	if len(req.State) > 1024 || (q.Get("response_mode") != "" && q.Get("response_mode") != "query") {
		authorizationError(w, r, req, "invalid_request", "unsupported response mode or oversized state")
		return
	}
	id := "mcp_" + rand.Text()
	c.mu.Lock()
	c.prune()
	full := len(c.pending) >= maxOAuthEntries
	if !full {
		c.pending[id] = req
	}
	c.mu.Unlock()
	if full {
		authorizationError(w, r, req, "temporarily_unavailable", "too many pending logins, try again later")
		return
	}
	c.consentCookie(w, id, int(stateLifetime.Seconds()))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := consentPage.Execute(w, struct{ Name, Redirect, ID, Action string }{client.Name, req.RedirectURI, id, c.issuer + AuthorizePath}); err != nil {
		c.login.Logger.Err("rendering mcp consent page %s", err)
	}
}

func (c *OAuthController) consentCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{ // nolint: gosec
		Name: consentCookieName, Value: value, MaxAge: maxAge,
		Path:   strings.TrimSuffix(c.login.AtlantisURL.Path, "/") + AuthorizePath,
		Secure: c.login.AtlantisURL.Scheme == "https", HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (c *OAuthController) consent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBody)
	if r.ParseForm() != nil || !singleValues(r.PostForm) {
		oauthError(w, "invalid_request", "invalid consent form")
		return
	}
	id := r.PostForm.Get("request_id")
	cookie, err := r.Cookie(consentCookieName)
	if err != nil || id == "" || subtle.ConstantTimeCompare([]byte(id), []byte(cookie.Value)) != 1 {
		oauthError(w, "invalid_request", "consent state did not match")
		return
	}
	c.mu.Lock()
	c.prune()
	req, ok := c.pending[id]
	if ok && !req.Approved {
		req.Approved = true
		c.pending[id] = req
	} else {
		ok = false
	}
	if r.PostForm.Get("decision") != "allow" {
		delete(c.pending, id)
	}
	c.mu.Unlock()
	c.consentCookie(w, "", -1)
	if !ok {
		oauthError(w, "invalid_request", "consent expired or already used")
		return
	}
	if r.PostForm.Get("decision") != "allow" {
		authorizationError(w, r, req, "access_denied", "authorization declined")
		return
	}
	c.login.startLogin(w, r, id)
}

func (c *OAuthController) callback(w http.ResponseWriter, r *http.Request, state string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	c.mu.Lock()
	c.prune()
	req, ok := c.pending[state]
	delete(c.pending, state)
	c.mu.Unlock()
	if !ok || !req.Approved {
		oauthError(w, "invalid_request", "login expired or already used")
		return
	}
	if r.URL.Query().Get("error") != "" || r.URL.Query().Get("code") == "" {
		authorizationError(w, r, req, "access_denied", "GitHub login was not completed")
		return
	}
	username, userID, err := c.login.identify(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		c.login.Logger.Err("identifying mcp user %s", err)
		authorizationError(w, r, req, "server_error", "could not identify GitHub user")
		return
	}
	grant := oauthGrant{
		Claims:   Claims{Kind: "code", Audience: c.resource, Username: username, UserID: userID, ID: rand.Text(), IssuedAt: c.signer.now().Unix(), ExpiresAt: c.signer.now().Add(time.Minute).Unix()},
		ClientID: req.ClientID, RedirectURI: req.RedirectURI, Challenge: req.Challenge,
	}
	code, err := c.signer.encode(grant)
	if err != nil {
		authorizationError(w, r, req, "server_error", "could not issue authorization code")
		return
	}
	c.mu.Lock()
	c.prune()
	full := len(c.codes) >= maxOAuthEntries
	if !full {
		c.codes[grant.ID] = grant.ExpiresAt
	}
	c.mu.Unlock()
	if full {
		authorizationError(w, r, req, "temporarily_unavailable", "too many pending codes, try again later")
		return
	}
	authorizationRedirect(w, r, req, url.Values{"code": {code}})
}

func authorizationError(w http.ResponseWriter, r *http.Request, req authorizationRequest, code, description string) {
	authorizationRedirect(w, r, req, url.Values{"error": {code}, "error_description": {description}})
}

func authorizationRedirect(w http.ResponseWriter, r *http.Request, req authorizationRequest, values url.Values) {
	target, _ := url.Parse(req.RedirectURI) // Validated before constructing the request.
	q := target.Query()
	q.Set("iss", req.Issuer)
	maps.Copy(q, values)
	if req.State != "" {
		q.Set("state", req.State)
	}
	target.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target.String(), http.StatusFound)
}

var consentPage = template.Must(template.New("consent").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Connect to Atlantis</title></head>
<body><h1>Connect an MCP client</h1>
<p>Client name (provided by the client): <strong>{{.Name}}</strong></p>
<p>Authorize this client to access Atlantis as your GitHub user. Commands remain subject to your repository permissions and this server's settings.</p>
<p>The client will receive credentials at <strong>{{.Redirect}}</strong>. Continue only if you recognize this address and started this connection yourself.</p>
<form method="post" action="{{.Action}}"><input type="hidden" name="request_id" value="{{.ID}}">
<button name="decision" value="allow">Continue with GitHub</button>
<button name="decision" value="deny">Cancel</button></form></body></html>`))
