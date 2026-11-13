// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/runatlantis/atlantis/server/logging"
)

const (
	// LoginPath starts the GitHub login that issues a personal token.
	LoginPath = "/auth/github/login"
	// CallbackPath is the OAuth redirect target. It must be registered as the
	// authorization callback URL of the GitHub OAuth App or GitHub App.
	CallbackPath = "/auth/github/callback"
	// EndpointPath serves the MCP protocol. It lives under /api/ so that web
	// basic auth does not apply; callers authenticate with a personal token.
	EndpointPath = "/api/mcp"

	stateCookieName = "atlantis_mcp_oauth_state"
	stateLifetime   = 10 * time.Minute
)

// LoginController issues personal tokens to users who prove their identity by
// logging in to GitHub. The GitHub token obtained during the login is used for
// one request, to learn who the user is, and is then dropped. It is requested
// without any scope, so it could not read or change anything anyway.
type LoginController struct {
	Logger logging.SimpleLogging
	Signer *TokenSigner
	// ClientID and ClientSecret belong to a GitHub OAuth App or GitHub App
	// whose callback URL is AtlantisURL + CallbackPath.
	ClientID     string
	ClientSecret string
	// AuthorizeURL, TokenURL and UserURL are the GitHub OAuth endpoints.
	AuthorizeURL string
	TokenURL     string
	UserURL      string
	// AtlantisURL is the externally reachable base URL of this server.
	AtlantisURL *url.URL
	HTTPClient  *http.Client
}

// NewGithubLoginController returns a LoginController for the given GitHub
// hostname. apiURL is the REST API base URL for that host.
func NewGithubLoginController(logger logging.SimpleLogging, signer *TokenSigner, hostname string, apiURL *url.URL, clientID string, clientSecret string, atlantisURL *url.URL) *LoginController {
	web := "https://" + hostname
	return &LoginController{
		Logger:       logger,
		Signer:       signer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthorizeURL: web + "/login/oauth/authorize",
		TokenURL:     web + "/login/oauth/access_token",
		UserURL:      strings.TrimSuffix(apiURL.String(), "/") + "/user",
		AtlantisURL:  atlantisURL,
		HTTPClient:   &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *LoginController) callbackURL() string {
	return strings.TrimSuffix(c.AtlantisURL.String(), "/") + CallbackPath
}

func (c *LoginController) cookiePath() string {
	return strings.TrimSuffix(c.AtlantisURL.Path, "/") + "/auth/github"
}

// Login redirects the browser to GitHub.
func (c *LoginController) Login(w http.ResponseWriter, r *http.Request) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		c.fail(w, http.StatusInternalServerError, "generating login state", err)
		return
	}
	state := hex.EncodeToString(raw)
	c.setStateCookie(w, state, int(stateLifetime.Seconds()))
	q := url.Values{}
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", c.callbackURL())
	q.Set("state", state)
	q.Set("allow_signup", "false")
	http.Redirect(w, r, c.AuthorizeURL+"?"+q.Encode(), http.StatusFound)
}

// setStateCookie sets or, with a negative maxAge, deletes the login state
// cookie. Lax is required: the cookie has to come back on the top-level
// redirect from GitHub.
func (c *LoginController) setStateCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{ // nolint: gosec
		Name:     stateCookieName,
		Value:    value,
		Path:     c.cookiePath(),
		MaxAge:   maxAge,
		HttpOnly: true,
		// Secure whenever Atlantis is served over HTTPS; a plain-HTTP
		// atlantis-url is only expected in local development.
		Secure:   c.AtlantisURL.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

// Callback completes the login and shows the new personal token once.
func (c *LoginController) Callback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(stateCookieName)
	state := r.URL.Query().Get("state")
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		c.fail(w, http.StatusBadRequest, "login state did not match, start again at "+LoginPath, nil)
		return
	}
	// The state is single use.
	c.setStateCookie(w, "", -1)

	code := r.URL.Query().Get("code")
	if code == "" {
		c.fail(w, http.StatusBadRequest, "GitHub did not return an authorization code", nil)
		return
	}
	login, id, err := c.identify(r.Context(), code)
	if err != nil {
		c.fail(w, http.StatusBadGateway, "identifying GitHub user", err)
		return
	}
	token, claims, err := c.Signer.Issue(login, id)
	if err != nil {
		c.fail(w, http.StatusInternalServerError, "issuing token", err)
		return
	}
	c.Logger.Info("issued MCP token %q for user %q, expires %s", claims.ID, login, claims.Expiry().UTC().Format(time.RFC3339))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	if err := tokenPage.Execute(w, tokenPageData{
		Username: login,
		Token:    token,
		Expires:  claims.Expiry().UTC().Format("2006-01-02 15:04 MST"),
		Endpoint: strings.TrimSuffix(c.AtlantisURL.String(), "/") + EndpointPath,
	}); err != nil {
		c.Logger.Err("rendering token page: %s", err)
	}
}

// identify exchanges the authorization code and returns the user's login and id.
func (c *LoginController) identify(ctx context.Context, code string) (string, int64, error) {
	form := url.Values{}
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", c.callbackURL())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var exchange struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := c.doJSON(req, &exchange); err != nil {
		return "", 0, fmt.Errorf("exchanging authorization code: %w", err)
	}
	if exchange.AccessToken == "" {
		return "", 0, fmt.Errorf("exchanging authorization code: %s %s", exchange.Error, exchange.Description)
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, c.UserURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+exchange.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	var user struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	}
	if err := c.doJSON(req, &user); err != nil {
		return "", 0, fmt.Errorf("fetching user: %w", err)
	}
	if user.Login == "" || user.ID == 0 {
		return "", 0, errors.New("fetching user: response had no login")
	}
	return user.Login, user.ID, nil
}

func (c *LoginController) doJSON(req *http.Request, out any) error {
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() // nolint: errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

func (c *LoginController) fail(w http.ResponseWriter, code int, msg string, err error) {
	if err != nil {
		c.Logger.Err("MCP login: %s: %s", msg, err)
	} else {
		c.Logger.Warn("MCP login: %s", msg)
	}
	// The underlying error can carry upstream response details, so only the
	// summary is shown to the browser.
	http.Error(w, "Login failed: "+msg, code)
}

type tokenPageData struct {
	Username string
	Token    string
	Expires  string
	Endpoint string
}

var tokenPage = template.Must(template.New("token").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Atlantis MCP token</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 46rem; margin: 3rem auto; padding: 0 1rem; line-height: 1.5; }
pre { background: #f4f4f4; color: #111; padding: 1rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
.warn { border-left: 4px solid #c60; padding-left: 1rem; }
</style>
</head>
<body>
<h1>Atlantis MCP token</h1>
<p>Signed in as <strong>{{.Username}}</strong>. This token lets an MCP client run Atlantis commands as you. It expires on {{.Expires}}.</p>
<pre>{{.Token}}</pre>
<p class="warn">It is shown only once and cannot be revoked individually. Treat it like a password. Sign in again to get a new one.</p>
<h2>MCP endpoint</h2>
<pre>{{.Endpoint}}</pre>
<p>Send the token as <code>Authorization: Bearer &lt;token&gt;</code>. For example, with Claude Code:</p>
<pre>claude mcp add --transport http atlantis {{.Endpoint}} --header "Authorization: Bearer {{.Token}}"</pre>
</body>
</html>
`))
