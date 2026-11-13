// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/runatlantis/atlantis/server/logging"
	. "github.com/runatlantis/atlantis/testing"
)

// fakeGithub serves the two GitHub endpoints the login uses.
func fakeGithub(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		Ok(t, r.ParseForm())
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("client_id") != "id" || r.Form.Get("client_secret") != "secret" || r.Form.Get("code") != "good-code" {
			io.WriteString(w, `{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired."}`) // nolint: errcheck
			return
		}
		io.WriteString(w, `{"access_token":"gho_test","token_type":"bearer","scope":""}`) // nolint: errcheck
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gho_test" {
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		io.WriteString(w, `{"login":"octocat","id":42}`) // nolint: errcheck
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestLogin(t *testing.T, gh *httptest.Server) *LoginController {
	t.Helper()
	atlantisURL, err := url.Parse("https://atlantis.example.com")
	Ok(t, err)
	return &LoginController{
		Logger:       logging.NewNoopLogger(t),
		Signer:       newTestSigner(t),
		ClientID:     "id",
		ClientSecret: "secret",
		AuthorizeURL: gh.URL + "/login/oauth/authorize",
		TokenURL:     gh.URL + "/login/oauth/access_token",
		UserURL:      gh.URL + "/user",
		AtlantisURL:  atlantisURL,
		HTTPClient:   gh.Client(),
	}
}

func startLogin(t *testing.T, c *LoginController) (*http.Cookie, string) {
	t.Helper()
	w := httptest.NewRecorder()
	c.Login(w, httptest.NewRequest(http.MethodGet, LoginPath, nil))
	Equals(t, http.StatusFound, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	Ok(t, err)
	Equals(t, "id", loc.Query().Get("client_id"))
	Equals(t, "https://atlantis.example.com"+CallbackPath, loc.Query().Get("redirect_uri"))
	// No scope is requested: the login only has to prove who the user is.
	Equals(t, "", loc.Query().Get("scope"))
	cookies := w.Result().Cookies()
	Equals(t, 1, len(cookies))
	Assert(t, cookies[0].HttpOnly && cookies[0].Secure, "state cookie must be HttpOnly and Secure")
	Equals(t, cookies[0].Value, loc.Query().Get("state"))
	return cookies[0], loc.Query().Get("state")
}

func TestLogin_IssuesTokenForGithubUser(t *testing.T) {
	c := newTestLogin(t, fakeGithub(t))
	cookie, state := startLogin(t, c)

	req := httptest.NewRequest(http.MethodGet, CallbackPath+"?code=good-code&state="+state, nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	c.Callback(w, req)

	Equals(t, http.StatusOK, w.Code)
	Equals(t, "no-store", w.Header().Get("Cache-Control"))
	token := regexp.MustCompile(regexp.QuoteMeta(TokenPrefix) + `\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`).FindString(w.Body.String())
	Assert(t, token != "", "no token in page: %s", w.Body.String())
	claims, err := c.Signer.Verify(token)
	Ok(t, err)
	Equals(t, "octocat", claims.Username)
	Equals(t, int64(42), claims.UserID)
	Assert(t, strings.Contains(w.Body.String(), "https://atlantis.example.com"+EndpointPath), "page must show the endpoint")
}

func TestLogin_Callback_Rejects(t *testing.T) {
	c := newTestLogin(t, fakeGithub(t))
	cookie, state := startLogin(t, c)

	cases := []struct {
		name   string
		query  string
		cookie *http.Cookie
		code   int
	}{
		{"no state cookie", "?code=good-code&state=" + state, nil, http.StatusBadRequest},
		{"state mismatch", "?code=good-code&state=other", cookie, http.StatusBadRequest},
		{"empty state", "?code=good-code", cookie, http.StatusBadRequest},
		{"no code", "?state=" + state, cookie, http.StatusBadRequest},
		{"bad code", "?code=bad&state=" + state, cookie, http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, CallbackPath+tc.query, nil)
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}
			w := httptest.NewRecorder()
			c.Callback(w, req)
			Equals(t, tc.code, w.Code)
			Assert(t, !strings.Contains(w.Body.String(), TokenPrefix), "no token may be issued")
		})
	}
}
