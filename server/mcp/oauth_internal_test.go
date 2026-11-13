// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	. "github.com/runatlantis/atlantis/testing"
)

const testRedirect = "http://127.0.0.1:4567/callback?existing=kept"
const testVerifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"

type oauthHarness struct {
	c       *OAuthController
	server  *httptest.Server
	browser *http.Client
	f       *fakes
}

type oauthResult struct {
	status int
	header http.Header
	body   string
}

func newOAuthHarness(t *testing.T) *oauthHarness {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	login := newTestLogin(t, fakeGithub(t))
	login.AtlantisURL, _ = url.Parse(srv.URL)
	c, err := NewOAuthController(login, time.Hour, 30*24*time.Hour)
	Ok(t, err)
	mux.HandleFunc("GET "+LoginPath, login.Login)
	mux.HandleFunc("GET "+CallbackPath, login.Callback)
	mux.Handle(ResourceMetadataPath, c.ResourceMetadata())
	mux.Handle(ResourceMetadataPath+EndpointPath, c.ResourceMetadata())
	mux.HandleFunc("GET "+AuthorizationMetadataPath, c.AuthorizationMetadata)
	mux.HandleFunc("POST "+RegisterPath, c.Register)
	mux.HandleFunc("GET "+AuthorizePath, c.Authorize)
	mux.HandleFunc("POST "+AuthorizePath, c.Authorize)
	mux.HandleFunc("POST "+TokenPath, c.Token)
	svc, f := newTestService(t)
	mux.Handle(EndpointPath, NewHandler(svc, c.signer, "test", c.resource))
	jar, err := cookiejar.New(nil)
	Ok(t, err)
	return &oauthHarness{c: c, server: srv, f: f, browser: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (h *oauthHarness) request(t *testing.T, method, target, body, contentType string) oauthResult {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = h.server.URL + target
	}
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	Ok(t, err)
	req.Header.Set("Content-Type", contentType)
	resp, err := h.browser.Do(req)
	Ok(t, err)
	defer resp.Body.Close() // nolint: errcheck
	data, err := io.ReadAll(resp.Body)
	Ok(t, err)
	return oauthResult{resp.StatusCode, resp.Header, string(data)}
}

func (h *oauthHarness) register(t *testing.T, redirects ...string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"redirect_uris": redirects, "client_name": "Test client", "token_endpoint_auth_method": "none"})
	Ok(t, err)
	res := h.request(t, "POST", RegisterPath, string(body), "application/json")
	Equals(t, http.StatusCreated, res.status)
	var out oauthex.ClientRegistrationResponse
	Ok(t, json.Unmarshal([]byte(res.body), &out))
	Equals(t, "none", out.TokenEndpointAuthMethod)
	Equals(t, "", out.ClientSecret)
	return out.ClientID
}

func authorizationQuery(id string) url.Values {
	sum := sha256.Sum256([]byte(testVerifier))
	return url.Values{"client_id": {id}, "redirect_uri": {testRedirect}, "response_type": {"code"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "state": {"opaque client state & +"}}
}

func (h *oauthHarness) consentForm(t *testing.T, q url.Values) url.Values {
	t.Helper()
	res := h.request(t, "GET", AuthorizePath+"?"+q.Encode(), "", "")
	Equals(t, http.StatusOK, res.status)
	Assert(t, strings.Contains(res.body, "Test client"), "consent must identify client")
	match := regexp.MustCompile(`name="request_id" value="([^"]+)"`).FindStringSubmatch(res.body)
	Equals(t, 2, len(match))
	return url.Values{"request_id": {match[1]}, "decision": {"allow"}}
}

func (h *oauthHarness) code(t *testing.T, id string) string {
	t.Helper()
	q := authorizationQuery(id)
	q.Set("resource", h.c.resource)
	form := h.consentForm(t, q)
	res := h.request(t, "POST", AuthorizePath, form.Encode(), "application/x-www-form-urlencoded")
	Equals(t, http.StatusFound, res.status)
	res = h.request(t, "GET", res.header.Get("Location"), "", "") // Fake GitHub login.
	Equals(t, http.StatusFound, res.status)
	callback := res.header.Get("Location")
	res = h.request(t, "GET", callback, "", "")
	Equals(t, http.StatusFound, res.status)
	target, err := url.Parse(res.header.Get("Location"))
	Ok(t, err)
	Equals(t, "kept", target.Query().Get("existing"))
	Equals(t, q.Get("state"), target.Query().Get("state"))
	Equals(t, h.c.issuer, target.Query().Get("iss"))
	Assert(t, target.Query().Get("code") != "", "missing code: %s", res.body)
	return target.Query().Get("code")
}

func exchangeForm(id, code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {id}, "code": {code}, "redirect_uri": {testRedirect}, "code_verifier": {testVerifier}}
}

func (h *oauthHarness) exchange(t *testing.T, form url.Values) oauthResult {
	t.Helper()
	res := h.request(t, "POST", TokenPath, form.Encode(), "application/x-www-form-urlencoded")
	Equals(t, "no-store", res.header.Get("Cache-Control"))
	Equals(t, "no-cache", res.header.Get("Pragma"))
	return res
}

func readTokens(t *testing.T, res oauthResult) tokenResponse {
	t.Helper()
	Equals(t, http.StatusOK, res.status)
	var out tokenResponse
	Ok(t, json.Unmarshal([]byte(res.body), &out))
	Equals(t, "Bearer", out.TokenType)
	Equals(t, int64(3600), out.ExpiresIn)
	return out
}

func expectOAuthError(t *testing.T, res oauthResult, code string) {
	t.Helper()
	Equals(t, http.StatusBadRequest, res.status)
	var out map[string]string
	Ok(t, json.Unmarshal([]byte(res.body), &out))
	Equals(t, code, out["error"])
	Equals(t, "", res.header.Get("Location"))
}

func TestOAuthMetadata(t *testing.T) {
	h := newOAuthHarness(t)
	for _, path := range []string{ResourceMetadataPath, ResourceMetadataPath + EndpointPath} {
		res := h.request(t, "GET", path, "", "")
		Equals(t, http.StatusOK, res.status)
		var meta oauthex.ProtectedResourceMetadata
		Ok(t, json.Unmarshal([]byte(res.body), &meta))
		Equals(t, h.c.resource, meta.Resource)
		Equals(t, []string{h.c.issuer}, meta.AuthorizationServers)
		Equals(t, []string{"header"}, meta.BearerMethodsSupported)
	}
	res := h.request(t, "GET", AuthorizationMetadataPath, "", "")
	var meta oauthex.AuthServerMeta
	Ok(t, json.Unmarshal([]byte(res.body), &meta))
	Equals(t, h.c.issuer, meta.Issuer)
	Equals(t, h.c.issuer+AuthorizePath, meta.AuthorizationEndpoint)
	Equals(t, h.c.issuer+TokenPath, meta.TokenEndpoint)
	Equals(t, h.c.issuer+RegisterPath, meta.RegistrationEndpoint)
	Equals(t, []string{"S256"}, meta.CodeChallengeMethodsSupported)
	Equals(t, []string{"authorization_code", "refresh_token"}, meta.GrantTypesSupported)
	Equals(t, []string{"none"}, meta.TokenEndpointAuthMethodsSupported)
	Assert(t, meta.AuthorizationResponseIssParameterSupported, "must advertise issuer in response")
}

func TestOAuthRegistration(t *testing.T) {
	h := newOAuthHarness(t)
	for _, uri := range []string{testRedirect, "http://localhost:1234/cb", "http://[::1]:1234/cb", "https://client.example/cb", "https://client.example:1234/cb?x=y"} {
		t.Run(uri, func(t *testing.T) {
			id := h.register(t, uri)
			client, err := h.c.client(id)
			Ok(t, err)
			Equals(t, []string{uri}, client.RedirectURIs)
			Equals(t, "Test client", client.Name)
			_, err = h.c.client(id + "tampered")
			Assert(t, err != nil, "tampered client accepted")
		})
	}
	for _, uri := range []string{"", "http://example.com/cb", "http://localhost/cb", "http://127.0.0.2:1234/cb", "http://localhost.evil:1234/cb", "https://user@client.example/cb", "https://client.example/#fragment", "https://client.example/#", "file:///cb", "javascript:alert(1)", "app:/cb", "/relative", "//client.example/cb", "http://[::1]:0/cb", "http://127.0.0.1:65536/cb", "https://client.example/" + strings.Repeat("a", 512)} {
		t.Run(uri, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"redirect_uris": []string{uri}})
			Ok(t, err)
			expectOAuthError(t, h.request(t, "POST", RegisterPath, string(body), "application/json"), "invalid_redirect_uri")
		})
	}
	for _, body := range []string{`{`, `{}` + `{}`, strings.Repeat(" ", maxOAuthBody) + `{}`} {
		expectOAuthError(t, h.request(t, "POST", RegisterPath, body, "application/json"), "invalid_client_metadata")
	}
	for _, extra := range []string{`"token_endpoint_auth_method":"client_secret_basic"`, `"grant_types":["implicit"]`, `"response_types":["token"]`, `"scope":"admin"`, `"client_name":"` + strings.Repeat("x", 129) + `"`} {
		expectOAuthError(t, h.request(t, "POST", RegisterPath, `{"redirect_uris":["https://client.example/cb"],`+extra+`}`, "application/json"), "invalid_client_metadata")
	}
	for _, body := range []string{`{}`, `{"redirect_uris":[]}`, `{"redirect_uris":["https://a","https://b","https://c","https://d","https://e"]}`} {
		expectOAuthError(t, h.request(t, "POST", RegisterPath, body, "application/json"), "invalid_redirect_uri")
	}
}

func TestOAuthAuthorizeValidation(t *testing.T) {
	h := newOAuthHarness(t)
	id := h.register(t, testRedirect)
	cases := []struct {
		name, key, value, err string
		redirect              bool
	}{
		{"missing challenge", "code_challenge", "", "invalid_request", true},
		{"plain PKCE", "code_challenge_method", "plain", "invalid_request", true},
		{"missing PKCE method", "code_challenge_method", "", "invalid_request", true},
		{"bad PKCE", "code_challenge", "bad", "invalid_request", true},
		{"response type", "response_type", "token", "unsupported_response_type", true},
		{"bad resource", "resource", "https://other.example/api/mcp", "invalid_target", true},
		{"scope", "scope", "admin", "invalid_scope", true},
		{"response mode", "response_mode", "fragment", "invalid_request", true},
		{"URI mismatch", "redirect_uri", "https://attacker.example", "invalid_request", false},
		{"loopback path mismatch", "redirect_uri", "http://127.0.0.1:9999/other?existing=kept", "invalid_request", false},
		{"loopback host mismatch", "redirect_uri", "http://localhost:4567/callback?existing=kept", "invalid_request", false},
		{"tampered client", "client_id", id + "tampered", "invalid_request", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := authorizationQuery(id)
			q.Set(tc.key, tc.value)
			res := h.request(t, "GET", AuthorizePath+"?"+q.Encode(), "", "")
			if !tc.redirect {
				expectOAuthError(t, res, tc.err)
				return
			}
			Equals(t, http.StatusFound, res.status)
			target, err := url.Parse(res.header.Get("Location"))
			Ok(t, err)
			Equals(t, tc.err, target.Query().Get("error"))
			Equals(t, q.Get("state"), target.Query().Get("state"))
			Equals(t, h.c.issuer, target.Query().Get("iss"))
			Equals(t, "127.0.0.1:4567", target.Host)
		})
	}
	q := authorizationQuery(id)
	q.Set("redirect_uri", strings.Replace(testRedirect, ":4567", ":9999", 1))
	res := h.request(t, "GET", AuthorizePath+"?"+q.Encode(), "", "")
	Equals(t, http.StatusOK, res.status)
	q.Add("resource", h.c.resource)
	q.Add("resource", "https://attacker.example")
	expectOAuthError(t, h.request(t, "GET", AuthorizePath+"?"+q.Encode(), "", ""), "invalid_request")
	expectOAuthError(t, h.request(t, "GET", AuthorizePath+"?bad=%zz", "", ""), "invalid_request")
}

func TestOAuthHTTPFlowAndBearer(t *testing.T) {
	h := newOAuthHarness(t)
	id := h.register(t, testRedirect)
	code := h.code(t, id)
	form := exchangeForm(id, code)
	form.Set("resource", h.c.resource)
	tokens := readTokens(t, h.exchange(t, form))
	claims, err := h.c.signer.verifyBearer(tokens.AccessToken, h.c.resource)
	Ok(t, err)
	Equals(t, "octocat", claims.Username)
	Equals(t, int64(42), claims.UserID)
	Equals(t, h.c.resource, claims.Audience)
	legacy, _, err := h.c.signer.Issue("octocat", 42)
	Ok(t, err)
	wrongAudience, _, err := h.c.signer.issue("octocat", 42, "access", "https://other.example/api/mcp", time.Hour)
	Ok(t, err)
	expired, _, err := h.c.signer.issue("octocat", 42, "access", h.c.resource, -time.Hour)
	Ok(t, err)
	for _, tc := range []struct {
		name, token string
		status      int
	}{
		{"OAuth access", tokens.AccessToken, http.StatusOK}, {"legacy personal", legacy, http.StatusOK},
		{"refresh", tokens.RefreshToken, http.StatusUnauthorized}, {"code", code, http.StatusUnauthorized},
		{"client", id, http.StatusUnauthorized}, {"missing", "", http.StatusUnauthorized},
		{"tampered", tokens.AccessToken + "tampered", http.StatusUnauthorized}, {"audience", wrongAudience, http.StatusUnauthorized},
		{"expired", expired, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", h.c.resource, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			Ok(t, err)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			resp, err := h.browser.Do(req)
			Ok(t, err)
			defer resp.Body.Close() // nolint: errcheck
			Equals(t, tc.status, resp.StatusCode)
			if tc.status == http.StatusUnauthorized {
				Equals(t, `Bearer resource_metadata="`+resourceMetadataURL(h.c.resource)+`"`, resp.Header.Get("WWW-Authenticate"))
			} else {
				body, err := io.ReadAll(resp.Body)
				Ok(t, err)
				Assert(t, strings.Contains(string(body), "atlantis_whoami"), "tools/list did not list tools")
			}
		})
	}
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {tokens.RefreshToken}, "resource": {h.c.resource}}
	next := readTokens(t, h.exchange(t, refresh))
	Assert(t, next.RefreshToken != tokens.RefreshToken && next.AccessToken != tokens.AccessToken, "tokens must rotate")
	expectOAuthError(t, h.exchange(t, refresh), "invalid_grant")
	refresh.Set("refresh_token", next.RefreshToken)
	expectOAuthError(t, h.exchange(t, refresh), "invalid_grant") // Replay revokes the family.
	for _, token := range []string{tokens.AccessToken, legacy, code, id} {
		refresh.Set("refresh_token", token)
		expectOAuthError(t, h.exchange(t, refresh), "invalid_grant")
	}
}

func TestOAuthTokenValidation(t *testing.T) {
	h := newOAuthHarness(t)
	id := h.register(t, testRedirect)
	code := h.code(t, id)
	other := h.register(t, "https://different.example/cb")
	for _, tc := range []struct{ key, value, err string }{
		{"code_verifier", strings.Repeat("z", 43), "invalid_grant"}, {"code_verifier", "short", "invalid_grant"},
		{"redirect_uri", "http://127.0.0.1:9999/callback?existing=kept", "invalid_grant"},
		{"client_id", other, "invalid_grant"}, {"client_id", id + "x", "invalid_client"},
		{"resource", "https://other.example/api/mcp", "invalid_target"}, {"grant_type", "password", "unsupported_grant_type"},
		{"scope", "admin", "invalid_scope"}, {"code", code + "tampered", "invalid_grant"},
	} {
		t.Run(tc.key+tc.value[:min(len(tc.value), 16)], func(t *testing.T) {
			form := exchangeForm(id, code)
			form.Set(tc.key, tc.value)
			expectOAuthError(t, h.exchange(t, form), tc.err)
		})
	}
	form := exchangeForm(id, code)
	form.Add("client_id", other)
	expectOAuthError(t, h.exchange(t, form), "invalid_request")
	readTokens(t, h.exchange(t, exchangeForm(id, code)))
	expectOAuthError(t, h.exchange(t, exchangeForm(id, code)), "invalid_grant")
	code = h.code(t, id)
	now := h.c.signer.now()
	h.c.signer.now = func() time.Time { return now.Add(61 * time.Second) }
	expectOAuthError(t, h.exchange(t, exchangeForm(id, code)), "invalid_grant")
}

func TestOAuthConcurrentCodeExchange(t *testing.T) {
	h := newOAuthHarness(t)
	id := h.register(t, testRedirect)
	code := h.code(t, id)
	var wg sync.WaitGroup
	statuses := make(chan int, 8)
	for range 8 {
		wg.Go(func() {
			r := httptest.NewRequest("POST", TokenPath, strings.NewReader(exchangeForm(id, code).Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			h.c.Token(w, r)
			statuses <- w.Code
		})
	}
	wg.Wait()
	close(statuses)
	successes := 0
	for status := range statuses {
		if status == http.StatusOK {
			successes++
		} else {
			Equals(t, http.StatusBadRequest, status)
		}
	}
	Equals(t, 1, successes)
}

func TestOAuthConsentAndCallback(t *testing.T) {
	h := newOAuthHarness(t)
	id := h.register(t, testRedirect)
	form := h.consentForm(t, authorizationQuery(id))
	bad := url.Values{"request_id": {form.Get("request_id") + "tampered"}, "decision": {"allow"}}
	expectOAuthError(t, h.request(t, "POST", AuthorizePath, bad.Encode(), "application/x-www-form-urlencoded"), "invalid_request")
	form.Set("decision", "deny")
	res := h.request(t, "POST", AuthorizePath, form.Encode(), "application/x-www-form-urlencoded")
	Equals(t, http.StatusFound, res.status)
	target, err := url.Parse(res.header.Get("Location"))
	Ok(t, err)
	Equals(t, "access_denied", target.Query().Get("error"))
	for _, query := range []string{"error=access_denied", "code=bad", "code=good-code"} {
		form = h.consentForm(t, authorizationQuery(id))
		res = h.request(t, "POST", AuthorizePath, form.Encode(), "application/x-www-form-urlencoded")
		Equals(t, http.StatusFound, res.status)
		state := form.Get("request_id")
		callback := CallbackPath + "?state=" + state + "&" + query
		res = h.request(t, "GET", callback, "", "")
		Equals(t, http.StatusFound, res.status)
		target, err = url.Parse(res.header.Get("Location"))
		Ok(t, err)
		if query == "error=access_denied" {
			Equals(t, "access_denied", target.Query().Get("error"))
		}
		if query == "code=bad" {
			Equals(t, "server_error", target.Query().Get("error"))
		}
		res = h.request(t, "GET", callback, "", "")
		Equals(t, http.StatusBadRequest, res.status)
	}
}

func TestOAuthRefreshExpiryAndRestart(t *testing.T) {
	h := newOAuthHarness(t)
	id := h.register(t, testRedirect)
	tokens := readTokens(t, h.exchange(t, exchangeForm(id, h.code(t, id))))
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {tokens.RefreshToken}}
	var original oauthGrant
	Ok(t, h.c.signer.decode(tokens.RefreshToken, &original))
	now := h.c.signer.now()
	h.c.signer.now = func() time.Time { return now.Add(time.Hour) }
	next := readTokens(t, h.exchange(t, refresh))
	var rotated oauthGrant
	Ok(t, h.c.signer.decode(next.RefreshToken, &rotated))
	Equals(t, original.ExpiresAt, rotated.ExpiresAt)
	refresh.Set("refresh_token", next.RefreshToken)
	h.c.signer.now = func() time.Time { return now.Add(30 * 24 * time.Hour) }
	expectOAuthError(t, h.exchange(t, refresh), "invalid_grant")
	h.c.signer.now = time.Now
	tokens = readTokens(t, h.exchange(t, exchangeForm(id, h.code(t, id))))
	code := h.code(t, id)
	restarted, err := NewOAuthController(h.c.login, time.Hour, 30*24*time.Hour)
	Ok(t, err)
	for _, form := range []url.Values{exchangeForm(id, code), {"grant_type": {"refresh_token"}, "client_id": {id}, "refresh_token": {tokens.RefreshToken}}} {
		req := httptest.NewRequest("POST", TokenPath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		restarted.Token(w, req)
		Equals(t, http.StatusBadRequest, w.Code)
	}
	_, err = restarted.client(id)
	Ok(t, err) // Stateless registrations survive restart.
	_, err = restarted.signer.verifyBearer(tokens.AccessToken, restarted.resource)
	Ok(t, err) // Access tokens retain their bounded lifetime.
}

func TestOAuthControllerConfigurationAndDiscoveryPaths(t *testing.T) {
	login := newTestLogin(t, fakeGithub(t))
	for _, raw := range []string{"http://public.example", "https://user@public.example", "https://public.example?query=x", "https://public.example#fragment", "/relative"} {
		login.AtlantisURL, _ = url.Parse(raw)
		_, err := NewOAuthController(login, time.Hour, time.Hour)
		Assert(t, err != nil, "unsafe base URL accepted: %s", raw)
	}
	login.AtlantisURL, _ = url.Parse("https://atlantis.example/prefix/")
	_, err := NewOAuthController(login, 0, time.Hour)
	Assert(t, err != nil, "zero lifetime accepted")
	c, err := NewOAuthController(login, time.Hour, time.Hour)
	Ok(t, err)
	Equals(t, "https://atlantis.example/prefix/api/mcp", c.resource)
	Equals(t, "https://atlantis.example/.well-known/oauth-protected-resource/prefix/api/mcp", resourceMetadataURL(c.resource))
	for _, path := range c.DiscoveryPaths() {
		w := httptest.NewRecorder()
		c.DiscoveryHandler(path).ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		Equals(t, http.StatusOK, w.Code)
		Assert(t, strings.Contains(w.Body.String(), "https://atlantis.example/prefix"), "discovery lost base path")
	}
	for _, host := range []string{"127.0.0.1", "localhost", "[::1]"} {
		a := "http://" + host + ":1000/cb?existing=kept"
		b := "http://" + host + ":2000/cb?existing=kept"
		Assert(t, matchesRedirect(a, b), "loopback port change must work")
		Assert(t, !matchesRedirect(a, b+"-changed"), "loopback query change must fail")
	}
	Assert(t, !matchesRedirect("https://example.com:1000/cb", "https://example.com:2000/cb"), "HTTPS ports must match exactly")
}

func TestOAuthConsentExpiryAndCapacity(t *testing.T) {
	h := newOAuthHarness(t)
	id := h.register(t, testRedirect)
	form := h.consentForm(t, authorizationQuery(id))
	now := h.c.signer.now()
	h.c.signer.now = func() time.Time { return now.Add(stateLifetime) }
	expectOAuthError(t, h.request(t, "POST", AuthorizePath, form.Encode(), "application/x-www-form-urlencoded"), "invalid_request")
	h.c.signer.now = time.Now
	h.c.mu.Lock()
	for i := range maxOAuthEntries {
		h.c.pending[strconv.Itoa(i)] = authorizationRequest{ExpiresAt: time.Now().Add(time.Hour).Unix()}
	}
	h.c.mu.Unlock()
	res := h.request(t, "GET", AuthorizePath+"?"+authorizationQuery(id).Encode(), "", "")
	Equals(t, http.StatusFound, res.status)
	target, err := url.Parse(res.header.Get("Location"))
	Ok(t, err)
	Equals(t, "temporarily_unavailable", target.Query().Get("error"))
	h.c.signer.now = func() time.Time { return now.Add(2 * time.Hour) }
	res = h.request(t, "GET", AuthorizePath+"?"+authorizationQuery(id).Encode(), "", "")
	Equals(t, http.StatusOK, res.status)
}

func TestOAuthCommandsKeepUserAndPermissions(t *testing.T) {
	h := newOAuthHarness(t)
	id := h.register(t, testRedirect)
	tokens := readTokens(t, h.exchange(t, exchangeForm(id, h.code(t, id))))
	client := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "0"}, nil)
	session, err := client.Connect(context.Background(), &sdk.StreamableClientTransport{
		Endpoint: h.c.resource, HTTPClient: &http.Client{Transport: bearerTransport{token: tokens.AccessToken}},
		DisableStandaloneSSE: true, MaxRetries: -1,
	}, nil)
	Ok(t, err)
	defer session.Close() // nolint: errcheck
	res, err := session.CallTool(context.Background(), &sdk.CallToolParams{Name: "atlantis_plan", Arguments: map[string]any{"repo": "owner/repo", "pull": 7}})
	Ok(t, err)
	Assert(t, !res.IsError, "OAuth command failed: %+v", res.Content)
	ran := h.f.commands()
	Equals(t, 1, len(ran))
	Equals(t, "octocat", ran[0].user.Username)
	h.f.permission = "read"
	res, err = session.CallTool(context.Background(), &sdk.CallToolParams{Name: "atlantis_plan", Arguments: map[string]any{"repo": "owner/repo", "pull": 8}})
	Ok(t, err)
	Assert(t, res.IsError, "write must fail after repository permission is removed")
	Equals(t, 1, len(h.f.commands()))
}

func TestOAuthTokenRequestBoundsAndBinding(t *testing.T) {
	h := newOAuthHarness(t)
	id := h.register(t, testRedirect)
	tokens := readTokens(t, h.exchange(t, exchangeForm(id, h.code(t, id))))
	other := h.register(t, "https://other.example/callback")
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {other}, "refresh_token": {tokens.RefreshToken}}
	expectOAuthError(t, h.exchange(t, form), "invalid_grant")
	form.Set("client_id", id)
	form.Set("resource", h.c.resource+"#")
	expectOAuthError(t, h.exchange(t, form), "invalid_target")
	form.Del("resource")
	form.Set("client_secret", "secret")
	expectOAuthError(t, h.exchange(t, form), "invalid_client")
	form.Del("client_secret")
	expectOAuthError(t, h.request(t, "POST", TokenPath, form.Encode(), "application/json"), "invalid_request")
	expectOAuthError(t, h.request(t, "POST", TokenPath+"?grant_type=refresh_token", form.Encode(), "application/x-www-form-urlencoded"), "invalid_request")
	form.Set("extra", strings.Repeat("x", maxOAuthBody))
	expectOAuthError(t, h.exchange(t, form), "invalid_request")
	form.Del("extra")
	readTokens(t, h.exchange(t, form)) // Invalid requests did not consume the refresh token.
	redirects := make([]string, 4)
	for i := range redirects {
		redirects[i] = "https://client.example/" + strings.Repeat("<", 480)
	}
	body, err := json.Marshal(map[string]any{"redirect_uris": redirects})
	Ok(t, err)
	expectOAuthError(t, h.request(t, "POST", RegisterPath, string(body), "application/json"), "invalid_client_metadata")
}
