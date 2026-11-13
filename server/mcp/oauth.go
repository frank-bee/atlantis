// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

const (
	ResourceMetadataPath      = "/.well-known/oauth-protected-resource"
	AuthorizationMetadataPath = "/.well-known/oauth-authorization-server"
	AuthorizePath             = "/oauth/authorize"
	TokenPath                 = "/oauth/token" // nolint: gosec
	RegisterPath              = "/oauth/register"
	maxOAuthBody              = 16384
	maxOAuthEntries           = 10000
)

// OAuthController authorizes public MCP clients using GitHub identities.
// Registrations are stateless. Pending logins, codes and refresh families live
// in bounded memory and are invalidated on restart; use a single instance.
type OAuthController struct {
	login      *LoginController
	signer     *TokenSigner
	issuer     string
	resource   string
	accessTTL  time.Duration
	refreshTTL time.Duration
	mu         sync.Mutex
	pending    map[string]authorizationRequest
	codes      map[string]int64
	families   map[string]refreshFamily
}

type registeredClient struct {
	Kind         string   `json:"kind"`
	Audience     string   `json:"aud"`
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"client_name,omitempty"`
}

// NewOAuthController connects native MCP authorization to the existing login.
func NewOAuthController(login *LoginController, accessTTL, refreshTTL time.Duration) (*OAuthController, error) {
	base := login.AtlantisURL
	if base == nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		(base.Scheme != "https" && (base.Scheme != "http" || !isLoopback(base.Hostname()))) {
		return nil, errors.New("mcp oauth requires an https atlantis-url (http is allowed only on loopback)")
	}
	if accessTTL < time.Second || refreshTTL < time.Second {
		return nil, errors.New("mcp oauth token lifetimes must be positive")
	}
	issuer := strings.TrimSuffix(base.String(), "/")
	c := &OAuthController{
		login: login, signer: login.Signer, issuer: issuer, resource: issuer + EndpointPath,
		accessTTL: accessTTL, refreshTTL: refreshTTL,
		pending: make(map[string]authorizationRequest), codes: make(map[string]int64), families: make(map[string]refreshFamily),
	}
	login.OAuth = c
	return c, nil
}

// ResourceURL is the audience of OAuth access tokens.
func (c *OAuthController) ResourceURL() string { return c.resource }

// DiscoveryPaths returns origin-root metadata paths, including path-qualified
// discovery when atlantis-url contains a reverse-proxy prefix.
func (c *OAuthController) DiscoveryPaths() []string {
	basePath := strings.TrimSuffix(c.login.AtlantisURL.Path, "/")
	paths := []string{ResourceMetadataPath, ResourceMetadataPath + basePath + EndpointPath, AuthorizationMetadataPath}
	if basePath != "" {
		paths = append(paths, AuthorizationMetadataPath+basePath)
	}
	return paths
}

// DiscoveryHandler serves metadata for a path returned by DiscoveryPaths.
func (c *OAuthController) DiscoveryHandler(path string) http.Handler {
	if strings.HasPrefix(path, ResourceMetadataPath) {
		return c.ResourceMetadata()
	}
	return http.HandlerFunc(c.AuthorizationMetadata)
}

func resourceMetadataURL(resource string) string {
	u, err := url.Parse(resource)
	if err != nil {
		return ""
	}
	u.Path = ResourceMetadataPath + u.Path
	u.RawPath = ""
	return u.String()
}

// ResourceMetadata serves RFC 9728 metadata using the SDK's CORS-aware handler.
func (c *OAuthController) ResourceMetadata() http.Handler {
	return sdkauth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource: c.resource, AuthorizationServers: []string{c.issuer},
		BearerMethodsSupported: []string{"header"}, ResourceName: "Atlantis MCP",
	})
}

// AuthorizationMetadata serves the supported RFC 8414 capabilities.
func (c *OAuthController) AuthorizationMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	oauthJSON(w, http.StatusOK, map[string]any{
		"authorization_response_iss_parameter_supported": true,
		"issuer": c.issuer, "authorization_endpoint": c.issuer + AuthorizePath,
		"token_endpoint": c.issuer + TokenPath, "registration_endpoint": c.issuer + RegisterPath,
		"response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

// Register issues a signed client identifier without storing a registration.
func (c *OAuthController) Register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBody)
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	var in oauthex.ClientRegistrationMetadata
	dec := json.NewDecoder(r.Body)
	if media != "application/json" || dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF {
		oauthError(w, "invalid_client_metadata", "expected a bounded JSON registration")
		return
	}
	if len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > 4 {
		oauthError(w, "invalid_redirect_uri", "register between one and four redirect URIs")
		return
	}
	for _, uri := range in.RedirectURIs {
		if !validRedirect(uri) {
			oauthError(w, "invalid_redirect_uri", "redirect URIs must use https or an http loopback address with a port")
			return
		}
	}
	if len(in.ClientName) > 128 || (in.TokenEndpointAuthMethod != "" && in.TokenEndpointAuthMethod != "none") || in.Scope != "" ||
		!subset(in.GrantTypes, "authorization_code", "refresh_token") || !subset(in.ResponseTypes, "code") {
		oauthError(w, "invalid_client_metadata", "only public authorization code clients without scopes are supported")
		return
	}
	client := registeredClient{Kind: "client", Audience: c.resource, RedirectURIs: in.RedirectURIs, Name: in.ClientName}
	id, err := c.signer.encode(client)
	if err != nil {
		oauthError(w, "server_error", "encoding client registration")
		return
	}
	if len(id) > 4096 {
		oauthError(w, "invalid_client_metadata", "encoded client registration is too large")
		return
	}
	oauthJSON(w, http.StatusCreated, &oauthex.ClientRegistrationResponse{
		ClientID: id, ClientIDIssuedAt: c.signer.now(),
		ClientRegistrationMetadata: oauthex.ClientRegistrationMetadata{
			RedirectURIs: in.RedirectURIs, ClientName: in.ClientName, TokenEndpointAuthMethod: "none",
			GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"},
		},
	})
}

func subset(values []string, allowed ...string) bool {
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return false
		}
	}
	return true
}

func (c *OAuthController) client(id string) (registeredClient, error) {
	var client registeredClient
	if len(id) > 4096 || c.signer.decode(id, &client) != nil || client.Kind != "client" || client.Audience != c.resource {
		return registeredClient{}, ErrInvalidToken
	}
	return client, nil
}

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func validRedirect(raw string) bool {
	if len(raw) > 512 || strings.Contains(raw, "#") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Opaque != "" {
		return false
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	return u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname()) && u.Port() != "")
}

func matchesRedirect(registered, requested string) bool {
	if !validRedirect(requested) {
		return false
	}
	if registered == requested {
		return true
	}
	a, err := url.Parse(registered)
	if err != nil || a.Scheme != "http" || !isLoopback(a.Hostname()) {
		return false
	}
	b, err := url.Parse(requested)
	if err != nil || a.Hostname() != b.Hostname() {
		return false
	}
	// RFC 8252 permits only the port to vary, not the path, query or host.
	a.Host, b.Host = a.Hostname(), b.Hostname()
	return a.String() == b.String()
}

func (c *OAuthController) validResource(raw string) bool {
	// Older clients omit resource; always bind to this MCP endpoint.
	if raw == "" {
		return true
	}
	a, err := url.Parse(raw)
	if err != nil || strings.Contains(raw, "#") {
		return false
	}
	b, _ := url.Parse(c.resource)
	a.Scheme, a.Host = strings.ToLower(a.Scheme), strings.ToLower(a.Host)
	b.Scheme, b.Host = strings.ToLower(b.Scheme), strings.ToLower(b.Host)
	return a.String() == b.String()
}

func oauthJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func oauthError(w http.ResponseWriter, code, description string) {
	status := http.StatusBadRequest
	if code == "server_error" {
		status = http.StatusInternalServerError
	}
	oauthJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func singleValues(values url.Values) bool {
	for _, v := range values {
		if len(v) != 1 {
			return false
		}
	}
	return true
}

// prune is called with mu held. No background goroutine outlives the server.
func (c *OAuthController) prune() {
	now := c.signer.now().Unix()
	for id, req := range c.pending {
		if req.ExpiresAt <= now {
			delete(c.pending, id)
		}
	}
	for id, expiry := range c.codes {
		if expiry <= now {
			delete(c.codes, id)
		}
	}
	for id, family := range c.families {
		if family.ExpiresAt <= now {
			delete(c.families, id)
		}
	}
}
