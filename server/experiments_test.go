// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/runatlantis/atlantis/server"
	"github.com/runatlantis/atlantis/server/controllers"
	. "github.com/runatlantis/atlantis/testing"
)

func TestValidateExperiments(t *testing.T) {
	const token = "do-not-log-this-token"
	cases := []struct {
		name   string
		config server.UserConfig
		err    string
	}{
		{name: "default"},
		{name: "API permission alone", config: server.UserConfig{Experiments: []string{"api"}}},
		{name: "drift permission alone", config: server.UserConfig{Experiments: []string{"drift-detection"}}},
		{name: "API configured", config: server.UserConfig{Experiments: []string{"api"}, APISecret: token}},
		{name: "drift configured independently", config: server.UserConfig{Experiments: []string{"drift-detection"}, APISecret: token, EnableDriftDetection: true}},
		{name: "both configured", config: server.UserConfig{Experiments: []string{"api", "drift-detection"}, APISecret: token, EnableDriftDetection: true, EnableDriftRemediation: true}},
		{name: "duplicate permissions", config: server.UserConfig{Experiments: []string{"api", "api"}, APISecret: token}},
		{name: "secret without permission", config: server.UserConfig{APISecret: token}, err: "api-secret requires"},
		{name: "drift flag without permission", config: server.UserConfig{EnableDriftDetection: true}, err: `enable-drift-detection requires the "drift-detection" experiment`},
		{name: "API does not permit drift", config: server.UserConfig{Experiments: []string{"api"}, APISecret: token, EnableDriftDetection: true}, err: `enable-drift-detection requires the "drift-detection" experiment`},
		{name: "remediation flag without permission", config: server.UserConfig{EnableDriftRemediation: true}, err: `enable-drift-remediation requires the "drift-detection" experiment`},
		{name: "remediation requires detection", config: server.UserConfig{Experiments: []string{"drift-detection"}, APISecret: token, EnableDriftRemediation: true}, err: "--enable-drift-remediation requires --enable-drift-detection"},
		{name: "drift requires authentication", config: server.UserConfig{Experiments: []string{"drift-detection"}, EnableDriftDetection: true}, err: "enable-drift-detection requires api-secret"},
		{name: "unknown", config: server.UserConfig{Experiments: []string{"unknown"}}, err: `unknown server experiment "unknown"`},
		{name: "MCP permission alone", config: server.UserConfig{Experiments: []string{"mcp"}}},
		{name: "MCP configured", config: mcpConfig(nil)},
		{name: "MCP flag without permission", config: mcpConfig(func(c *server.UserConfig) { c.Experiments = nil }), err: `mcp-enabled requires the "mcp" experiment`},
		{name: "MCP does not accept the API permission", config: mcpConfig(func(c *server.UserConfig) { c.Experiments = []string{"api"} }), err: `mcp-enabled requires the "mcp" experiment`},
		{name: "MCP requires a token secret", config: mcpConfig(func(c *server.UserConfig) { c.MCPTokenSecret = "" }), err: "mcp-enabled requires mcp-token-secret"},
		{name: "MCP rejects a short token secret", config: mcpConfig(func(c *server.UserConfig) { c.MCPTokenSecret = token }), err: "mcp-enabled requires mcp-token-secret"},
		{name: "MCP requires a token lifetime", config: mcpConfig(func(c *server.UserConfig) { c.MCPTokenTTLHours = 0 }), err: "mcp-token-ttl-hours must be at least 1"},
		{name: "MCP requires an OAuth client", config: mcpConfig(func(c *server.UserConfig) { c.MCPGithubOAuthClientSecret = "" }), err: "mcp-enabled requires mcp-gh-oauth-client-id"},
		{name: "MCP requires GitHub", config: mcpConfig(func(c *server.UserConfig) { c.GithubUser = "" }), err: "mcp-enabled currently supports GitHub only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.ValidateExperiments()
			if tc.err == "" {
				Ok(t, err)
				return
			}
			ErrContains(t, tc.err, err)
			ErrContains(t, server.ExperimentsDocumentationURL, err)
			Assert(t, !strings.Contains(err.Error(), token), "error leaked the API secret")
			_, err = server.NewServer(tc.config, server.Config{})
			ErrContains(t, tc.err, err)
		})
	}
}

// mcpConfig returns a valid MCP configuration, modified by change.
func mcpConfig(change func(*server.UserConfig)) server.UserConfig {
	c := server.UserConfig{
		Experiments:                []string{"mcp"},
		MCPEnabled:                 true,
		MCPReadOnly:                true,
		MCPTokenSecret:             "0123456789abcdef0123456789abcdef",
		MCPTokenTTLHours:           1,
		MCPGithubOAuthClientID:     "id",
		MCPGithubOAuthClientSecret: "client-secret",
		GithubUser:                 "user",
	}
	if change != nil {
		change(&c)
	}
	return c
}

func TestNewServer_MCPIsOffByDefaultAndWiredWhenEnabled(t *testing.T) {
	base := server.UserConfig{
		DataDir: t.TempDir(), AtlantisURL: testAtlantisUrl,
		LockingDBType: testLockingDBType, GithubHostname: testGitHubHostName, GithubUser: testGitHubUser,
	}
	mcpRoutes := []struct{ method, path string }{
		{"POST", "/api/mcp"},
		{"GET", "/auth/github/login"},
		{"GET", "/auth/github/callback"},
	}

	// The permission alone activates nothing.
	off := base
	off.Experiments = []string{"mcp"}
	s, err := server.NewServer(off, server.Config{AtlantisVersion: testAtlantisVersion})
	Ok(t, err)
	Assert(t, s.MCPHandler == nil && s.MCPLogin == nil && s.MCPService == nil, "mcp was wired without mcp-enabled")
	s.SetupRoutes()
	for _, route := range mcpRoutes {
		var match mux.RouteMatch
		Assert(t, !s.Router.Match(httptest.NewRequest(route.method, route.path, nil), &match), "%s is routed without mcp-enabled", route.path)
	}

	on := mcpConfig(nil)
	on.DataDir, on.AtlantisURL, on.LockingDBType = t.TempDir(), testAtlantisUrl, testLockingDBType
	on.GithubHostname, on.GithubUser = testGitHubHostName, testGitHubUser
	s, err = server.NewServer(on, server.Config{AtlantisVersion: testAtlantisVersion})
	Ok(t, err)
	Assert(t, s.MCPService != nil && s.MCPService.ReadOnly, "mcp must be wired read-only")
	s.SetupRoutes()
	for _, route := range mcpRoutes {
		var match mux.RouteMatch
		Assert(t, s.Router.Match(httptest.NewRequest(route.method, route.path, nil), &match), "%s is not routed", route.path)
	}
	// Without a token the endpoint answers 401 rather than running anything.
	response := httptest.NewRecorder()
	s.Router.ServeHTTP(response, httptest.NewRequest("POST", "/api/mcp", strings.NewReader("{}")))
	Equals(t, http.StatusUnauthorized, response.Code)
}

func TestExperimentPermissionsDoNotSetActivationFlags(t *testing.T) {
	for _, names := range [][]string{{"api"}, {"drift-detection"}, {"api", "drift-detection"}} {
		cfg := server.UserConfig{Experiments: names}
		Ok(t, cfg.ValidateExperiments())
		Equals(t, "", cfg.APISecret)
		Assert(t, !cfg.EnableDriftDetection && !cfg.EnableDriftRemediation, "permission changed activation flags")
	}
}

func TestNewServer_WiresAPIExperimentPermission(t *testing.T) {
	s, err := server.NewServer(server.UserConfig{
		DataDir: t.TempDir(), AtlantisURL: testAtlantisUrl,
		LockingDBType: testLockingDBType, GithubHostname: testGitHubHostName, GithubUser: testGitHubUser,
		APISecret: "token", Experiments: []string{"api"},
	}, server.Config{AtlantisVersion: testAtlantisVersion})
	Ok(t, err)
	Equals(t, []string{"api"}, s.Experiments)
	s.SetupRoutes()
	var match mux.RouteMatch
	Assert(t, s.Router.Match(httptest.NewRequest("POST", "/api/plan", nil), &match), "API permission was not wired to routing")
	Assert(t, !s.Router.Match(httptest.NewRequest("POST", "/api/drift/detect", nil), &match), "API permission exposed drift")
	Assert(t, s.APIController.DriftStorage == nil, "API permission initialized drift storage")
}

func TestSetupRoutes_ExperimentGates(t *testing.T) {
	routes := []struct{ method, path, experiment string }{
		{"POST", "/api/plan", "api"},
		{"POST", "/api/apply", "api"},
		{"GET", "/api/locks", "api"},
		{"GET", "/api/drift/status", "drift-detection"},
		{"POST", "/api/drift/detect", "drift-detection"},
		{"POST", "/api/drift/remediate", "drift-detection"},
		{"GET", "/api/drift/remediate", "drift-detection"},
		{"GET", "/api/drift/remediate/id", "drift-detection"},
	}
	for _, names := range [][]string{nil, {"api"}, {"drift-detection"}, {"api", "drift-detection"}} {
		t.Run(strings.Join(names, ","), func(t *testing.T) {
			s := &server.Server{Router: mux.NewRouter(), Experiments: names, APIController: &controllers.APIController{}}
			s.SetupRoutes()
			for _, route := range routes {
				permitted := false
				for _, name := range names {
					permitted = permitted || name == route.experiment
				}
				request := httptest.NewRequest(route.method, route.path, nil)
				var match mux.RouteMatch
				Equals(t, permitted, s.Router.Match(request, &match))
				if !permitted {
					response := httptest.NewRecorder()
					s.Router.ServeHTTP(response, request)
					Equals(t, http.StatusNotFound, response.Code)
				}
			}
			for _, path := range []string{"/healthz", "/readyz", "/status"} {
				var match mux.RouteMatch
				Assert(t, s.Router.Match(httptest.NewRequest("GET", path, nil), &match), "health route %s was gated", path)
			}
		})
	}
}
