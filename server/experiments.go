// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"slices"
	"strings"

	"github.com/runatlantis/atlantis/server/mcp"
)

// ExperimentsDocumentationURL includes experiments not yet in a stable release.
const ExperimentsDocumentationURL = "https://www.runatlantis.io/versions/main/docs/experiments.html"

const (
	apiExperiment   = "api"
	driftExperiment = "drift-detection"
	mcpExperiment   = "mcp"
)

var knownExperiments = []string{apiExperiment, driftExperiment, mcpExperiment}

// ValidateExperiments checks permissions and prerequisites before startup.
func (c UserConfig) ValidateExperiments() error {
	for _, name := range c.Experiments {
		if !slices.Contains(knownExperiments, name) {
			return fmt.Errorf("unknown server experiment %q in experiments configuration; supported names are %s; see %s", name, strings.Join(knownExperiments, ", "), ExperimentsDocumentationURL)
		}
	}
	api := slices.Contains(c.Experiments, apiExperiment)
	drift := slices.Contains(c.Experiments, driftExperiment)
	for _, setting := range []struct {
		name    string
		enabled bool
	}{
		{"enable-drift-detection", c.EnableDriftDetection},
		{"enable-drift-remediation", c.EnableDriftRemediation},
	} {
		if setting.enabled && !drift {
			return fmt.Errorf("%s requires the %q experiment; add it to experiments or disable %s; see %s", setting.name, driftExperiment, setting.name, ExperimentsDocumentationURL)
		}
	}
	// Both route groups use the secret; either experiment may authorize it.
	if c.APISecret != "" && !api && !drift {
		return fmt.Errorf("api-secret requires the %q experiment for command/lock endpoints or %q for drift endpoints; add the matching name to experiments or remove api-secret; see %s", apiExperiment, driftExperiment, ExperimentsDocumentationURL)
	}
	if err := c.validateMCP(); err != nil {
		return err
	}
	if c.EnableDriftRemediation && !c.EnableDriftDetection {
		return fmt.Errorf("--enable-drift-remediation requires --enable-drift-detection; see %s", ExperimentsDocumentationURL)
	}
	if c.EnableDriftDetection && c.APISecret == "" {
		return fmt.Errorf("enable-drift-detection requires api-secret for authentication; configure api-secret or disable enable-drift-detection; see %s", ExperimentsDocumentationURL)
	}
	return nil
}

// validateMCP checks the prerequisites of the experimental MCP server.
func (c UserConfig) validateMCP() error {
	if !c.MCPEnabled {
		return nil
	}
	if !slices.Contains(c.Experiments, mcpExperiment) {
		return fmt.Errorf("mcp-enabled requires the %q experiment; add it to experiments or disable mcp-enabled; see %s", mcpExperiment, ExperimentsDocumentationURL)
	}
	if len(c.MCPTokenSecret) < mcp.MinTokenSecretLength {
		return fmt.Errorf("mcp-enabled requires mcp-token-secret with at least %d characters; configure it or disable mcp-enabled; see %s", mcp.MinTokenSecretLength, ExperimentsDocumentationURL)
	}
	if c.MCPTokenTTLHours < 1 {
		return fmt.Errorf("mcp-token-ttl-hours must be at least 1; see %s", ExperimentsDocumentationURL)
	}
	if c.MCPGithubOAuthClientID == "" || c.MCPGithubOAuthClientSecret == "" {
		return fmt.Errorf("mcp-enabled requires mcp-gh-oauth-client-id and mcp-gh-oauth-client-secret, which users log in with to get a token; configure them or disable mcp-enabled; see %s", ExperimentsDocumentationURL)
	}
	if c.GithubUser == "" && c.GithubAppID == 0 {
		return fmt.Errorf("mcp-enabled currently supports GitHub only and requires gh-user or gh-app-id; see %s", ExperimentsDocumentationURL)
	}
	return nil
}
