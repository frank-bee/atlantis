// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	. "github.com/runatlantis/atlantis/testing"
)

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func connect(t *testing.T, svc *Service, token string) *sdk.ClientSession {
	t.Helper()
	srv := httptest.NewServer(NewHandler(svc, newTestSigner(t), "test", ""))
	t.Cleanup(srv.Close)
	client := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "0"}, nil)
	session, err := client.Connect(context.Background(), &sdk.StreamableClientTransport{
		Endpoint:             srv.URL,
		HTTPClient:           &http.Client{Transport: bearerTransport{token: token}},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}, nil)
	Ok(t, err)
	t.Cleanup(func() { session.Close() }) // nolint: errcheck
	return session
}

func toolNames(t *testing.T, session *sdk.ClientSession) []string {
	t.Helper()
	res, err := session.ListTools(context.Background(), nil)
	Ok(t, err)
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

func TestHandler_RejectsMissingOrInvalidToken(t *testing.T) {
	svc, _ := newTestService(t)
	srv := httptest.NewServer(NewHandler(svc, newTestSigner(t), "test", ""))
	defer srv.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	for name, auth := range map[string]string{
		"missing": "",
		"invalid": "Bearer nope",
		"basic":   "Basic YTpi",
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(body))
			Ok(t, err)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			resp, err := http.DefaultClient.Do(req)
			Ok(t, err)
			defer resp.Body.Close() // nolint: errcheck
			Equals(t, http.StatusUnauthorized, resp.StatusCode)
		})
	}
}

func TestHandler_HoldsNoStreamOpen(t *testing.T) {
	svc, _ := newTestService(t)
	signer := newTestSigner(t)
	token, _, err := signer.Issue("octocat", 42)
	Ok(t, err)
	srv := httptest.NewServer(NewHandler(svc, signer, "test", ""))
	defer srv.Close()

	// A GET would open a long-lived event stream, which would delay a
	// graceful server shutdown. The stateless handler refuses it.
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	Ok(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	Ok(t, err)
	defer resp.Body.Close() // nolint: errcheck
	Equals(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHandler_ReadOnlyDoesNotOfferCommands(t *testing.T) {
	svc, _ := newTestService(t)
	svc.ReadOnly = true
	token, _, err := newTestSigner(t).Issue("octocat", 42)
	Ok(t, err)
	session := connect(t, svc, token)

	Equals(t, []string{"atlantis_job_output", "atlantis_list_locks", "atlantis_pull_status", "atlantis_whoami"}, toolNames(t, session))

	_, err = session.CallTool(context.Background(), &sdk.CallToolParams{Name: "atlantis_apply", Arguments: map[string]any{}})
	Assert(t, err != nil, "an unregistered tool must not be callable")
}

func TestHandler_RunsCommandAsTokenUser(t *testing.T) {
	svc, f := newTestService(t)
	token, _, err := newTestSigner(t).Issue("octocat", 42)
	Ok(t, err)
	session := connect(t, svc, token)

	Equals(t, []string{"atlantis_apply", "atlantis_job_output", "atlantis_list_locks", "atlantis_plan", "atlantis_pull_status", "atlantis_unlock", "atlantis_whoami"}, toolNames(t, session))

	res, err := session.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "atlantis_plan",
		Arguments: map[string]any{"repo": "owner/repo", "pull": 7, "project": "network"},
	})
	Ok(t, err)
	Assert(t, !res.IsError, "tool failed: %+v", res.Content)
	raw, err := json.Marshal(res.StructuredContent)
	Ok(t, err)
	var out PullStatusOutput
	Ok(t, json.Unmarshal(raw, &out))
	Equals(t, headSHA, out.HeadSHA)

	ran := f.commands()
	Equals(t, 1, len(ran))
	Equals(t, "octocat", ran[0].user.Username)
	Equals(t, "network", ran[0].cmd.ProjectName)

	// A refusal reaches the client as a tool error it can read.
	f.permission = "read"
	res, err = session.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "atlantis_plan",
		Arguments: map[string]any{"repo": "owner/repo", "pull": 8},
	})
	Ok(t, err)
	Assert(t, res.IsError, "expected a tool error")
	Equals(t, 1, len(f.commands()))
}
