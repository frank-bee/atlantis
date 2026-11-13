// Copyright 2017 HootSuite Media Inc.
// SPDX-License-Identifier: Apache-2.0
// Modified hereafter by contributors to runatlantis/atlantis.

package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"slices"
	"strings"

	"github.com/runatlantis/atlantis/server/logging"
	"github.com/runatlantis/atlantis/server/mcp"
	"github.com/urfave/negroni/v3"
)

// NewRequestLogger creates a RequestLogger.
func NewRequestLogger(s *Server) *RequestLogger {
	l := &RequestLogger{
		logger:            s.Logger,
		WebAuthentication: s.WebAuthentication,
		WebUsername:       s.WebUsername,
		WebPassword:       s.WebPassword,
	}
	if s.MCPOAuth != nil {
		l.oauthDiscoveryPaths = s.MCPOAuth.DiscoveryPaths()
	}
	return l
}

// RequestLogger logs requests and their response codes.
// as well as handle the basicauth on the requests
type RequestLogger struct {
	logger              logging.SimpleLogging
	oauthDiscoveryPaths []string
	WebAuthentication   bool
	WebUsername         string
	WebPassword         string
}

// ServeHTTP implements the middleware function. It logs all requests at DEBUG level.
func (l *RequestLogger) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	requestURI := r.URL.RequestURI()
	if strings.HasPrefix(r.URL.Path, "/auth/github/") || r.URL.Path == mcp.AuthorizePath || r.URL.Path == mcp.TokenPath {
		// OAuth query parameters can carry codes and browser state.
		requestURI = r.URL.Path
	}
	l.logger.Debug("%s %s – from %s", r.Method, requestURI, r.RemoteAddr)
	allowed := false
	if !l.WebAuthentication ||
		r.URL.Path == "/events" ||
		r.URL.Path == "/healthz" ||
		r.URL.Path == "/readyz" ||
		r.URL.Path == "/status" ||
		// The MCP token login authenticates the user against GitHub itself.
		strings.HasPrefix(r.URL.Path, "/auth/github/") ||
		slices.Contains(l.oauthDiscoveryPaths, r.URL.Path) ||
		r.URL.Path == mcp.ResourceMetadataPath ||
		r.URL.Path == mcp.ResourceMetadataPath+mcp.EndpointPath ||
		r.URL.Path == mcp.AuthorizationMetadataPath ||
		r.URL.Path == mcp.RegisterPath ||
		r.URL.Path == mcp.AuthorizePath ||
		r.URL.Path == mcp.TokenPath ||
		strings.HasPrefix(r.URL.Path, "/api/") {
		allowed = true
	} else {
		user, pass, ok := r.BasicAuth()
		if ok {
			r.SetBasicAuth(user, pass)
			if l.credentialsMatch(user, pass) {
				l.logger.Debug("[VALID] log in: >> url: %s", requestURI)
				allowed = true
			} else {
				allowed = false
				l.logger.Info("[INVALID] log in attempt: >> url: %s", requestURI)
			}
		}
	}
	if !allowed {
		rw.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
	} else {
		next(rw, r)
	}
	l.logger.Debug("%s %s – respond HTTP %d", r.Method, requestURI, rw.(negroni.ResponseWriter).Status())
}

// credentialsMatch reports whether the supplied basic-auth credentials equal
// the configured ones. Each value is reduced to a SHA-256 digest before the
// constant-time comparison: ConstantTimeCompare returns early when the lengths
// differ, so comparing the raw values would reveal whether the supplied
// length was right. Both comparisons always run, even when the username is
// wrong, so the time taken to answer reveals neither how much of a value was
// correct nor which of the two was wrong.
func (l *RequestLogger) credentialsMatch(user, pass string) bool {
	userMatch := digestsEqual(user, l.WebUsername)
	passMatch := digestsEqual(pass, l.WebPassword)
	return userMatch && passMatch
}

// digestsEqual compares the SHA-256 digests of got and want in constant time.
func digestsEqual(got, want string) bool {
	gotSum := sha256.Sum256([]byte(got))
	wantSum := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotSum[:], wantSum[:]) == 1
}
