// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	mcpserver "github.com/jedisct1/openapi-mcp/pkg/mcp/server"
)

func getMCPBaseURL(mcpBaseUrl string, port int) string {
	if mcpBaseUrl != "" {
		return mcpBaseUrl
	}
	return fmt.Sprintf("http://localhost:%d", port)
}

// CustomStreamableHTTPServer embeds the 3rd-party StreamableHTTPServer
type CustomStreamableHTTPServer struct {
	*mcpserver.StreamableHTTPServer
	endpointPath                string
	httpServer                  *http.Server
	issuer                      string
	mcpBaseUrl                  string
	oauthAuthorizationServerURL string
	oauthEnabled                bool
	port                        int
}

type fnAuth = func(ctx context.Context, r *http.Request) context.Context

type CustomStreamableHTTPOption func(*CustomStreamableHTTPServer)

// NewCustomStreamableHTTPServer creates a new instance of your custom server
func NewCustomStreamableHTTPServer(server *mcpserver.MCPServer, endpointPath string, fn fnAuth, serveOpts *ServeOptions) *CustomStreamableHTTPServer {
	opts := []mcpserver.StreamableHTTPOption{
		mcpserver.WithEndpointPath(endpointPath),
		mcpserver.WithHTTPContextFunc(fn),
	}

	return &CustomStreamableHTTPServer{
		StreamableHTTPServer:        mcpserver.NewStreamableHTTPServer(server, opts...),
		endpointPath:                endpointPath,
		issuer:                      serveOpts.OauthIssuer,
		mcpBaseUrl:                  serveOpts.McpBaseUrl,
		oauthAuthorizationServerURL: serveOpts.OauthAuthorizationServerURL,
		oauthEnabled:                serveOpts.OauthEnabled,
		port:                        serveOpts.Port,
	}
}

// Override ServeHTTP to add your custom logic
func (s *CustomStreamableHTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.oauthEnabled {
		if r.Method != http.MethodOptions {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="MCP", resource_metadata="%s/.well-known/resource-metadata"`, getMCPBaseURL(s.mcpBaseUrl, s.port)))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
	}

	// Call the original method
	s.StreamableHTTPServer.ServeHTTP(w, r)

	// Custom logic after
}

// Override ServeHTTP to add your custom logic
func (s *CustomStreamableHTTPServer) Start(addr string) error {
	mux := http.NewServeMux()
	mux.Handle(s.endpointPath, s) // Serve MCP endpoint

	// Custom endpoints
	if s.oauthEnabled {
		mux.HandleFunc("/.well-known/openid-configuration", s.serveOAuthASDiscoveryProxy)
		mux.HandleFunc("/.well-known/oauth-authorization-server", s.serveOAuthASDiscoveryProxy)

		mux.HandleFunc("/.well-known/oauth-protected-resource", s.serveOAuthProtectedResourceMetadata)
		mux.HandleFunc("/.well-known/resource-metadata", s.serveOAuthProtectedResourceMetadata)
	}

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return s.httpServer.ListenAndServe()
}

// Proxy for Auth0's non-existent .well-known/oauth-authorization-server
func (s *CustomStreamableHTTPServer) serveOAuthASDiscoveryProxy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	resp, err := http.Get(s.oauthAuthorizationServerURL)
	if err != nil {
		http.Error(w, "Failed to fetch OAuth AS configuration", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// Actual config required for the MCP
func (s *CustomStreamableHTTPServer) serveOAuthProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	metadata := map[string]interface{}{
		"resource":                        fmt.Sprintf("%s/mcp", getMCPBaseURL(s.mcpBaseUrl, s.port)),
		"resource_auth_methods_supported": []string{"bearer"},
		"resource_scopes_supported":       []string{"openid", "profile", "email"},
		"issuer":                          s.issuer,
		"authorization_servers":           []string{fmt.Sprintf("%s", getMCPBaseURL(s.mcpBaseUrl, s.port))},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(metadata)
}
