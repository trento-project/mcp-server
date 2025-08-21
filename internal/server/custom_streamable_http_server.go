// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	mcpserver "github.com/mark3labs/mcp-go/server"
)

func getMCPBaseURL(mcpBaseURL string, port int) string {
	if mcpBaseURL != "" {
		return mcpBaseURL
	}

	return fmt.Sprintf("http://localhost:%d", port)
}

// CustomStreamableHTTPServer embeds the 3rd-party StreamableHTTPServer.
type CustomStreamableHTTPServer struct {
	*mcpserver.StreamableHTTPServer

	endpointPath                string
	httpServer                  *http.Server
	issuer                      string
	mcpBaseURL                  string
	oauthAuthorizationServerURL string
	oauthEnabled                bool
	port                        int
}

type fnAuth = func(ctx context.Context, r *http.Request) context.Context

// CustomStreamableHTTPOption is a option of the CustomStreamableHTTPServer type.
type CustomStreamableHTTPOption func(*CustomStreamableHTTPServer)

// NewCustomStreamableHTTPServer creates a new instance of your custom server.
func NewCustomStreamableHTTPServer(
	server *mcpserver.MCPServer,
	endpointPath string,
	fn fnAuth,
	serveOpts *ServeOptions,
) *CustomStreamableHTTPServer {
	opts := []mcpserver.StreamableHTTPOption{
		mcpserver.WithEndpointPath(endpointPath),
		mcpserver.WithHTTPContextFunc(fn),
	}

	return &CustomStreamableHTTPServer{
		StreamableHTTPServer:        mcpserver.NewStreamableHTTPServer(server, opts...),
		endpointPath:                endpointPath,
		issuer:                      serveOpts.OauthIssuer,
		mcpBaseURL:                  serveOpts.McpBaseURL,
		oauthAuthorizationServerURL: serveOpts.OauthAuthorizationServerURL,
		oauthEnabled:                serveOpts.OauthEnabled,
		port:                        serveOpts.Port,
	}
}

// Override ServeHTTP to add your custom logic.
func (s *CustomStreamableHTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.oauthEnabled {
		if r.Method != http.MethodOptions {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				w.Header().
					Set("WWW-Authenticate",
						fmt.Sprintf(`Bearer realm="MCP", resource_metadata="%s/.well-known/resource-metadata"`,
							getMCPBaseURL(s.mcpBaseURL, s.port)),
					)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)

				return
			}
		}
	}

	// Call the original method
	s.StreamableHTTPServer.ServeHTTP(w, r)
}

// Start begins the execution of the HTTP server.
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
		Addr:        addr,
		Handler:     mux,
		ReadTimeout: 10 * time.Second,
	}

	return s.httpServer.ListenAndServe()
}

// Proxy for Auth0's non-existent .well-known/oauth-authorization-server.
func (s *CustomStreamableHTTPServer) serveOAuthASDiscoveryProxy(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.oauthAuthorizationServerURL, nil)
	if err != nil {
		http.Error(w, "failed to build the request to fetch OAuth AS configuration", http.StatusInternalServerError)

		return
	}

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to fetch OAuth AS configuration", http.StatusBadGateway)

		return
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			slog.Error("failed to close response body",
				"error", err,
			)
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, "Failed to proxy OAuth AS configuration", http.StatusBadGateway)
	}
}

// Actual config required for the MCP.
func (s *CustomStreamableHTTPServer) serveOAuthProtectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	metadata := map[string]any{
		"resource":                        fmt.Sprintf("%s/mcp", getMCPBaseURL(s.mcpBaseURL, s.port)),
		"resource_auth_methods_supported": []string{"bearer"},
		"resource_scopes_supported":       []string{"openid", "profile", "email"},
		"issuer":                          s.issuer,
		"authorization_servers":           []string{getMCPBaseURL(s.mcpBaseURL, s.port)},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(metadata)
	if err != nil {
		http.Error(w, "Failed to encode OAuth protected resource metadata", http.StatusInternalServerError)
	}
}

// Shutdown gracefully stops the server.
func (s *CustomStreamableHTTPServer) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}

	return nil
}
