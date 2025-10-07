// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/alexliesenfeld/health"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trento-project/mcp-server/internal/utils"
)

// createLivenessChecker creates and returns a liveness health check handler.
func createLivenessChecker(serveOpts *ServeOptions) http.Handler {
	if serveOpts == nil {
		serveOpts = &ServeOptions{}
	}

	// This check just performs a minimal check to prevent undesired restarts.
	livenessChecker := health.NewChecker(
		health.WithInfo(map[string]any{
			"name":    serveOpts.Name,
			"version": serveOpts.Version,
		}),
	)

	return health.NewHandler(livenessChecker)
}

// createReadinessChecker creates and returns a readiness health check handler.
func createReadinessChecker(serveOpts *ServeOptions) http.Handler {
	readinessChecker := health.NewChecker(
		health.WithCheck(health.Check{
			Name: "mcp-server",
			Check: func(ctx context.Context) error {
				// Check connectivity to the MCP server using an MCP client.
				return checkMCPServer(ctx, serveOpts)
			},
		}),
		health.WithCheck(health.Check{
			Name: "api-server",
			Check: func(ctx context.Context) error {
				// Check HTTP connectivity to the API server.
				return checkAPIServerConnectivity(ctx, serveOpts)
			},
		}),
		health.WithCheck(health.Check{
			Name: "api-documentation",
			Check: func(ctx context.Context) error {
				// Check HTTP connectivity to API documentation files.
				return checkOASDocsConnectivity(ctx, serveOpts)
			},
		}),
	)

	return health.NewHandler(readinessChecker)
}

// checkMCPServer checks if the MCP server can connect using an MCP client.
func checkMCPServer(ctx context.Context, serveOpts *ServeOptions) error {
	// Create a proper MCP client to test the server
	clientImpl := &mcp.Implementation{
		Name:    "health-check-client",
		Version: serveOpts.Version,
	}

	client := mcp.NewClient(clientImpl, nil)

	// Create the appropriate transport for the MCP client
	var mcpTransport mcp.Transport

	switch serveOpts.Transport {
	case utils.TransportSSE:
		mcpTransport = &mcp.SSEClientTransport{
			Endpoint: fmt.Sprintf("http://localhost:%d/sse", serveOpts.Port),
			HTTPClient: &http.Client{
				Timeout: 3 * time.Second,
			},
		}
	case utils.TransportStreamable:
		mcpTransport = &mcp.StreamableClientTransport{
			Endpoint: fmt.Sprintf("http://localhost:%d/mcp", serveOpts.Port),
			HTTPClient: &http.Client{
				Timeout: 3 * time.Second,
			},
		}
	default:
		return fmt.Errorf("unknown transport type: %s", serveOpts.Transport)
	}

	// Create a context with timeout for the health check
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Attempt to connect to the MCP server
	session, err := client.Connect(checkCtx, mcpTransport, nil)
	if err != nil {
		return fmt.Errorf("MCP client failed to connect: %w", err)
	}

	defer func() {
		// Close the MCP session
		_ = session.Close()
	}()

	// Perform a ping to verify the server is responding properly
	err = session.Ping(checkCtx, nil)
	if err != nil {
		return fmt.Errorf("MCP server ping failed: %w", err)
	}

	return nil
}

// checkAPIServerConnectivity verifies that all configured API server is reachable.
func checkAPIServerConnectivity(ctx context.Context, serveOpts *ServeOptions) error {
	// Check the main Trento URL
	err := checkSingleAPIServer(ctx, serveOpts.TrentoURL, "trento-api", serveOpts)
	if err != nil {
		return err
	}

	return nil
}

// checkOASDocsConnectivity verifies that the API docs are reachable.
func checkOASDocsConnectivity(ctx context.Context, serveOpts *ServeOptions) error {
	var allErrors []error

	// Check all the OpenAPI specs
	for _, oasPath := range serveOpts.OASPath {
		// Only check remote URLs, not local files
		if strings.HasPrefix(oasPath, "http://") || strings.HasPrefix(oasPath, "https://") {
			err := checkSingleAPIServer(ctx, oasPath, fmt.Sprintf("oas-server-%s", oasPath), serveOpts)
			if err != nil {
				allErrors = append(allErrors, err)
			}
		}
	}

	// If we have any errors, join them and return
	if len(allErrors) > 0 {
		return errors.Join(allErrors...)
	}

	return nil
}

// checkSingleAPIServer checks if a single API server is reachable.
func checkSingleAPIServer(
	ctx context.Context,
	serverURL,
	serverName string,
	serveOpts *ServeOptions,
) error {
	if serverURL == "" {
		return fmt.Errorf("%s: server URL is empty", serverName)
	}

	// Create HTTP client with appropriate settings
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: serveOpts.InsecureSkipTLSVerify, //nolint:gosec
			},
		},
		Timeout: 5 * time.Second,
	}

	// Create a health check request with timeout
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, serverURL, nil)
	if err != nil {
		return fmt.Errorf("%s: failed to create request to %s: %w", serverName, serverURL, err)
	}

	// Set the UA to track the version.
	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s", serveOpts.Name, serveOpts.Version))

	// Perform the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: server %s is unreachable: %w", serverName, serverURL, err)
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			slog.WarnContext(ctx, "failed to close response body",
				"error", err,
				"server.name", serverName,
				"server.url", serverURL,
			)
		}
	}()

	// Accept 1xx, 2xx and 3xx status code.
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s: server %s returned server error: %d %s", serverName, serverURL, resp.StatusCode, resp.Status)
	}

	return nil
}

// startHealthServer starts the health check server on the specified port.
func startHealthServer(
	ctx context.Context,
	serveOpts *ServeOptions,
	errChan chan<- error,
) *http.Server {
	// Create separate handlers for liveness and readiness following Kubernetes best practices
	livenessHandler := createLivenessChecker(serveOpts)
	readinessHandler := createReadinessChecker(serveOpts)

	livenessEndpoint := "/livez"
	readinessEndpoint := "/readyz"

	// Create a mux and register the health endpoints
	mux := http.NewServeMux()
	mux.Handle(readinessEndpoint, readinessHandler)
	mux.Handle(livenessEndpoint, livenessHandler)

	// Use the configured health port
	healthAddr := fmt.Sprintf(":%d", serveOpts.HealthPort)

	healthServer := &http.Server{
		Addr:              healthAddr,
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       15 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

	go func() {
		slog.InfoContext(ctx, "the health check server is listening",
			"server.address", healthAddr,
			"endpoint.liveness", livenessEndpoint,
			"endpoint.readiness", readinessEndpoint,
		)

		err := healthServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.ErrorContext(ctx, "health server failed",
				"error", err,
			)

			errChan <- fmt.Errorf("health server error: %w", err)
		}
	}()

	return healthServer
}
