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
	"net/url"
	"strings"
	"time"

	"github.com/alexliesenfeld/health"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trento-project/mcp-server/internal/utils"
)

const (
	// wandaProxyName is the name used when serving Wanda behind a proxy.
	// For now, this is the default recommended name, but users might want to change it;
	// if needed, we can always extract it into a config flag.
	wandaProxyName = "wanda"

	// checkNameTpl is the template name for the checks.
	checkNameTpl = "%s-api"
	// wandaCheckName is the name for the wanda check.
	wandaCheckName = "wanda"
	// wandaCheckName is the name for the web check.
	webCheckName = "web"
)

// createLivenessChecker creates and returns a liveness health check handler.
func createLivenessChecker(ctx context.Context, serveOpts *ServeOptions) http.Handler {
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

	slog.InfoContext(ctx, "creating liveness health check")

	return health.NewHandler(livenessChecker)
}

// createReadinessChecker creates and returns a readiness health check handler.
func createReadinessChecker(ctx context.Context, serveOpts *ServeOptions) http.Handler {
	// Create HTTP client with appropriate settings
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: serveOpts.InsecureSkipTLSVerify, //nolint:gosec
			},
		},
		Timeout: 5 * time.Second,
	}

	// Start with the MCP server check
	checks := []health.Check{
		{
			Name: "mcp-server",
			Check: func(ctx context.Context) error {
				// Check connectivity to the MCP server using an MCP client.
				return checkMCPServer(ctx, serveOpts)
			},
		},
	}

	slog.InfoContext(ctx, "creating health check for MCP server")

	// Add individual health checks for each OAS path
	checks = append(checks, createOASPathHealthChecks(ctx, serveOpts, httpClient)...)

	// Build the checker options
	options := []health.CheckerOption{}
	for _, check := range checks {
		options = append(options, health.WithCheck(check))
	}

	readinessChecker := health.NewChecker(options...)

	return health.NewHandler(readinessChecker)
}

// createOASPathHealthChecks creates individual health checks for each OAS path.
func createOASPathHealthChecks(ctx context.Context, serveOpts *ServeOptions, httpClient *http.Client) []health.Check {
	var checks []health.Check

	// If we have explicit OAS paths, create a health check for each one
	// assuming "<base path> + /api/healthz"
	if len(serveOpts.OASPath) > 0 {
		for _, oasPath := range serveOpts.OASPath {
			check, err := createSingleOASHealthCheck(ctx, oasPath, serveOpts, httpClient)
			if err != nil {
				continue
			}

			checks = append(checks, check)
		}
		// If no explicit OAS paths but we have a TrentoURL, create checks for autodiscovery paths
		// also assuming "<base path> + /api/healthz"
	} else if serveOpts.TrentoURL != "" {
		for _, autoPath := range serveOpts.AutodiscoveryPaths {
			fullOASPath := strings.TrimRight(serveOpts.TrentoURL, "/") + autoPath

			check, err := createSingleOASHealthCheck(ctx, fullOASPath, serveOpts, httpClient)
			if err != nil {
				continue
			}

			checks = append(checks, check)
		}
	}

	return checks
}

// createSingleOASHealthCheck creates a single health check for an OAS path.
func createSingleOASHealthCheck(
	ctx context.Context,
	oasPath string,
	serveOpts *ServeOptions,
	httpClient *http.Client,
) (health.Check, error) {
	// Parse the OAS path once to extract information for the health check
	parsedOASPath, err := url.Parse(oasPath)
	if err != nil {
		return health.Check{}, fmt.Errorf("failed to parse OAS path %s: %w", oasPath, err)
	}

	// Validate that the URL has a host (required for health checks)
	if parsedOASPath.Host == "" {
		return health.Check{}, fmt.Errorf("failed to extract host from OAS path %s", oasPath)
	}

	// Determine check name based on the oasPath:
	// if it contains "wandaProxyName" somewhere, assume it is the "wandaCheckName" check,
	// otherwise, default to webCheckName
	checkName := fmt.Sprintf(checkNameTpl, webCheckName)
	if strings.Contains(oasPath, wandaProxyName) {
		checkName = fmt.Sprintf(checkNameTpl, wandaCheckName)
	}

	// Build the health check URL:
	// if it contains "/wandaProxyName/" in the path (like foo.example.com/wanda),
	// then pre-append the "/wandaProxyName/" to the health check URL,
	// (for example foo.example.com/wanda/api/healthz)
	healthPath := serveOpts.HealthAPIPath
	if strings.Contains(parsedOASPath.Path, fmt.Sprintf("/%s/", wandaProxyName)) {
		healthPath = fmt.Sprintf("/%s%s", wandaProxyName, serveOpts.HealthAPIPath)
	}

	// Use the OAS path scheme and host and build the health check URL
	baseURL := fmt.Sprintf("%s://%s", parsedOASPath.Scheme, parsedOASPath.Host)
	healthURL := strings.TrimRight(baseURL, "/") + healthPath

	slog.InfoContext(ctx, "creating health check for OAS path",
		"checkName", checkName,
		"healthURL", healthURL,
		"oasPath", oasPath,
	)

	return health.Check{
		Name: checkName,
		Check: func(ctx context.Context) error {
			return checkAPIServiceHealth(ctx, healthURL, oasPath, serveOpts, httpClient)
		},
	}, nil
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
			Endpoint: (&url.URL{
				Scheme: "http",
				Host:   fmt.Sprintf("localhost:%d", serveOpts.Port),
				Path:   "/sse",
			}).String(),
			HTTPClient: &http.Client{
				Timeout: 3 * time.Second,
			},
		}
	case utils.TransportStreamable:
		mcpTransport = &mcp.StreamableClientTransport{
			Endpoint: (&url.URL{
				Scheme: "http",
				Host:   fmt.Sprintf("localhost:%d", serveOpts.Port),
				Path:   "/mcp",
			}).String(),
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

// checkAPIServiceHealth checks if an API server is reachable using the provided health URL.
func checkAPIServiceHealth(
	ctx context.Context,
	healthURL string,
	oasPath string,
	serveOpts *ServeOptions,
	httpClient *http.Client,
) error {
	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request for %s: %w", healthURL, err)
	}

	// Set User-Agent header
	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s", serveOpts.Name, serveOpts.Version))

	// Make the request
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to %s (derived from OAS path %s): %w", healthURL, oasPath, err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			slog.DebugContext(ctx, "failed to close response body",
				"error", err,
				"path", healthURL,
			)
		}
	}()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API server at %s (derived from OAS path %s) returned a non-200 status code (%d)",
			healthURL, oasPath, resp.StatusCode,
		)
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
	livenessHandler := createLivenessChecker(ctx, serveOpts)
	readinessHandler := createReadinessChecker(ctx, serveOpts)

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
