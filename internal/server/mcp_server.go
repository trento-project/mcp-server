// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	openapi2mcp "github.com/evcc-io/openapi-mcp"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trento-project/mcp-server/internal/utils"
)

// AuthContextWrapperFn is a wrapper for the authentication functions that are passed to the MCP server.
type AuthContextWrapperFn = func(ctx context.Context, req *http.Request) context.Context

const (
	// bearerTokenEnv is the env var name that the MCP client is expecting to read.
	// This comes from the tool conversion performed at:
	// https://github.com/evcc-io/openapi-mcp/blob/5af774c51f554649795872fe26c415f804456951/pkg/openapi2mcp/register.go#L77
	bearerTokenEnv = "BEARER_TOKEN"
)

// createMCPServer creates the MCP server, but does not start serving it yet.
func createMCPServer(ctx context.Context, serveOpts *ServeOptions) *mcp.Server {
	// Create MCP server options.
	opts := &mcp.ServerOptions{
		KeepAlive: 30 * time.Second,
		PageSize:  mcp.DefaultPageSize,
	}

	slog.DebugContext(ctx, "the MCP server options have been created",
		"server.options", fmt.Sprintf("%+v", opts),
	)

	impl := &mcp.Implementation{
		Name:    serveOpts.Name,
		Title:   serveOpts.Name,
		Version: serveOpts.Version,
	}

	srv := mcp.NewServer(impl, opts)

	// Add a logging middleware
	srv.AddReceivingMiddleware(withLogger(slog.Default()))

	return srv
}

// handleToolsRegistration loads the OAS file, transforms it into MCP tools and registers them into the MCP server.
func handleToolsRegistration(
	ctx context.Context,
	srv *mcp.Server,
	serveOpts *ServeOptions, //nolint:revive
) (*mcp.Server, []string, error) {
	var allTools []string

	if len(serveOpts.OASPath) == 0 {
		return nil, nil, errors.New("no OpenAPI spec path provided")
	}

	for _, path := range serveOpts.OASPath {
		// Load OpenAPI spec.
		oasDoc, err := loadOpenAPISpec(ctx, path, serveOpts)
		if err != nil {
			slog.ErrorContext(ctx, "failed to read an API spec",
				"path", path,
				"error", err,
			)

			return nil, nil, fmt.Errorf("failed to read API spec from %s: %w", path, err)
		}

		// Overwrite the Trento URL in the OpenAPI
		if len(oasDoc.Servers) > 0 {
			oasDoc.Servers[0].URL = serveOpts.TrentoURL
		} else {
			// Or just add it
			oasDoc.Servers = append(oasDoc.Servers, &openapi3.Server{
				URL: serveOpts.TrentoURL,
			})
		}

		tools := registerToolsFromSpec(srv, oasDoc, serveOpts)
		allTools = append(allTools, tools...)
	}

	return srv, allTools, nil
}

func registerToolsFromSpec(srv *mcp.Server, oasDoc *openapi3.T, serveOpts *ServeOptions) []string {
	// Extract the API operations.
	operations := openapi2mcp.ExtractOpenAPIOperations(oasDoc)

	// TODO(agamez): Pre-filter operations by tag intersection to avoid relying on external library filtering.
	//nolint:lll
	// see https://github.com/jedisct1/openapi-mcp/blob/7fc6e6013a413754e52fbac2197f8027c68040f9/pkg/openapi2mcp/register.go#L901
	if len(serveOpts.TagFilter) > 0 {
		filteredOperations := []openapi2mcp.OpenAPIOperation{}

		for _, op := range operations {
			matched := false

			for _, x := range serveOpts.TagFilter {
				if slices.Contains(op.Tags, x) {
					matched = true

					break
				}
			}

			if matched {
				filteredOperations = append(filteredOperations, op)
			}
		}

		operations = filteredOperations
	}

	opts := &openapi2mcp.ToolGenOptions{
		TagFilter:               nil, // TODO(agamez): revert back to "serveOpts.TagFilter," once we can.
		ConfirmDangerousActions: true,
		NameFormat: func(oldOperationID string) string {
			// Convert dots to underscores first
			operationID := strings.ReplaceAll(oldOperationID, ".", "_")
			// Remove any "WandaWeb_VX_" or "TrentoWeb_VX_" prefix (VX can be V1, V2, etc.)
			re := regexp.MustCompile(`^(WandaWeb|TrentoWeb)_V\d+_`)
			operationID = re.ReplaceAllString(operationID, "")
			// Remove all 'Controller' substrings
			operationID = strings.ReplaceAll(operationID, "Controller", "")

			return operationID
		},
	}

	// Register them as MCP tools.
	tools := openapi2mcp.RegisterOpenAPITools(srv, operations, oasDoc, opts)

	return tools
}

// loadOpenAPISpec loads the OpenAPI specification from either a URL or local file.
func loadOpenAPISpec(ctx context.Context, path string, serveOpts *ServeOptions) (*openapi3.T, error) {
	var (
		oasDoc *openapi3.T
		err    error
	)

	// Check if it is a remote path.
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		oasDoc, err = loadOpenAPISpecFromURL(ctx, path, serveOpts)
	} else {
		// If not, load the spec from disk.
		oasDoc, err = openapi2mcp.LoadOpenAPISpec(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read the API spec from %s: %w", path, err)
		}
	}

	return oasDoc, err
}

// loadOpenAPISpecFromURL fetches the OpenAPI specification from a remote URL.
func loadOpenAPISpecFromURL(ctx context.Context, path string, serveOpts *ServeOptions) (*openapi3.T, error) {
	// Create a client based on the TLS preferences and proxy settings from env.
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: serveOpts.InsecureSkipTLSVerify, //nolint:gosec // Allow insecure TLS when explicitly requested
			},
		},
		Timeout: 30 * time.Second,
	}

	// Generate the GET request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set the UA to track the version.
	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s", serveOpts.Name, serveOpts.Version))

	// Perform the request.
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OpenAPI spec from URL: %w", err)
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			slog.DebugContext(ctx, "failed to close response body",
				"error", closeErr,
			)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch OpenAPI spec, status code: %d", resp.StatusCode)
	}

	// Store the OAS docs.
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Create the loader.
	loader := &openapi3.Loader{IsExternalRefsAllowed: true}

	// Load the OAS spec.
	oasDoc, err := loader.LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OpenAPI spec from data: %w", err)
	}

	return oasDoc, nil
}

// handleMCPServerRun configures and starts the MCP server based on the selected transport.
// It returns the server instance for management by the caller.
func handleMCPServerRun(
	ctx context.Context,
	srv *mcp.Server,
	serveOpts *ServeOptions,
	serverErrChan chan<- error,
) (utils.StoppableServer, error) {
	// Build the address to listen to
	listenAddr := fmt.Sprintf(":%d", serveOpts.Port)

	slog.DebugContext(ctx, "about to start the MCP server",
		"server.address", listenAddr,
		"server.transport", serveOpts.Transport,
	)

	var (
		mcpServer utils.StoppableServer
		err       error
	)

	// Depending on the chosen transport, we handle the MCP server startup.
	switch serveOpts.Transport {
	case utils.TransportSSE:
		mcpServer, err = startSSEServer(ctx, srv, listenAddr, serveOpts.HeaderName, serverErrChan)

	case utils.TransportStreamable:
		mcpServer, err = startStreamableHTTPServer(ctx, srv, listenAddr, serveOpts.HeaderName, serverErrChan)

	default:
		return nil, fmt.Errorf("invalid transport type: %s", serveOpts.Transport)
	}

	if err != nil {
		return nil, err
	}

	return mcpServer, nil
}

// startServer starts a given MCP in a goroutine.
func startServer(
	ctx context.Context,
	listenAddr string,
	handler http.Handler,
	transportType utils.TransportType,
	errChan chan<- error,
) *http.Server {
	httpSrv := &http.Server{
		Addr:    listenAddr,
		Handler: handler,
		// The WriteTimeout needs to be longer than the MCP KeepAlive interval (30s)
		// to prevent the server from prematurely closing long-lived SSE/Streamable connections.
		// ReadTimeout and IdleTimeout are also increased to be more lenient.
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

	go func() {
		slog.InfoContext(ctx, "the MCP server is listening",
			"server.address", listenAddr,
			"server.transport", transportType,
		)

		err := httpSrv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.ErrorContext(ctx, fmt.Sprintf("failed to serve MCP server via %s", transportType),
				"error", err,
			)

			errChan <- err
		}
	}()

	return httpSrv
}

// startStreamableHTTPServer initializes and starts a custom streamable HTTP server.
func startStreamableHTTPServer(
	ctx context.Context,
	mcpSrv *mcp.Server,
	listenAddr string,
	headerName string,
	errChan chan<- error,
) (utils.StoppableServer, error) {
	streamableHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server {
			handleAPIKeyAuth(r, headerName)

			return mcpSrv
		},
		&mcp.StreamableHTTPOptions{},
	)

	httpServer := startServer(ctx, listenAddr, streamableHandler, utils.TransportStreamable, errChan)

	return httpServer, nil
}

// startSSEServer initializes and starts a Server-Sent Events (SSE) server.
func startSSEServer(
	ctx context.Context,
	mcpSrv *mcp.Server,
	listenAddr string,
	headerName string,
	errChan chan<- error,
) (utils.StoppableServer, error) {
	sseHandler := mcp.NewSSEHandler(
		func(r *http.Request) *mcp.Server {
			handleAPIKeyAuth(r, headerName)

			return mcpSrv
		},
		&mcp.SSEOptions{},
	)

	httpServer := startServer(ctx, listenAddr, sseHandler, utils.TransportSSE, errChan)

	return httpServer, nil
}

// handleAPIKeyAuth extracts the API key from the request header and sets it as the bearer token environment variable.
// TODO(agamez): double-check in the future, we might have something built-in
// see https://github.com/modelcontextprotocol/go-sdk/blob/87f222477b31e542d33283f71358f829eb6a996b/auth/auth.go#L38
func handleAPIKeyAuth(r *http.Request, headerName string) {
	apiKey := r.Header.Get(headerName)

	if apiKey == "" {
		slog.DebugContext(r.Context(), "API key not found in request header", "header", headerName)
		// Unset the bearer token if no API key is provided.
		err := os.Unsetenv(bearerTokenEnv)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to unset bearer token", "env", bearerTokenEnv, "error", err)
		}
	} else {
		slog.DebugContext(r.Context(), "API key found, setting bearer token", "env", bearerTokenEnv, "header", headerName)

		err := os.Setenv(bearerTokenEnv, apiKey)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to set bearer token", "env", bearerTokenEnv, "error", err)
		}
	}
}

// withLogger returns a middleware to log each invocation of the mcp server.
func withLogger(logger *slog.Logger) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			session := req.GetSession()
			params := req.GetParams()

			logger.DebugContext(ctx, "MCP method started",
				"method", method,
				"session_id", session.ID(),
				"has_params", params != nil,
			)

			start := time.Now()

			result, err := next(ctx, method, req)

			duration := time.Since(start)

			if err != nil {
				logger.ErrorContext(ctx, "MCP method failed",
					"method", method,
					"session_id", session.ID(),
					"duration_ms", duration.Milliseconds(),
					"error", err,
				)
			}

			return result, err
		}
	}
}
