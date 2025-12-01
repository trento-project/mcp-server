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
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	openapi2mcp "github.com/evcc-io/openapi-mcp"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trento-project/mcp-server/internal/utils"
)

// AuthContextWrapperFn is a wrapper for the authentication functions that are passed to the MCP server.
type AuthContextWrapperFn = func(ctx context.Context, req *http.Request) context.Context

// contextKey is a type definition for the context key.
type contextKey string

const (
	// bearerTokenEnv is the env var name that the MCP client is expecting to read.
	// This comes from the tool conversion performed at:
	// https://github.com/evcc-io/openapi-mcp/blob/5af774c51f554649795872fe26c415f804456951/pkg/openapi2mcp/register.go#L77
	bearerTokenEnv string = "BEARER_TOKEN"
	// sessionBearerTokenKey is the context key used for passing the API token through.
	sessionBearerTokenKey contextKey = "session_bearer_token"

	// methodInitialize see https://modelcontextprotocol.io/specification/draft/schema#initialize
	methodInitialize string = "initialize"
	// methodCallTool see https://modelcontextprotocol.io/specification/draft/schema#tools%2Fcall
	methodCallTool string = "tools/call"
)

// Session token storage and synchronization.
var (
	// sessionTokens maps session ID to bearer token for multi-user support.
	sessionTokens sync.Map //nolint:gochecknoglobals

	// envMutex serializes tool execution to prevent race conditions when setting
	// the global BEARER_TOKEN environment variable.
	// This is necessary because openapi2mcp uses os.Getenv() which is process-global.
	envMutex sync.Mutex //nolint:gochecknoglobals
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

	// Add authentication middleware FIRST - it must run before tool execution
	srv.AddReceivingMiddleware(withAuthMiddleware())

	// Add logging middleware
	srv.AddReceivingMiddleware(withLogger(slog.Default()))

	return srv
}

// handleToolsRegistration loads the OAS file, transforms it into MCP tools and registers them into the MCP server.
func handleToolsRegistration(
	ctx context.Context,
	srv *mcp.Server,
	serveOpts *ServeOptions, //nolint:revive
) (*mcp.Server, []string, error) {
	var (
		allTools          []string
		oasDiscoveryPaths []string
	)

	// If custom OAS paths are passed, use them; otherwise, try autodiscovery.
	if len(serveOpts.OASPath) != 0 {
		oasDiscoveryPaths = serveOpts.OASPath
	} else {
		if serveOpts.TrentoURL == "" {
			return nil, nil, errors.New("no OAS paths provided and no Trento URL configured for autodiscovery")
		}

		if len(serveOpts.AutodiscoveryPaths) == 0 {
			return nil, nil, errors.New("no OAS paths provided and no autodiscovery paths configured")
		}

		// Construct URLs by removing trailing slash and appending the configurable API endpoints
		trentoBaseURL, err := url.Parse(serveOpts.TrentoURL)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"invalid Trento URL for autodiscovery: %q (parse error: %w). Expected format like http://trento.example.com",
				serveOpts.TrentoURL, err,
			)
		}

		if trentoBaseURL.Scheme == "" {
			return nil, nil, fmt.Errorf(
				"invalid Trento URL for autodiscovery: %q (missing scheme). Please include http:// or https://",
				serveOpts.TrentoURL,
			)
		}

		if trentoBaseURL.Host == "" {
			return nil, nil, fmt.Errorf(
				"invalid Trento URL for autodiscovery: %q (missing host). Expected a host like trento.example.com",
				serveOpts.TrentoURL,
			)
		}

		// Construct full URLs
		for _, path := range serveOpts.AutodiscoveryPaths {
			ref, err := url.Parse(path)
			if err != nil {
				slog.DebugContext(ctx, "invalid autodiscovery path; skipping",
					"error", err,
					"path", path,
				)

				continue
			}

			fullPath := trentoBaseURL.ResolveReference(ref).String()
			oasDiscoveryPaths = append(oasDiscoveryPaths, fullPath)
		}

		slog.InfoContext(ctx, "no OpenAPI spec paths provided, attempting autodiscovery",
			"trento_url", serveOpts.TrentoURL,
			"discovery_paths", oasDiscoveryPaths,
		)
	}

	for _, path := range oasDiscoveryPaths {
		// Load OpenAPI spec.
		oasDoc, err := loadOpenAPISpec(ctx, path, serveOpts)
		if err != nil {
			slog.ErrorContext(ctx, "failed to read an API spec",
				"path", path,
				"error", err,
			)

			return nil, nil, fmt.Errorf("failed to read API spec from %s: %w", path, err)
		}

		// If TrentoURL is empty and the spec path is remote (http/https), derive the base URL (scheme://host[:port])
		// from the path and update the OpenAPI servers accordingly:
		if serveOpts.TrentoURL == "" && (strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://")) {
			newAPIServerURL := ""

			parsedURL, err := url.Parse(path)

			if err == nil && parsedURL.Scheme != "" && parsedURL.Host != "" {
				serverURL := &url.URL{
					Scheme: parsedURL.Scheme,
					Host:   parsedURL.Host,
				}
				newAPIServerURL = serverURL.String()
			}

			// If there is already at least one server, replace the first entry.
			if len(oasDoc.Servers) > 0 {
				slog.DebugContext(ctx, "replacing server URL in OpenAPI spec",
					"path", path,
					"old_url", oasDoc.Servers[0].URL,
					"current_url", newAPIServerURL,
				)

				oasDoc.Servers[0].URL = newAPIServerURL
				// If not, just create a new "server" entry.
			} else {
				oasDoc.Servers = append(oasDoc.Servers, &openapi3.Server{URL: newAPIServerURL})
				slog.DebugContext(ctx, "no server found in OpenAPI spec, adding new server",
					"path", path,
					"current_url", newAPIServerURL,
				)
			}
			// Otherwise (TrentoURL provided or non-remote path) leave servers as-is.
		} else {
			if len(oasDoc.Servers) > 0 {
				slog.DebugContext(ctx, "using original server URL in OpenAPI spec",
					"path", path,
					"current_url", oasDoc.Servers[0].URL,
				)
			} else {
				slog.ErrorContext(ctx, "no server found in OpenAPI spec, check the API documentation",
					"path", path,
				)
			}
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

	// Create an HTTP client with TLS configuration for tool execution
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: serveOpts.InsecureSkipTLSVerify, //nolint:gosec // Allow insecure TLS when explicitly requested
			},
		},
		Timeout: 0 * time.Second,
	}

	opts := &openapi2mcp.ToolGenOptions{
		TagFilter:               nil,   // TODO(agamez): revert back to "serveOpts.TagFilter," once we can.
		ConfirmDangerousActions: false, // TODO(agamez): not really working IRL, make it configurable?
		RequestHandler: func(req *http.Request) (*http.Response, error) {
			return httpClient.Do(req)
		},
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
		err = resp.Body.Close()
		if err != nil {
			slog.DebugContext(ctx, "failed to close response body",
				"error", err,
				"path", path,
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
		WriteTimeout: 0 * time.Second,
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

// setAPIKeyInContext extracts the API key from the request header and stores it in the request context.
// The middleware will later associate it with the session.
func setAPIKeyInContext(r *http.Request, headerName string) {
	apiKey := r.Header.Get(headerName)
	if apiKey != "" {
		slog.DebugContext(r.Context(), "API key found in request, storing in context", "header", headerName)
		*r = *r.WithContext(context.WithValue(r.Context(), sessionBearerTokenKey, apiKey))
	} else {
		slog.DebugContext(r.Context(), "API key not found in request header", "header", headerName)
	}
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
			setAPIKeyInContext(r, headerName)

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
			setAPIKeyInContext(r, headerName)

			return mcpSrv
		},
		&mcp.SSEOptions{},
	)

	httpServer := startServer(ctx, listenAddr, sseHandler, utils.TransportSSE, errChan)

	return httpServer, nil
}

// withAuthMiddleware creates middleware that manages per-session bearer tokens.
// It intercepts the 'initialize' method to store tokens and 'tools/call' to inject them.
func withAuthMiddleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			sessionID := req.GetSession().ID()

			// When a session is initialized, store its bearer token
			if method == methodInitialize {
				if token, ok := ctx.Value(sessionBearerTokenKey).(string); ok && token != "" {
					sessionTokens.Store(sessionID, token)
					slog.DebugContext(ctx, "stored bearer token for new session",
						"session.id", sessionID,
					)
				} else {
					slog.DebugContext(ctx, "session initialized without bearer token",
						"session.id", sessionID,
					)
				}

				return next(ctx, method, req)
			}

			// Only inject auth for tool calls,
			// for now it's the only place where
			// the API key is used.
			if method != methodCallTool {
				return next(ctx, method, req)
			}

			// Retrieve the session's bearer token
			var token string

			if storedToken, exists := sessionTokens.Load(sessionID); exists {
				if t, ok := storedToken.(string); ok {
					token = t
				} else {
					slog.DebugContext(ctx, "stored token is not a string, skipping",
						"session_id", sessionID,
					)
				}
			}

			if token == "" {
				slog.DebugContext(ctx, "no bearer token found for tool call",
					"session.id", sessionID,
					"method", method,
				)
				// Continue without auth - the API will return 401 if authentication is required
				return next(ctx, method, req)
			}

			slog.DebugContext(ctx, "injecting bearer token for tool execution",
				"session.id", sessionID,
			)

			// Acquire lock to prevent race conditions with different tokens
			envMutex.Lock()
			defer envMutex.Unlock()

			// Save original environment state
			originalToken, hasOriginal := os.LookupEnv(bearerTokenEnv)

			// Set session-specific token
			err := os.Setenv(bearerTokenEnv, token)
			if err != nil {
				slog.ErrorContext(ctx, "failed to set bearer token",
					"session.id", sessionID,
					"error", err,
				)

				return nil, fmt.Errorf("failed to set authentication token: %w", err)
			}

			// Ensure environment is restored after tool execution
			defer func() {
				var restoreErr error
				if hasOriginal {
					restoreErr = os.Setenv(bearerTokenEnv, originalToken)
				} else {
					restoreErr = os.Unsetenv(bearerTokenEnv)
				}

				if restoreErr != nil {
					slog.ErrorContext(ctx, "failed to restore environment after tool execution",
						"session.id", sessionID,
						"error", restoreErr,
					)
				}
			}()

			// Execute tool with session-specific authentication
			return next(ctx, method, req)
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
				"session.id", session.ID(),
				"has_params", params != nil,
			)

			start := time.Now()

			result, err := next(ctx, method, req)

			duration := time.Since(start)

			if err != nil {
				logger.ErrorContext(ctx, "MCP method failed",
					"method", method,
					"session.id", session.ID(),
					"duration_ms", duration.Milliseconds(),
					"error", err,
				)
			}

			return result, err
		}
	}
}
