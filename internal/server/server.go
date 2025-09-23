// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

// Package server is the where the server logic is implemented.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"time"

	openapi2mcp "github.com/evcc-io/openapi-mcp"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trento-project/mcp-server/internal/utils"
)

// ServeOptions encapsulates the available command-line options.
type ServeOptions struct {
	Name             string
	OASPath          string
	Port             int
	Transport        utils.TransportType
	TrentoHeaderName string
	TagFilter        []string
	TrentoURL        string
	Version          string
}

// StoppableServer defines an interface for servers that can be started and shut down.
type StoppableServer interface {
	Shutdown(ctx context.Context) error
}

// AuthContextWrapperFn is a wrapper for the authentication functions that are passed to the MCP server.
type AuthContextWrapperFn = func(ctx context.Context, req *http.Request) context.Context

const (
	// bearerTokenEnv is the env var name that the MCP client is expecting to read.
	// This comes from the tool conversion performed at:
	// https://github.com/evcc-io/openapi-mcp/blob/5af774c51f554649795872fe26c415f804456951/pkg/openapi2mcp/register.go#L77
	bearerTokenEnv = "BEARER_TOKEN"
)

// Serve is the root command that is run when no other sub-commands are present.
func Serve(ctx context.Context, serveOpts *ServeOptions) error {
	slog.DebugContext(ctx, "starting Serve() command",
		"server.options", fmt.Sprintf("%+v", *serveOpts),
	)

	// Create the MCP server.
	srv := createMCPServer(ctx, serveOpts)

	slog.DebugContext(ctx, "the MCP server has been created",
		"mcp.name", serveOpts.Name,
		"mcp.version", serveOpts.Version,
	)

	// Create the MCP server and register the tools.
	// The openapi-mcp library logs to stdout/stderr.
	// We capture and redirect it to our logger to honor the log levels.
	// TODO(agamez): remove if the library is updated, see:
	// https://github.com/evcc-io/openapi-mcp/blob/0c909602302e0e228c89808be3f33bc6d521f0ce/schema.go#L71
	// https://github.com/evcc-io/openapi-mcp/blob/0c909602302e0e228c89808be3f33bc6d521f0ce/register.go#L423
	var tools []string

	err := utils.CaptureLibraryLogs(ctx, func() error {
		var (
			regErr          error
			registeredSrv   *mcp.Server
			registeredTools []string
		)

		registeredSrv, registeredTools, regErr = handleToolsRegistration(ctx, srv, serveOpts)
		if regErr == nil {
			srv = registeredSrv
			tools = registeredTools
		}

		return regErr
	})
	if err != nil {
		return err
	}

	slog.DebugContext(ctx, "the tools have been registered",
		"mcp.tools.count", len(tools),
		"mcp.tools", fmt.Sprintf("%+v", tools),
	)

	slog.InfoContext(ctx, fmt.Sprintf("the MCP server %s has %d registered tools", serveOpts.Name, len(tools)))

	// Start the MCP server depending on the chosen transport.
	err = handleServerRun(ctx, srv, serveOpts)
	if err != nil {
		return err
	}

	return nil
}

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
	// Load OpenAPI spec.
	oasDoc, err := openapi2mcp.LoadOpenAPISpec(serveOpts.OASPath)
	if err != nil {
		slog.ErrorContext(ctx, "failed to read the API spec",
			"error", err,
		)

		return nil, []string{}, fmt.Errorf("failed to read the API spec: %w", err)
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

	return srv, tools, nil
}

// handleServerRun configures and starts the appropriate server based on the selected transport.
// It sets up an authentication context wrapper and blocks until a shutdown signal is received. //nolint:lll.
func handleServerRun(ctx context.Context, srv *mcp.Server, serveOpts *ServeOptions) error {
	// Build the address to listen to
	listenAddr := fmt.Sprintf(":%d", serveOpts.Port)

	slog.DebugContext(ctx, "about to start the MCP server",
		"server.address", listenAddr,
		"server.transport", serveOpts.Transport,
	)

	serverErrChan := make(chan error, 1)

	var (
		stoppableServer StoppableServer
		err             error
	)

	// Depending on the chosen transport, we handle the server startup.

	switch serveOpts.Transport {
	case utils.TransportSSE:
		stoppableServer, err = startSSEServer(ctx, srv, listenAddr, serveOpts.TrentoHeaderName, serverErrChan)

	case utils.TransportStreamable:
		stoppableServer, err = startStreamableHTTPServer(ctx, srv, listenAddr, serveOpts.TrentoHeaderName, serverErrChan)

	default:
		return fmt.Errorf("invalid transport type: %s", serveOpts.Transport)
	}

	if err != nil {
		return err
	}

	// Block until shutdown or an error occurs
	return waitForShutdown(ctx, stoppableServer, serverErrChan)
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
		Addr:              listenAddr,
		Handler:           handler,
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		IdleTimeout:       30 * time.Second,
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
) (StoppableServer, error) {
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
) (StoppableServer, error) {
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

// waitForShutdown, once and interrupt signal is received, it gracefully shuts down the server.
func waitForShutdown(ctx context.Context, server StoppableServer, serverErrChan <-chan error) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	select {
	case err := <-serverErrChan:
		return fmt.Errorf("server error: %w", err)
	case <-quit:
		slog.DebugContext(ctx, "interrupt signal received, shutting down")
	case <-ctx.Done():
		slog.DebugContext(ctx, "context cancelled, shutting down")
	}

	// Stop listening to signals to clean up the handler.
	signal.Stop(quit)
	close(quit)

	slog.DebugContext(ctx, "gracefully shutting down the MCP server")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := server.Shutdown(shutdownCtx)
	if err != nil {
		slog.ErrorContext(ctx, "failed to shut down the MCP server, forcing exit",
			"error", err,
		)

		return fmt.Errorf("server shutdown failed: %w", err)
	}

	slog.InfoContext(ctx, "the MCP server was shut down successfully")

	return nil
}

// handleAPIKeyAuth extracts the API key from the request header and sets it as the bearer token environment variable.
// TODO(agamez): double-check in the future, we might have something built-in
// see https://github.com/modelcontextprotocol/go-sdk/blob/87f222477b31e542d33283f71358f829eb6a996b/auth/auth.go#L38
func handleAPIKeyAuth(r *http.Request, headerName string) {
	apiKey := r.Header.Get(headerName)

	if apiKey == "" {
		slog.InfoContext(r.Context(), "API key not found in request header", "header", headerName)
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
