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
	"time"

	"github.com/evcc-io/openapi-mcp/pkg/openapi2mcp"
	"github.com/getkin/kin-openapi/openapi3"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/trento-project/mcp-server/internal/utils"
)

// ServeOptions encapsulates the available command-line options.
type ServeOptions struct {
	McpBaseURL                  string
	Name                        string
	OASPath                     string
	OauthAuthorizationServerURL string
	OauthEnabled                bool
	OauthIssuer                 string
	OauthValidateURL            string
	Port                        int
	Transport                   utils.TransportType
	TrentoPassword              string
	TrentoURL                   string
	TrentoUsername              string
	Version                     string
}

// StoppableServer defines an interface for servers that can be started and shut down.
type StoppableServer interface {
	Start(addr string) error
	Shutdown(ctx context.Context) error
}

// AuthContextWrapperFn is a wrapper for the authentication functions that are passed to the MCP server.
type AuthContextWrapperFn = func(c context.Context, r *http.Request) context.Context

// Serve is the root command that is run when no other sub-commands are present.
func Serve(ctx context.Context, serveOpts *ServeOptions) error {
	var err error

	slog.DebugContext(ctx, "starting Serve() command",
		"server.options", fmt.Sprintf("%+v", *serveOpts),
	)

	// Create the MCP server.
	srv := createMCPServer(ctx, serveOpts)

	slog.DebugContext(ctx, "the MCP server has been created",
		"mcpserver.name", serveOpts.Name,
		"mcpserver.version", serveOpts.Version,
	)

	// Create the MCP server and register the tools.
	srv, tools, err := handleToolsRegistration(ctx, srv, serveOpts)
	if err != nil {
		return err
	}

	slog.DebugContext(ctx, "the tools have been registered",
		"mcpserver.tools.count", len(tools),
		"mcpserver.tools", fmt.Sprintf("%+v", tools),
	)

	slog.InfoContext(ctx, fmt.Sprintf("the MCP server %s has %d registered tools", serveOpts.Name, len(tools)))

	// Start the MCP server depending on the chosen transport.
	err = handleServerRun(ctx, srv, serveOpts)
	if err != nil {
		return err
	}

	return err
}

// createMCPServer creates the MCP server, but does not start serving it yet.
func createMCPServer(ctx context.Context, serveOpts *ServeOptions) *mcpserver.MCPServer {
	// Create MCP server options.
	// For additional ones, refer to https://github.com/mark3labs/mcp-go/blob/main/server/server.go
	opts := []mcpserver.ServerOption{
		mcpserver.WithLogging(),              // enables logging capabilities for the server
		mcpserver.WithRecovery(),             // recovers from panics in tool handlers
		mcpserver.WithToolCapabilities(true), // configures tool-related server capabilities
	}

	slog.DebugContext(ctx, "the MCP server options have been created",
		"server.options", fmt.Sprintf("%+v", opts),
	)

	// Create the MCP server with above options.
	srv := mcpserver.NewMCPServer(serveOpts.Name, serveOpts.Version, opts...)

	return srv
}

// handleToolsRegistration loads the OAS file, transforms it into MCP tools and registers them into the MCP server.
func handleToolsRegistration(
	ctx context.Context,
	srv *mcpserver.MCPServer,
	serveOpts *ServeOptions,
) (*mcpserver.MCPServer, []string, error) {
	// Load OpenAPI spec.
	oasDoc, err := openapi2mcp.LoadOpenAPISpec(serveOpts.OASPath)
	if err != nil {
		slog.ErrorContext(ctx, "failed to read the API spec",
			"error", err,
		)

		return nil, []string{}, fmt.Errorf("failed to read the API spec: %w", err)
	}

	// Overwrite or the Trento URL in the OpenAPI
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

	// Register them as MCP tools.
	tools := openapi2mcp.RegisterOpenAPITools(srv, operations, oasDoc, nil)

	return srv, tools, nil
}

// handleServerRun configures and starts the appropriate server based on the selected transport.
// It sets up an authentication context wrapper and blocks until a shutdown signal is received.
func handleServerRun(ctx context.Context, srv *mcpserver.MCPServer, serveOpts *ServeOptions) error {
	// Build the address to listen to
	listenAddr := fmt.Sprintf(":%d", serveOpts.Port)

	slog.DebugContext(ctx, "about to start the MCP server",
		"server.address", listenAddr,
		"server.transport", serveOpts.Transport,
	)

	// Wrapper to pass the url and other params in the future
	authContext := func(c context.Context, r *http.Request) context.Context {
		return authContextFunc(
			c,
			r,
			serveOpts.OauthEnabled,
			serveOpts.OauthValidateURL,
			serveOpts.TrentoURL,
			serveOpts.TrentoUsername,
			serveOpts.TrentoPassword,
		)
	}

	serverErrChan := make(chan error, 1)
	var stoppableServer StoppableServer
	var err error

	// Depending on the chosen transport, we handle the server startup.
	switch serveOpts.Transport {
	case utils.TransportSSE:
		stoppableServer, err = startSSEServer(ctx, srv, listenAddr, authContext, serverErrChan)

	case utils.TransportStreamable:
		stoppableServer, err = startStreamableHTTPServer(ctx, srv, listenAddr, serveOpts, authContext, serverErrChan)

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
	server StoppableServer,
	transportType utils.TransportType,
	errChan chan<- error,
) {
	go func() {
		slog.InfoContext(ctx, "the MCP server is listening",
			"server.address", listenAddr,
			"server.transport", transportType,
		)
		if err := server.Start(listenAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.ErrorContext(ctx, fmt.Sprintf("failed to serve MCP server via %s", transportType),
				"error", err,
			)
			errChan <- err
		}
	}()
}

// startStreamableHTTPServer initializes and starts a custom streamable HTTP server.
func startStreamableHTTPServer(
	ctx context.Context,
	mcpSrv *mcpserver.MCPServer,
	listenAddr string,
	serveOpts *ServeOptions,
	authContext AuthContextWrapperFn,
	errChan chan<- error,
) (*CustomStreamableHTTPServer, error) {
	streamableServer := NewCustomStreamableHTTPServer(mcpSrv, "/mcp", authContext, serveOpts)
	startServer(ctx, listenAddr, streamableServer, utils.TransportStreamable, errChan)
	return streamableServer, nil
}

// startSSEServer initializes and starts a Server-Sent Events (SSE) server.
func startSSEServer(
	ctx context.Context,
	mcpSrv *mcpserver.MCPServer,
	listenAddr string,
	authContext AuthContextWrapperFn,
	errChan chan<- error,
) (*mcpserver.SSEServer, error) {
	sseServer := mcpserver.NewSSEServer(mcpSrv, mcpserver.WithSSEContextFunc(authContext))
	startServer(ctx, listenAddr, sseServer, utils.TransportSSE, errChan)
	return sseServer, nil
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

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.ErrorContext(ctx, "failed to shut down the MCP server, forcing exit",
			"error", err,
		)
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	slog.InfoContext(ctx, "the MCP server was shut down successfully")

	return nil
}
