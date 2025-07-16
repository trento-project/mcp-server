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

	"github.com/getkin/kin-openapi/openapi3"
	mcpserver "github.com/jedisct1/openapi-mcp/pkg/mcp/server"
	"github.com/jedisct1/openapi-mcp/pkg/openapi2mcp"
)

// ServeOptions encapsulates the available command-line options.
type ServeOptions struct {
	McpBaseURL                  string
	OASPath                     string
	OauthAuthorizationServerURL string
	OauthEnabled                bool
	OauthIssuer                 string
	OauthValidateURL            string
	Port                        int
	Transport                   string
	TrentoPassword              string
	TrentoURL                   string
	TrentoUsername              string
}

// Serve is the root command that is run when no other sub-commands are present.
func Serve(serveOpts ServeOptions) error {
	ctx := context.Background()

	var err error

	slog.DebugContext(ctx, "starting Serve() command", "server.options", serveOpts)

	// Call the main server logic.
	err = runServer(ctx, &serveOpts)

	return err
}

func runServer(ctx context.Context, serveOpts *ServeOptions) error {
	listenAddr := fmt.Sprintf(":%d", serveOpts.Port)

	mcpSrv, err := createMCPServer(ctx, serveOpts)
	if err != nil {
		return err
	}

	switch serveOpts.Transport {
	case "sse":
		// startSSEServer logs and handles fatal errors internally if server fails to start
		err := startSSEServer(ctx, mcpSrv, listenAddr, serveOpts)
		if err != nil {
			return err
		}

	case "streamable":
		// startHTTPServer logs and handles fatal errors internally if server fails to start
		streamableServer := startHTTPServer(ctx, mcpSrv, listenAddr, serveOpts)

		waitForShutdownStreamable(ctx, streamableServer)
	default:
		return fmt.Errorf("invalid transport type: %s", serveOpts.Transport)
	}

	// So, if we reach here, it means graceful shutdown (or forced exit within waitForShutdown).
	return nil
}

func createMCPServer(ctx context.Context, serveOpts *ServeOptions) (*mcpserver.MCPServer, error) {
	// Load OpenAPI spec.
	oasDoc, err := openapi2mcp.LoadOpenAPISpec(serveOpts.OASPath)
	if err != nil {
		slog.ErrorContext(ctx, "failed to read the API spec", "error", err)

		return nil, fmt.Errorf("failed to read the API spec: %w", err)
	}

	// Overwrite the Trento URL in the OpenAPI
	if len(oasDoc.Servers) > 0 {
		oasDoc.Servers[0].URL = serveOpts.TrentoURL
	} else {
		oasDoc.Servers = append(oasDoc.Servers, &openapi3.Server{
			URL: serveOpts.TrentoURL,
		})
	}

	// Create MCP server options.
	opts := []mcpserver.ServerOption{
		mcpserver.WithLogging(),
		mcpserver.WithRecovery(),
	}

	// Create MCP server.
	srv := mcpserver.NewMCPServer("trento-mcp-server", oasDoc.Info.Version, opts...)

	// Extract the API operations.
	operations := openapi2mcp.ExtractOpenAPIOperations(oasDoc)

	// Register them as MCP tools.
	openapi2mcp.RegisterOpenAPITools(srv, operations, oasDoc, nil)

	return srv, nil
}

func startHTTPServer(
	ctx context.Context,
	mcpSrv *mcpserver.MCPServer,
	listenAddr string,
	serveOpts *ServeOptions,
) *CustomStreamableHTTPServer {
	// Wrapper to pass the url and other params in the future
	authContextFuncWrapper := func(c context.Context, r *http.Request) context.Context {
		if !serveOpts.OauthEnabled {
			return authContextFuncNoOauth(
				c,
				r,
				serveOpts.OauthValidateURL,
				serveOpts.TrentoURL,
				serveOpts.TrentoUsername,
				serveOpts.TrentoPassword,
			)
		}

		return authContextFunc(
			c,
			r,
			serveOpts.OauthValidateURL,
			serveOpts.TrentoURL,
			serveOpts.TrentoUsername,
			serveOpts.TrentoPassword,
		)
	}

	// Create the server, using custom one to handle mcp auth
	streamableServer := NewCustomStreamableHTTPServer(mcpSrv, "/mcp", authContextFuncWrapper, serveOpts)

	// Run the http server for the mcp in a separate goroutine.
	go func() {
		slog.InfoContext(ctx, "mcp server via HTTP starting", "server.address", listenAddr)

		err := streamableServer.Start(listenAddr)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.ErrorContext(ctx, "failed to serve MCP server via HTTP", "error", err)
		}
	}()

	slog.InfoContext(ctx, "mcp server via HTTP listening successfully", "server.address", listenAddr)

	return streamableServer
}

func startSSEServer(
	ctx context.Context,
	mcpSrv *mcpserver.MCPServer,
	listenAddr string,
	serveOpts *ServeOptions,
) error {
	authContextFuncWrapper := func(c context.Context, r *http.Request) context.Context {
		if !serveOpts.OauthEnabled {
			return authContextFuncNoOauth(
				c,
				r,
				serveOpts.OauthValidateURL,
				serveOpts.TrentoURL,
				serveOpts.TrentoUsername,
				serveOpts.TrentoPassword,
			)
		}

		return authContextFunc(
			c,
			r,
			serveOpts.OauthValidateURL,
			serveOpts.TrentoURL,
			serveOpts.TrentoUsername,
			serveOpts.TrentoPassword,
		)
	}

	// Create the server, using custom one to handle mcp auth
	sseServer := mcpserver.NewSSEServer(mcpSrv, mcpserver.WithSSEContextFunc(authContextFuncWrapper))

	// Run the http server for the mcp in a separate goroutine.
	slog.InfoContext(ctx, "mcp server via SSE starting", "server.address", listenAddr)

	err := sseServer.Start(listenAddr)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.ErrorContext(ctx, "failed to serve MCP server via HTTP", "error", err)
		panic(err)
	}

	slog.InfoContext(ctx, "mcp server via SSE listening successfully", "server.address", listenAddr)

	return nil
}

func waitForShutdownStreamable(ctx context.Context, streamableServer *CustomStreamableHTTPServer) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	slog.InfoContext(ctx, "shutting down mcp server")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := streamableServer.Shutdown(shutdownCtx)
	if err != nil {
		slog.ErrorContext(ctx, "failed to shut the mcp server down, forcing exit", "error", err)
		panic(err)
	}

	slog.InfoContext(ctx, "mcp server shut down successfully")
}
