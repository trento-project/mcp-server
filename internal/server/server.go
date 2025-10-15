// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

// Package server is the where the server logic is implemented.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/trento-project/mcp-server/internal/utils"
)

// ServeOptions encapsulates the available command-line options.
type ServeOptions struct {
	AutodiscoveryPaths    []string            `mapstructure:"AUTODISCOVERY_PATHS"`
	EnableHealthCheck     bool                `mapstructure:"ENABLE_HEALTH_CHECK"`
	HeaderName            string              `mapstructure:"HEADER_NAME"`
	HealthAPIPath         string              `mapstructure:"HEALTH_API_PATH"`
	HealthPort            int                 `mapstructure:"HEALTH_PORT"`
	InsecureSkipTLSVerify bool                `mapstructure:"INSECURE_SKIP_TLS_VERIFY"`
	Name                  string              `mapstructure:"-"`
	OASPath               []string            `mapstructure:"OAS_PATH"`
	Port                  int                 `mapstructure:"PORT"`
	TagFilter             []string            `mapstructure:"TAG_FILTER"`
	Transport             utils.TransportType `mapstructure:"TRANSPORT"`
	TrentoURL             string              `mapstructure:"TRENTO_URL"`
	Version               string              `mapstructure:"-"`
}

// Serve is the root command that is run when no other sub-commands are present.
func Serve(ctx context.Context, serveOpts *ServeOptions) error {
	slog.InfoContext(ctx, "starting the MCP server",
		"server.options", fmt.Sprintf("%+v", *serveOpts),
	)

	// Create the MCP server.
	srv := createMCPServer(ctx, serveOpts)

	slog.InfoContext(ctx, "the MCP server has been created",
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

	// Create error channel for server communication
	serverErrChan := make(chan error, 2) // Buffer for both MCP and health servers

	// Create a server group to manage both MCP and health servers
	serverGroup := utils.NewServerGroup()

	// Start the MCP server depending on the chosen transport
	mcpServer, err := handleMCPServerRun(ctx, srv, serveOpts, serverErrChan)
	if err != nil {
		return err
	}

	// Add the MCP server to the server group
	serverGroup.Add(mcpServer)

	// Start the health check server
	if serveOpts.EnableHealthCheck {
		healthServer := startHealthServer(ctx, serveOpts, serverErrChan)
		serverGroup.Add(healthServer)
	}

	// Block until shutdown or an error occurs
	return waitForShutdown(ctx, serverGroup, serverErrChan)
}

// waitForShutdown, once and interrupt signal is received, it gracefully shuts down the servers.
func waitForShutdown(ctx context.Context, serverGroup *utils.ServerGroup, serverErrChan <-chan error) error {
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

	slog.DebugContext(ctx, "gracefully shutting down all servers")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := serverGroup.Shutdown(shutdownCtx)
	if err != nil {
		slog.ErrorContext(ctx, "failed to shut down servers, forcing exit",
			"error", err,
		)

		return fmt.Errorf("server shutdown failed: %w", err)
	}

	slog.InfoContext(ctx, "all servers were shut down successfully")

	return nil
}
