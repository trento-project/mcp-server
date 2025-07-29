// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

// Package server is the where the server logic is implemented.
package server_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trento-project/mcp-server/internal/server"
	"github.com/trento-project/mcp-server/internal/utils"
)

type authContextWrapperFn func(c context.Context, r *http.Request) context.Context

func TestServe(t *testing.T) {
	tmpFile := createTempOASFile(t)

	tests := []struct {
		name      string
		transport utils.TransportType
		path      string
	}{
		{
			name:      "Streamable transport",
			transport: utils.TransportStreamable,
			path:      "/mcp",
		},
		{
			name:      "SSE transport",
			transport: utils.TransportSSE,
			path:      "/sse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			port := getAvailablePort(t)
			serveOpts := &server.ServeOptions{
				Port:           port,
				OASPath:        tmpFile,
				Transport:      tt.transport,
				TrentoURL:      "http://trento.test",
				TrentoUsername: "user",
				TrentoPassword: "password",
			}

			checkURL := fmt.Sprintf("http://localhost:%d%s", port, tt.path)
			testServerShutdown(t, cancel, func() error {
				return server.Serve(ctx, serveOpts)
			}, checkURL, fmt.Sprintf("TestServe with transport %s timed out", tt.transport))
		})
	}
}

func TestCreateMCPServer(t *testing.T) {
	ctx := context.Background()
	serveOpts := &server.ServeOptions{
		Name:    "test-server",
		Version: "1.0.0",
	}

	// The function under test
	srv := server.CreateMCPServer(ctx, serveOpts)
	require.NotNil(t, srv, "Expected a non-nil MCP server, got nil")

	// Create an in-process mcpClient to interact with the server.
	mcpClient, err := mcpclient.NewInProcessClient(srv)
	require.NoError(t, err, "failed to create in-process client")

	// Start the mcp client
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err = mcpClient.Start(ctxWithTimeout)
	require.NoError(t, err, "failed to start client")

	// Initialize the client and check the server's response
	initRequest := mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo: mcp.Implementation{
				Name:    "test-client",
				Version: "0.1.0",
			},
		},
	}

	initResult, err := mcpClient.Initialize(ctx, initRequest)
	require.NoError(t, err, "failed to initialize MCP client")

	// Assert that the server info from the initialize result matches our options
	assert.Equal(t, serveOpts.Name, initResult.ServerInfo.Name)
	assert.Equal(t, serveOpts.Version, initResult.ServerInfo.Version)
}

func TestHandleToolsRegistration(t *testing.T) {
	ctx := context.Background()
	srv := server.CreateMCPServer(ctx, &server.ServeOptions{Name: "test", Version: "v1"})
	tmpFile := createTempOASFile(t)

	serveOpts := &server.ServeOptions{
		OASPath:   tmpFile,
		TrentoURL: "http://trento.test",
	}

	// execute
	_, tools, err := server.HandleToolsRegistration(ctx, srv, serveOpts)

	// assert
	require.NoError(t, err)
	require.NotNil(t, tools)
	assert.Contains(t, tools, "getTest")
	assert.Contains(t, tools, "info") // openapi2mcp adds an 'info' tool
}

func TestHandleServerRun(t *testing.T) {
	tests := []struct {
		name      string
		transport utils.TransportType
		path      string
	}{
		{
			name:      "Streamable transport",
			transport: utils.TransportStreamable,
			path:      "/mcp",
		},
		{
			name:      "SSE transport",
			transport: utils.TransportSSE,
			path:      "/sse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			srv := server.CreateMCPServer(ctx, &server.ServeOptions{Name: "test", Version: "v1"})
			port := getAvailablePort(t)

			serveOpts := &server.ServeOptions{
				Port:           port,
				Transport:      tt.transport,
				TrentoUsername: "user",
				TrentoPassword: "password",
			}

			checkURL := fmt.Sprintf("http://localhost:%d%s", port, tt.path)
			testServerShutdown(t, cancel, func() error {
				return server.HandleServerRun(ctx, srv, serveOpts)
			}, checkURL, "TestHandleServerRun timed out waiting for shutdown")
		})
	}
}

func TestStartServer(t *testing.T) {
	type shutdowner interface {
		Shutdown(context.Context) error
	}

	tests := []struct {
		name    string
		startFn func(
			ctx context.Context,
			mcpSrv *mcpserver.MCPServer,
			addr string,
			serveOpts *server.ServeOptions,
			authContext authContextWrapperFn,
			errChan chan<- error,
		) (shutdowner, error)
		checkPath string
	}{
		{
			name: "Streamable HTTP Server",
			startFn: func(
				ctx context.Context,
				mcpSrv *mcpserver.MCPServer,
				addr string,
				serveOpts *server.ServeOptions,
				authContext authContextWrapperFn,
				errChan chan<- error,
			) (shutdowner, error) {
				return server.StartStreamableHTTPServer(ctx, mcpSrv, addr, serveOpts, authContext, errChan)
			},
			checkPath: "/mcp",
		},
		{
			name: "SSE Server",
			startFn: func(
				ctx context.Context,
				mcpSrv *mcpserver.MCPServer,
				addr string,
				serveOpts *server.ServeOptions,
				authContext authContextWrapperFn,
				errChan chan<- error,
			) (shutdowner, error) {
				return server.StartSSEServer(ctx, mcpSrv, addr, serveOpts, authContext, errChan)
			},
			checkPath: "/sse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mcpSrv, port, addr := setupServerTest(t, ctx)

			serveOpts := &server.ServeOptions{Port: port}
			authContext := func(c context.Context, _ *http.Request) context.Context { return c }
			errChan := make(chan error, 1)

			httpServer, err := tt.startFn(ctx, mcpSrv, addr, serveOpts, authContext, errChan)
			require.NoError(t, err)
			require.NotNil(t, httpServer)
			defer httpServer.Shutdown(ctx) //nolint:errcheck

			// Wait for the server to be ready
			waitForServerReady(t, fmt.Sprintf("http://localhost:%d%s", port, tt.checkPath), 5*time.Second)
		})
	}
}

func TestWaitForShutdown(t *testing.T) {
	tests := []struct {
		name    string
		startFn func(
			ctx context.Context,
			mcpSrv *mcpserver.MCPServer,
			addr string,
			serveOpts *server.ServeOptions,
			authContext authContextWrapperFn,
			errChan chan<- error,
		) (any, error)
		waitFn    func(ctx context.Context, srv any, errChan chan error) error
		checkPath string
	}{
		{
			name: "Streamable",
			startFn: func(
				ctx context.Context,
				mcpSrv *mcpserver.MCPServer,
				addr string,
				serveOpts *server.ServeOptions,
				authContext authContextWrapperFn,
				errChan chan<- error,
			) (any, error) {
				return server.StartStreamableHTTPServer(ctx, mcpSrv, addr, serveOpts, authContext, errChan)
			},
			waitFn: func(ctx context.Context, srv any, errChan chan error) error {
				return server.WaitForShutdown(ctx, srv.(server.StoppableServer), errChan) //nolint:forcetypeassert
			},
			checkPath: "/mcp",
		},
		{
			name: "SSE",
			startFn: func(
				ctx context.Context,
				mcpSrv *mcpserver.MCPServer,
				addr string,
				serveOpts *server.ServeOptions,
				authContext authContextWrapperFn,
				errChan chan<- error,
			) (any, error) {
				return server.StartSSEServer(ctx, mcpSrv, addr, serveOpts, authContext, errChan)
			},
			waitFn: func(ctx context.Context, srv any, errChan chan error) error {
				return server.WaitForShutdown(ctx, srv.(server.StoppableServer), errChan) //nolint:forcetypeassert
			},
			checkPath: "/sse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			mcpSrv, port, addr := setupServerTest(t, ctx)
			serveOpts := &server.ServeOptions{Port: port}
			authContext := func(c context.Context, _ *http.Request) context.Context { return c }
			errChan := make(chan error, 1)

			httpServer, err := tt.startFn(ctx, mcpSrv, addr, serveOpts, authContext, errChan)
			require.NoError(t, err)
			require.NotNil(t, httpServer)

			waitErrChan := make(chan error, 1)
			go func() {
				// This will block until shutdown or error
				waitErrChan <- tt.waitFn(ctx, httpServer, errChan)
				close(waitErrChan)
			}()

			// Wait for the server to be ready
			checkURL := fmt.Sprintf("http://localhost:%d%s", port, tt.checkPath)
			waitForServerReady(t, checkURL, 5*time.Second)

			// Cancel the context to trigger shutdown
			cancel()

			// Wait for shutdown to complete
			select {
			case err := <-waitErrChan:
				assert.NoError(t, err, "waitForShutdown should return no error on graceful shutdown")
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for shutdown")
			}

			// Verify server is down
			_, err = http.Get(fmt.Sprintf("http://localhost:%d%s", port, tt.checkPath))
			assert.Error(t, err, "Server should be down")
		})
	}
}

func waitForServerReady(t *testing.T, url string, timeout time.Duration) {
	t.Helper()

	client := http.Client{}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			// The streamable server responds with 200 on GET for discovery.
			// The SSE server only accepts POST, so a 405 on GET indicates it's up and running.
			if resp.StatusCode == http.StatusOK ||
				(strings.HasSuffix(url, "/sse") && resp.StatusCode == http.StatusMethodNotAllowed) {
				return // Server is ready
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("server at %s not ready after %v", url, timeout)
}

// Helper functions for test setup and cleanup

// createTempOASFile creates a temporary OpenAPI specification file for testing
func createTempOASFile(t *testing.T) string {
	t.Helper()
	oasContent := `
{
  "openapi": "3.0.0",
  "info": {
    "title": "Simple API",
    "version": "1.0.0"
  },
  "paths": {
    "/test": {
      "get": {
        "operationId": "getTest",
        "summary": "A test endpoint",
        "responses": {
          "200": {
            "description": "OK"
          }
        }
      }
    }
  }
}`
	tmpFile, err := os.CreateTemp("", "openapi-*.json")
	require.NoError(t, err)
	t.Cleanup(func() { err = os.Remove(tmpFile.Name()); require.NoError(t, err) })

	_, err = tmpFile.WriteString(oasContent)
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err)

	return tmpFile.Name()
}

// getAvailablePort finds an available port for testing
func getAvailablePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert
	err = l.Close()
	require.NoError(t, err)
	return port
}

// setupServerTest is a helper that creates a test MCP server and gets an available port
//
//nolint:revive
func setupServerTest(t *testing.T, ctx context.Context) (*mcpserver.MCPServer, int, string) {
	t.Helper()
	mcpSrv := server.CreateMCPServer(ctx, &server.ServeOptions{Name: "test", Version: "v1"})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	port := l.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert
	err = l.Close()
	require.NoError(t, err)

	return mcpSrv, port, addr
}

// testServerShutdown is a helper that starts a server function in a goroutine,
// waits for it to be ready, triggers shutdown via context cancellation,
// and verifies graceful shutdown
func testServerShutdown(
	t *testing.T,
	cancel context.CancelFunc,
	serverFn func() error,
	checkURL string,
	timeoutMsg string,
) {
	t.Helper()

	errChan := make(chan error, 1)
	go func() {
		errChan <- serverFn()
	}()

	// Wait for the server to be ready
	waitForServerReady(t, checkURL, 5*time.Second)

	// Cancel the context to trigger shutdown
	cancel()

	// Wait for server to return
	select {
	case err := <-errChan:
		assert.NoError(t, err, "server should exit gracefully")
	case <-time.After(10 * time.Second):
		t.Fatal(timeoutMsg)
	}
}
