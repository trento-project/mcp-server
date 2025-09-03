// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

// Package server is the where the server logic is implemented.
//
//nolint:lll
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

func TestServe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		transport   utils.TransportType
		path        string
		oasContent  string
		expectErr   bool
		errContains string
	}{
		{
			name:       "Streamable transport should start and stop",
			transport:  utils.TransportStreamable,
			path:       "/mcp",
			oasContent: createSimpleOASContent(),
			expectErr:  false,
		},
		{
			name:       "SSE transport should start and stop",
			transport:  utils.TransportSSE,
			path:       "/sse",
			oasContent: createSimpleOASContent(),
			expectErr:  false,
		},
		{
			name:        "should fail with invalid OAS file",
			transport:   utils.TransportStreamable,
			oasContent:  `{ "invalid": "json"`,
			expectErr:   true,
			errContains: "failed to read the API spec",
		},
		{
			name:        "should fail with invalid transport",
			transport:   "invalid-transport",
			oasContent:  createSimpleOASContent(),
			expectErr:   true,
			errContains: "invalid transport type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tmpFile := createTempOASFile(t, tt.oasContent)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			port := getAvailablePort(t)
			serveOpts := &server.ServeOptions{
				Port:      port,
				OASPath:   tmpFile,
				Transport: tt.transport,
				TrentoURL: "http://trento.test",
			}

			if tt.expectErr {
				err := server.Serve(ctx, serveOpts)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				checkURL := fmt.Sprintf("http://localhost:%d%s", port, tt.path)
				testServerShutdown(t, cancel, func() error {
					return server.Serve(ctx, serveOpts)
				}, checkURL, fmt.Sprintf("TestServe with transport %s timed out", tt.transport))
			}
		})
	}
}

func TestCreateMCPServer(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	tests := []struct {
		name             string
		oasContent       string
		tagFilter        []string
		expectErr        bool
		errContains      string
		expectedTools    []string
		notExpectedTools []string
	}{

		{
			name: "should register tools with MCP tag",
			oasContent: `{
				"openapi": "3.0.0", "info": {"title": "API", "version": "1.0"},
				"paths": {
					"/test": {"get": {"operationId": "getTest", "tags": ["MCP"], "responses": {"200": {"description": "OK"}}}}
				}
			}`,
			tagFilter:     []string{"MCP"},
			expectErr:     false,
			expectedTools: []string{"getTest", "info"},
		},
		{
			name: "should not register tools without MCP tag if filtered",
			oasContent: `{
				"openapi": "3.0.0", "info": {"title": "API", "version": "1.0"},
				"paths": {
					"/test": {"get": {"operationId": "getTest", "tags": ["Other"], "responses": {"200": {"description": "OK"}}}}
				}
			}`,
			tagFilter:        []string{"MCP"},
			expectErr:        false,
			expectedTools:    []string{"info"},
			notExpectedTools: []string{"getTest"},
		},
		{
			name: "should register tools with custom tag",
			oasContent: `{
				"openapi": "3.0.0", "info": {"title": "API", "version": "1.0"},
				"paths": {
					"/test": {"get": {"operationId": "getTest", "tags": ["Custom"], "responses": {"200": {"description": "OK"}}}}
				}
			}`,
			tagFilter:     []string{"Custom"},
			expectErr:     false,
			expectedTools: []string{"getTest", "info"},
		},
		{
			name: "should handle multiple tags",
			oasContent: `{
				"openapi": "3.0.0", "info": {"title": "API", "version": "1.0"},
				"paths": {
					"/test1": {"get": {"operationId": "getTest1", "tags": ["A"], "responses": {"200": {"description": "OK"}}}},
					"/test2": {"get": {"operationId": "getTest2", "tags": ["B"], "responses": {"200": {"description": "OK"}}}},
					"/test3": {"get": {"operationId": "getTest3", "tags": ["C"], "responses": {"200": {"description": "OK"}}}}
				}
			}`,
			tagFilter:        []string{"A", "C"},
			expectErr:        false,
			expectedTools:    []string{"getTest1", "getTest3", "info"},
			notExpectedTools: []string{"getTest2"},
		},
		{
			name:        "should return error for invalid OAS file",
			oasContent:  `{ "openapi": "3.0.0", "info": { ... }`, // malformed JSON
			tagFilter:   []string{"MCP"},
			expectErr:   true,
			errContains: "failed to read the API spec",
		},
		{
			name: "should format operation names correctly",
			oasContent: `{
				"openapi": "3.0.0", "info": {"title": "API", "version": "1.0"},
				"paths": {
					"/test1": {"get": {"operationId": "TrentoWeb.V1.SomeController.action", "tags": ["MCP"], "responses": {"200": {"description": "OK"}}}},
					"/test2": {"get": {"operationId": "WandaWeb_V2_Another_action", "tags": ["MCP"], "responses": {"200": {"description": "OK"}}}},
					"/test3": {"get": {"operationId": "NoPrefixControllerAction", "tags": ["MCP"], "responses": {"200": {"description": "OK"}}}}
				}
			}`,
			tagFilter:     []string{"MCP"},
			expectErr:     false,
			expectedTools: []string{"Some_action", "Another_action", "NoPrefixAction", "info"},
		},
		{
			name: "should overwrite server URL if present",
			oasContent: `{
				"openapi": "3.0.0", "info": {"title": "API", "version": "1.0"},
				"servers": [{"url": "http://original.url"}],
				"paths": {
					"/test": {"get": {"operationId": "getTest", "tags": ["MCP"], "responses": {"200": {"description": "OK"}}}}
				}
			}`,
			tagFilter: []string{"MCP"},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel() // Run sub-tests in parallel

			ctx := context.Background()
			srv := server.CreateMCPServer(ctx, &server.ServeOptions{Name: "test", Version: "v1"})

			// Create a temporary OAS file for each test case
			tmpFile := createTempOASFile(t, tt.oasContent)

			serveOpts := &server.ServeOptions{
				OASPath:   tmpFile,
				TrentoURL: "http://trento.test",
				TagFilter: tt.tagFilter,
			}

			// execute
			_, tools, err := server.HandleToolsRegistration(ctx, srv, serveOpts)

			// assert
			if tt.expectErr {
				require.Error(t, err)

				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, tools)

				for _, expectedTool := range tt.expectedTools {
					assert.Contains(t, tools, expectedTool)
				}

				for _, notExpectedTool := range tt.notExpectedTools {
					assert.NotContains(t, tools, notExpectedTool)
				}
			}
		})
	}
}

func TestHandleServerRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		transport   utils.TransportType
		path        string
		expectErr   bool
		errContains string
	}{
		{
			name:      "should start and stop streamable transport",
			transport: utils.TransportStreamable,
			path:      "/mcp",
			expectErr: false,
		},
		{
			name:      "should start and stop sse transport",
			transport: utils.TransportSSE,
			path:      "/sse",
			expectErr: false,
		},
		{
			name:        "should fail with invalid transport",
			transport:   "invalid-transport",
			expectErr:   true,
			errContains: "invalid transport type",
		},
		{
			name:        "should fail if port is in use for streamable",
			transport:   utils.TransportStreamable,
			expectErr:   true,
			errContains: "address",
		},
		{
			name:        "should fail if port is in use for sse",
			transport:   utils.TransportSSE,
			expectErr:   true,
			errContains: "address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			srv := server.CreateMCPServer(ctx, &server.ServeOptions{Name: "test", Version: "v1"})
			port := getAvailablePort(t)

			// For the "port in use" test, occupy the port before starting the server
			if strings.Contains(tt.errContains, "address") {
				lc := net.ListenConfig{KeepAlive: time.Second}
				l, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", port))
				require.NoError(t, err)
				defer l.Close() //nolint:errcheck
				// Give the OS a moment to register the port as in use
				time.Sleep(200 * time.Millisecond)
			}

			serveOpts := &server.ServeOptions{
				Port:      port,
				Transport: tt.transport,
			}

			if tt.expectErr {
				err := server.HandleServerRun(ctx, srv, serveOpts)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				checkURL := fmt.Sprintf("http://localhost:%d%s", port, tt.path)
				testServerShutdown(t, cancel, func() error {
					return server.HandleServerRun(ctx, srv, serveOpts)
				}, checkURL, "TestHandleServerRun timed out waiting for shutdown")
			}
		})
	}
}

func TestWaitForShutdown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		startFn         func(context.Context, *mcpserver.MCPServer, string, server.AuthContextWrapperFn, chan<- error) (server.StoppableServer, error)
		checkPath       string
		mockStartErr    error
		mockShutdownErr error
		expectErr       bool
		errContains     string
	}{
		{
			name: "Streamable graceful shutdown",
			startFn: func(
				ctx context.Context,
				mcpSrv *mcpserver.MCPServer,
				addr string, authContext server.AuthContextWrapperFn,
				errChan chan<- error,
			) (server.StoppableServer, error) {
				return server.StartStreamableHTTPServer(ctx,
					mcpSrv, addr, authContext, errChan)
			},
			checkPath: "/mcp",
			expectErr: false,
		},
		{
			name: "SSE graceful shutdown",
			startFn: func(
				ctx context.Context, mcpSrv *mcpserver.MCPServer,
				addr string, authContext server.AuthContextWrapperFn,
				errChan chan<- error,
			) (server.StoppableServer, error) {
				return server.StartSSEServer(ctx, mcpSrv, addr, authContext, errChan)
			},
			checkPath: "/sse",
			expectErr: false,
		},
		{
			name:         "Server start error",
			mockStartErr: assert.AnError,
			expectErr:    true,
			errContains:  "server error:",
		},
		{
			name:            "Server shutdown error",
			mockShutdownErr: assert.AnError,
			expectErr:       true,
			errContains:     "server shutdown failed:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			//nolint:gocritic
			if tt.mockStartErr != nil {
				// Test case for server startup failure
				mockServer := &mockStoppableServer{startErr: tt.mockStartErr}
				serverErrChan := make(chan error, 1)

				go func() {
					err := mockServer.Start("")
					if err != nil {
						serverErrChan <- err
					}
				}()

				err := server.WaitForShutdown(ctx, mockServer, serverErrChan)

				require.Error(t, err)
				require.ErrorIs(t, err, tt.mockStartErr)
				assert.Contains(t, err.Error(), tt.errContains)
			} else if tt.mockShutdownErr != nil {
				// Test case for server shutdown failure
				mockServer := &mockStoppableServer{shutdownErr: tt.mockShutdownErr}
				serverErrChan := make(chan error, 1)

				go func() {
					// This mock server starts successfully
					err := mockServer.Start("")
					if err != nil {
						serverErrChan <- err
					}
				}()

				waitErrChan := make(chan error, 1)

				go func() {
					waitErrChan <- server.WaitForShutdown(ctx, mockServer, serverErrChan)

					close(waitErrChan)
				}()

				cancel() // Trigger shutdown

				select {
				case err := <-waitErrChan:
					require.Error(t, err)
					require.ErrorIs(t, err, tt.mockShutdownErr)
					assert.Contains(t, err.Error(), tt.errContains)
				case <-time.After(5 * time.Second):
					t.Fatal("timed out waiting for shutdown error")
				}
			} else {
				// Test case for graceful shutdown
				mcpSrv, port, addr := setupServerTest(t, ctx)
				authContext := func(c context.Context, _ *http.Request) context.Context { return c }
				errChan := make(chan error, 1)

				httpServer, err := tt.startFn(ctx, mcpSrv, addr, authContext, errChan)
				require.NoError(t, err)
				require.NotNil(t, httpServer)

				waitErrChan := make(chan error, 1)

				go func() {
					waitErrChan <- server.WaitForShutdown(ctx, httpServer, errChan)

					close(waitErrChan)
				}()

				checkURL := fmt.Sprintf("http://localhost:%d%s", port, tt.checkPath)
				waitForServerReady(t, checkURL, 5*time.Second)

				cancel()

				select {
				case err := <-waitErrChan:
					require.NoError(t, err, "waitForShutdown should return no error on graceful shutdown")
				case <-time.After(5 * time.Second):
					t.Fatal("timed out waiting for shutdown")
				}

				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, checkURL, nil)
				require.NoError(t, err)

				client := &http.Client{}
				resp, err := client.Do(req)
				require.Error(t, err, "Server should be down")

				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
			}
		})
	}
}

func waitForServerReady(t *testing.T, url string, timeout time.Duration) {
	t.Helper()

	client := http.Client{}

	deadline := time.Now().Add(timeout)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	require.NoError(t, err)

	for time.Now().Before(deadline) {
		// Use client.Do to ensure the context is passed for cancellation
		// and to avoid issues with client.Get's default redirect behavior
		resp, err := client.Do(req)
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

// mockStoppableServer is a mock implementation of the StoppableServer interface for testing.
type mockStoppableServer struct {
	startErr    error
	shutdownErr error
}

func (m *mockStoppableServer) Start(_ string) error {
	return m.startErr
}
func (m *mockStoppableServer) Shutdown(_ context.Context) error { return m.shutdownErr }

// createSimpleOASContent returns a simple and valid OAS content with a single operation.
func createSimpleOASContent() string {
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
				"tags": [
					"MCP"
				],
				"responses": {
					"200": {
						"description": "OK"
					}
				}
			}
		}
	}
}`

	return oasContent
}

// createTempOASFile creates a temporary OpenAPI specification file for testing.
func createTempOASFile(t *testing.T, oasContent string) string {
	t.Helper()

	tmpFile, err := os.CreateTemp(t.TempDir(), "openapi-*.json")
	require.NoError(t, err)
	t.Cleanup(func() { err = os.Remove(tmpFile.Name()); require.NoError(t, err) })

	_, err = tmpFile.WriteString(oasContent)
	require.NoError(t, err)
	err = tmpFile.Close()
	require.NoError(t, err)

	return tmpFile.Name()
}

// getAvailablePort finds an available port for testing.
func getAvailablePort(t *testing.T) int {
	t.Helper()

	lc := net.ListenConfig{KeepAlive: time.Second}
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
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

	lc := net.ListenConfig{KeepAlive: time.Second}
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := l.Addr().String()
	port := l.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert
	err = l.Close()
	require.NoError(t, err)

	return mcpSrv, port, addr
}

// testServerShutdown is a helper that starts a server function in a goroutine,
// waits for it to be ready, triggers shutdown via context cancellation,
// and verifies graceful shutdown.
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

	// Give the server a moment to clean up goroutines (especially for SSE)
	time.Sleep(200 * time.Millisecond)

	// Wait for server to return
	select {
	case err := <-errChan:
		require.NoError(t, err, "server should exit gracefully")
	case <-time.After(10 * time.Second):
		t.Fatal(timeoutMsg)
	}
}

func TestApiKeyAuthContextFunc(t *testing.T) {
	const (
		headerName     = "X-Test-Api-Key"
		bearerTokenEnv = "BEARER_TOKEN"
	)

	tests := []struct {
		name           string
		apiKey         string
		headerPresent  bool
		initialEnv     string // if empty, env is unset
		expectEnvSet   bool
		expectedAPIKey string
	}{
		{
			name:           "should set BEARER_TOKEN when api key is present",
			apiKey:         "my-secret-key",
			headerPresent:  true,
			initialEnv:     "",
			expectEnvSet:   true,
			expectedAPIKey: "my-secret-key",
		},
		{
			name:           "should unset BEARER_TOKEN when api key is not present",
			headerPresent:  false,
			initialEnv:     "some-stale-key",
			expectEnvSet:   false,
			expectedAPIKey: "",
		},
		{
			name:           "should unset BEARER_TOKEN when api key is an empty string",
			apiKey:         "",
			headerPresent:  true,
			initialEnv:     "some-stale-key",
			expectEnvSet:   false,
			expectedAPIKey: "",
		},
		{
			name:           "should overwrite an existing BEARER_TOKEN",
			apiKey:         "new-key",
			headerPresent:  true,
			initialEnv:     "old-key",
			expectEnvSet:   true,
			expectedAPIKey: "new-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup initial environment for this test case
			if tt.initialEnv != "" {
				t.Setenv(bearerTokenEnv, tt.initialEnv)
			} else {
				err := os.Unsetenv(bearerTokenEnv)
				require.NoError(t, err)
			}

			// Create request
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
			require.NoError(t, err)

			if tt.headerPresent {
				req.Header.Set(headerName, tt.apiKey)
			}

			// Call the function under test
			server.APIKeyAuthContextFunc(context.Background(), req, headerName)

			// Assertions
			actualAPIKey, isSet := os.LookupEnv(bearerTokenEnv)
			assert.Equal(t, tt.expectEnvSet, isSet)

			if tt.expectEnvSet {
				assert.Equal(t, tt.expectedAPIKey, actualAPIKey)
			}
		})
	}
}
