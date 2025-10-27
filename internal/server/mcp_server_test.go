// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

//nolint:lll
package server_test

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	openapi2mcp "github.com/evcc-io/openapi-mcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trento-project/mcp-server/internal/server"
	"github.com/trento-project/mcp-server/internal/utils"
)

//nolint:dupl
func TestStartSSEServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		headerName  string
		expectError bool
		checkPath   string
	}{
		{
			name:       "successful SSE server start",
			headerName: "X-API-Key",
			checkPath:  "/sse",
		},
		{
			name:       "SSE server with different header name",
			headerName: "X-Custom-Auth",
			checkPath:  "/sse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			srv := server.CreateMCPServer(ctx, &server.ServeOptions{Name: "test", Version: "v1"})
			port := getAvailablePort(t)
			listenAddr := fmt.Sprintf(":%d", port)
			checkURL := fmt.Sprintf("http://localhost:%d%s", port, tt.checkPath)

			testServerShutdown(t, cancel, func() error {
				serverErrChan := make(chan error, 1)

				sseServer, err := server.StartSSEServer(ctx, srv, listenAddr, tt.headerName, serverErrChan)
				if err != nil {
					return err
				}

				return waitForShutdownSingle(ctx, t, sseServer, serverErrChan)
			}, checkURL, "TestStartSSEServer timed out waiting for shutdown")
		})
	}
}

//nolint:dupl
func TestStartStreamableHTTPServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		headerName  string
		expectError bool
		checkPath   string
	}{
		{
			name:       "successful streamable server start",
			headerName: "X-API-Key",
			checkPath:  "/mcp",
		},
		{
			name:       "streamable server with different header name",
			headerName: "X-Custom-Auth",
			checkPath:  "/mcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			srv := server.CreateMCPServer(ctx, &server.ServeOptions{Name: "test", Version: "v1"})
			port := getAvailablePort(t)
			listenAddr := fmt.Sprintf(":%d", port)
			checkURL := fmt.Sprintf("http://localhost:%d%s", port, tt.checkPath)

			testServerShutdown(t, cancel, func() error {
				serverErrChan := make(chan error, 1)

				streamableServer, err := server.StartStreamableHTTPServer(ctx, srv, listenAddr, tt.headerName, serverErrChan)
				if err != nil {
					return err
				}

				return waitForShutdownSingle(ctx, t, streamableServer, serverErrChan)
			}, checkURL, "TestStartStreamableHTTPServer timed out waiting for shutdown")
		})
	}
}

func TestStartServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		transport     utils.TransportType
		handlerFunc   func() http.Handler
		expectStartup bool
	}{
		{
			name:      "start server with basic handler",
			transport: utils.TransportStreamable,
			handlerFunc: func() http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, err := w.Write([]byte("OK"))
					assert.NoError(t, err)
				})
			},
			expectStartup: true,
		},
		{
			name:      "start server with SSE transport",
			transport: utils.TransportSSE,
			handlerFunc: func() http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, err := w.Write([]byte("SSE OK"))
					assert.NoError(t, err)
				})
			},
			expectStartup: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			port := getAvailablePort(t)
			listenAddr := fmt.Sprintf(":%d", port)
			checkURL := fmt.Sprintf("http://localhost:%d", port)

			testServerShutdown(t, cancel, func() error {
				serverErrChan := make(chan error, 1)
				httpServer := server.StartServer(ctx, listenAddr, tt.handlerFunc(), tt.transport, serverErrChan)

				return waitForShutdownSingle(ctx, t, httpServer, serverErrChan)
			}, checkURL, "TestStartServer timed out waiting for shutdown")
		})
	}
}

func TestWithLogger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		loggerName  string
		expectPanic bool
	}{
		{
			name:       "creates middleware with default logger",
			loggerName: "test-logger",
		},
		{
			name:       "creates middleware with different logger",
			loggerName: "another-logger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create logger middleware
			logger := slog.Default()
			middleware := server.WithLogger(logger)

			// Verify that the middleware function is created successfully
			require.NotNil(t, middleware, "middleware should not be nil")

			// Verify that it returns a MethodHandler function
			assert.IsType(t, mcp.MethodHandler(nil), middleware(nil))
		})
	}
}

func TestCreateMCPServer(t *testing.T) {
	t.Parallel()

	serveOpts := &server.ServeOptions{
		Name:    "test-server",
		Version: "1.0.0",
	}

	// The function under test
	srv := server.CreateMCPServer(t.Context(), serveOpts)
	require.NotNil(t, srv, "Expected a non-nil MCP server, got nil")

	// Connect server and client over an in-memory transport using the official go-sdk client
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	// Connect the server side first so it is ready to accept the client initialize
	_, err := srv.Connect(t.Context(), serverTransport, nil)
	require.NoError(t, err, "failed to connect server")

	// Create the client implementation and connect
	clientImpl := &mcp.Implementation{Name: "test-client", Version: "0.1.0"}
	client := mcp.NewClient(clientImpl, nil)
	cs, err := client.Connect(t.Context(), clientTransport, nil)
	require.NoError(t, err, "failed to connect client")

	defer func() { _ = cs.Close() }()

	ctxWithTimeout, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	require.NoError(t, cs.Ping(ctxWithTimeout, nil))
	tools, err := cs.ListTools(ctxWithTimeout, nil)
	require.NoError(t, err)
	assert.Empty(t, tools.Tools)
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
		{
			name: "should include ops when any tag intersects (multiple tags & filters)",
			oasContent: `{
				"openapi": "3.0.0", "info": {"title": "API", "version": "1.0"},
				"paths": {
					"/alpha": {"get": {"operationId": "alphaBetaOp", "tags": ["Alpha", "Beta"], "responses": {"200": {"description": "OK"}}}},
					"/gamma": {"get": {"operationId": "gammaOp", "tags": ["Gamma"], "responses": {"200": {"description": "OK"}}}}
				}
			}`,
			tagFilter:        []string{"Beta", "Delta"},
			expectErr:        false,
			expectedTools:    []string{"alphaBetaOp", "info"},
			notExpectedTools: []string{"gammaOp"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel() // Run sub-tests in parallel

			srv := server.CreateMCPServer(t.Context(), &server.ServeOptions{Name: "test", Version: "v1"})

			// Create a temporary OAS file for each test case
			tmpFile := createTempOASFile(t, tt.oasContent)

			serveOpts := &server.ServeOptions{
				OASPath:   []string{tmpFile},
				TrentoURL: "http://trento.test",
				TagFilter: tt.tagFilter,
			}

			// execute
			_, tools, err := server.HandleToolsRegistration(t.Context(), srv, serveOpts)

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

func TestRegisterToolsFromSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		oasContent       string
		tagFilter        []string
		expectedTools    []string
		notExpectedTools []string
	}{
		{
			name: "should register tools with no tag filter",
			oasContent: `{
				"openapi": "3.0.0", "info": {"title": "API", "version": "1.0"},
				"paths": {
					"/test1": {"get": {"operationId": "getTest1", "tags": ["A"], "responses": {"200": {"description": "OK"}}}},
					"/test2": {"get": {"operationId": "getTest2", "tags": ["B"], "responses": {"200": {"description": "OK"}}}}
				}
			}`,
			tagFilter:     []string{},
			expectedTools: []string{"getTest1", "getTest2", "info"},
		},
		{
			name: "should register only tools matching the tag filter",
			oasContent: `{
				"openapi": "3.0.0", "info": {"title": "API", "version": "1.0"},
				"paths": {
					"/test1": {"get": {"operationId": "getTest1", "tags": ["A"], "responses": {"200": {"description": "OK"}}}},
					"/test2": {"get": {"operationId": "getTest2", "tags": ["B"], "responses": {"200": {"description": "OK"}}}}
				}
			}`,
			tagFilter:        []string{"A"},
			expectedTools:    []string{"getTest1", "info"},
			notExpectedTools: []string{"getTest2"},
		},
		{
			name: "should register tools if any of their tags match the filter",
			oasContent: `{
				"openapi": "3.0.0", "info": {"title": "API", "version": "1.0"},
				"paths": {
					"/test1": {"get": {"operationId": "getTest1", "tags": ["A", "C"], "responses": {"200": {"description": "OK"}}}},
					"/test2": {"get": {"operationId": "getTest2", "tags": ["B"], "responses": {"200": {"description": "OK"}}}}
				}
			}`,
			tagFilter:        []string{"A", "B"},
			expectedTools:    []string{"getTest1", "getTest2", "info"},
			notExpectedTools: []string{},
		},
		{
			name: "should correctly format operation names",
			oasContent: `{
				"openapi": "3.0.0", "info": {"title": "API", "version": "1.0"},
				"paths": {
					"/test1": {"get": {"operationId": "TrentoWeb_V1_SomeController.action", "tags": ["A"], "responses": {"200": {"description": "OK"}}}},
					"/test2": {"get": {"operationId": "WandaWeb_V2_Another.action", "tags": ["A"], "responses": {"200": {"description": "OK"}}}},
					"/test3": {"get": {"operationId": "NoPrefixControllerAction", "tags": ["A"], "responses": {"200": {"description": "OK"}}}}
				}
			}`,
			tagFilter:     []string{"A"},
			expectedTools: []string{"Some_action", "Another_action", "NoPrefixAction", "info"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := server.CreateMCPServer(t.Context(), &server.ServeOptions{Name: "test", Version: "v1"})
			serveOpts := &server.ServeOptions{
				TagFilter: tt.tagFilter,
			}

			tmpFile := createTempOASFile(t, tt.oasContent)

			oasDoc, err := openapi2mcp.LoadOpenAPISpec(tmpFile)
			require.NoError(t, err)

			tools := server.RegisterToolsFromSpec(srv, oasDoc, serveOpts)

			require.NotNil(t, tools)

			for _, expectedTool := range tt.expectedTools {
				assert.Contains(t, tools, expectedTool, "expected tool not found")
			}

			for _, notExpectedTool := range tt.notExpectedTools {
				assert.NotContains(t, tools, notExpectedTool, "unexpected tool found")
			}
		})
	}
}

func TestHandleToolsRegistrationWithURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		oasContent    string
		trentoURL     string
		tagFilter     []string
		expectErr     bool
		errContains   string
		expectedTools int
	}{
		{
			name:          "should register tools from URL with Trento URL override",
			oasContent:    createSimpleOASContent(),
			trentoURL:     "https://custom-trento.example.com",
			tagFilter:     []string{"MCP"},
			expectErr:     false,
			expectedTools: 2, // getTest + info
		},
		{
			name:        "invalid OAS from URL",
			oasContent:  `{ "invalid": "json"`,
			trentoURL:   "https://trento.test",
			tagFilter:   []string{"MCP"},
			expectErr:   true,
			errContains: "failed to parse OpenAPI spec",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.oasContent))
			}))
			defer testServer.Close()

			serveOpts := &server.ServeOptions{
				Name:                  "trento-mcp-server",
				Version:               "1.0.0",
				OASPath:               []string{testServer.URL + "/openapi.json"},
				TrentoURL:             tt.trentoURL,
				TagFilter:             tt.tagFilter,
				InsecureSkipTLSVerify: false,
			}

			srv := server.CreateMCPServer(t.Context(), serveOpts)
			require.NotNil(t, srv)

			srv, tools, err := server.HandleToolsRegistration(t.Context(), srv, serveOpts)

			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				require.NotNil(t, srv)
				assert.Len(t, tools, tt.expectedTools)
			}
		})
	}
}

//nolint:paralleltest
func TestHandleMCPServerRun(t *testing.T) {
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

			ctx, cancel := context.WithCancel(t.Context())
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
				serverErrChan := make(chan error, 1)
				mcpServer, err := server.HandleMCPServerRun(ctx, srv, serveOpts, serverErrChan)

				if strings.Contains(tt.errContains, "address") {
					// For port conflict tests, the function returns successfully but error comes through channel
					require.NoError(t, err)
					require.NotNil(t, mcpServer)

					// Wait for the error from the channel
					select {
					case chanErr := <-serverErrChan:
						assert.Contains(t, chanErr.Error(), tt.errContains)
					case <-time.After(2 * time.Second):
						t.Fatal("expected error from server error channel but got none")
					}
				} else {
					// For other errors (like invalid transport), expect immediate error
					require.Error(t, err)
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				checkURL := fmt.Sprintf("http://localhost:%d%s", port, tt.path)
				testServerShutdown(t, cancel, func() error {
					serverErrChan := make(chan error, 1)

					mcpServer, err := server.HandleMCPServerRun(ctx, srv, serveOpts, serverErrChan)
					if err != nil {
						return err
					}
					// Use waitForShutdownSingle helper for testing
					return waitForShutdownSingle(ctx, t, mcpServer, serverErrChan)
				}, checkURL, "TestHandleServerRun timed out waiting for shutdown")
			}
		})
	}
}

func TestLoadOpenAPISpec_MultipleFiles(t *testing.T) {
	t.Parallel()

	oasContent1 := createSimpleOASContent()
	oasContent2 := strings.Replace(oasContent1, "getTest", "getTest2", 1)

	tmpFile1 := createTempOASFile(t, oasContent1)
	tmpFile2 := createTempOASFile(t, oasContent2)

	srv := server.CreateMCPServer(t.Context(), &server.ServeOptions{Name: "test", Version: "v1"})
	serveOpts := &server.ServeOptions{OASPath: []string{tmpFile1, tmpFile2}}
	_, tools, err := server.HandleToolsRegistration(t.Context(), srv, serveOpts)
	require.NoError(t, err)
	assert.Contains(t, tools, "getTest")
	assert.Contains(t, tools, "getTest2")
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
			// Consider the server ready if it returns any non-5xx response.
			// Streamable/SSE handlers may return 200, 405, or 404 on GET depending on implementation.
			if resp.StatusCode < 500 {
				return
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
func setupServerTest(ctx context.Context, t *testing.T) (*mcp.Server, int, string) {
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

func TestSetAPIKeyInContext(t *testing.T) {
	t.Parallel()

	const testHeaderName = "X-Test-Api-Key"

	tests := []struct {
		name            string
		headerName      string
		headerValue     string
		headerPresent   bool
		expectInContext bool
		expectedAPIKey  string
	}{
		{
			name:            "should store API key in context when header is present",
			headerName:      testHeaderName,
			headerValue:     "my-secret-key",
			headerPresent:   true,
			expectInContext: true,
			expectedAPIKey:  "my-secret-key",
		},
		{
			name:            "should not store API key when header is absent",
			headerName:      testHeaderName,
			headerValue:     "",
			headerPresent:   false,
			expectInContext: false,
			expectedAPIKey:  "",
		},
		{
			name:            "should not store API key when header value is empty",
			headerName:      testHeaderName,
			headerValue:     "",
			headerPresent:   true,
			expectInContext: false,
			expectedAPIKey:  "",
		},
		{
			name:            "should handle different header names",
			headerName:      "X-Custom-Auth",
			headerValue:     "custom-key-123",
			headerPresent:   true,
			expectInContext: true,
			expectedAPIKey:  "custom-key-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create request with the chosen header
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
			require.NoError(t, err)

			if tt.headerPresent {
				req.Header.Set(tt.headerName, tt.headerValue)
			}

			server.SetAPIKeyInContext(req, tt.headerName)

			// Get the value of the context key
			ctxValue := req.Context().Value(server.SessionBearerTokenKey)

			if tt.expectInContext {
				require.NotNil(t, ctxValue)
				apiKey, ok := ctxValue.(string)
				require.True(t, ok)
				assert.Equal(t, tt.expectedAPIKey, apiKey)
			} else {
				assert.Nil(t, ctxValue)
			}
		})
	}
}

func TestLoadOpenAPISpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		oasPath       string
		isHTTPLoad    bool
		oasContent    string
		expectErr     bool
		errContains   string
		expectedTitle string
	}{
		{
			name:          "should load from HTTP URL",
			oasPath:       "",
			isHTTPLoad:    true,
			oasContent:    createSimpleOASContent(),
			expectErr:     false,
			expectedTitle: "Simple API",
		},
		{
			name:          "should load from file path",
			oasPath:       "",
			isHTTPLoad:    false,
			oasContent:    createSimpleOASContent(),
			expectErr:     false,
			expectedTitle: "Simple API",
		},
		{
			name:        "invalid file",
			oasPath:     "/non/existent/file.json",
			isHTTPLoad:  false,
			oasContent:  "",
			expectErr:   true,
			errContains: "failed to read the API spec",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			serveOpts := &server.ServeOptions{
				Name:                  "trento-mcp-server",
				Version:               "1.0.0",
				OASPath:               []string{tt.oasPath},
				InsecureSkipTLSVerify: false,
			}

			var (
				cleanup func()
				path    string
			)

			if tt.isHTTPLoad {
				testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(tt.oasContent))
				}))
				path = testServer.URL + "/openapi.json"
				cleanup = testServer.Close
			} else {
				tmpFile := createTempOASFile(t, tt.oasContent)
				path = tmpFile
				cleanup = func() {}
			}

			defer cleanup()

			oasDoc, err := server.LoadOpenAPISpec(t.Context(), path, serveOpts)

			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, oasDoc)
			} else {
				require.NoError(t, err)
				require.NotNil(t, oasDoc)
				assert.Equal(t, tt.expectedTitle, oasDoc.Info.Title)
			}
		})
	}
}

func TestLoadOpenAPISpecFromURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		oasContent            string
		statusCode            int
		InsecureSkipTLSVerify bool
		expectErr             bool
		oasPath               string
		errContains           string
		expectedTitle         string
	}{
		{
			name:                  "valid OAS from HTTP URL",
			oasContent:            createSimpleOASContent(),
			statusCode:            http.StatusOK,
			InsecureSkipTLSVerify: false,
			expectErr:             false,
			oasPath:               "",
			expectedTitle:         "Simple API",
		},
		{
			name:                  "valid OAS from HTTPS URL with insecure TLS",
			oasContent:            createSimpleOASContent(),
			statusCode:            http.StatusOK,
			InsecureSkipTLSVerify: true,
			expectErr:             false,
			oasPath:               "",
			expectedTitle:         "Simple API",
		},
		{
			name:                  "404 status code",
			oasContent:            createSimpleOASContent(),
			statusCode:            http.StatusNotFound,
			InsecureSkipTLSVerify: false,
			expectErr:             true,
			oasPath:               "",
			errContains:           "status code: 404",
		},
		{
			name:                  "invalid JSON",
			oasContent:            `{ "invalid": "json"`,
			statusCode:            http.StatusOK,
			InsecureSkipTLSVerify: false,
			expectErr:             true,
			oasPath:               "",
			errContains:           "failed to parse OpenAPI spec",
		},
		{
			name:                  "network error",
			oasContent:            createSimpleOASContent(),
			statusCode:            http.StatusOK,
			InsecureSkipTLSVerify: false,
			expectErr:             true,
			oasPath:               "http://non-existent-server.com/openapi.json",
			errContains:           "failed to fetch OpenAPI spec",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify User-Agent header is set
				userAgent := r.Header.Get("User-Agent")
				assert.Contains(t, userAgent, "trento-mcp-server")

				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.oasContent))
			}))
			defer testServer.Close()

			serveOpts := &server.ServeOptions{
				Name:                  "trento-mcp-server",
				Version:               "1.0.0",
				OASPath:               []string{""},
				InsecureSkipTLSVerify: tt.InsecureSkipTLSVerify,
			}

			// If oasPath is unset, use the test server url.
			if tt.oasPath == "" {
				serveOpts.OASPath[0] = testServer.URL + "/openapi.json"
			} else {
				serveOpts.OASPath[0] = tt.oasPath
			}

			oasDoc, err := server.LoadOpenAPISpecFromURL(t.Context(), serveOpts.OASPath[0], serveOpts)

			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, oasDoc)
			} else {
				require.NoError(t, err)
				require.NotNil(t, oasDoc)
				assert.Equal(t, tt.expectedTitle, oasDoc.Info.Title)
			}
		})
	}
}

func TestHandleToolsRegistrationAutodiscovery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		trentoURL          string
		autodiscoveryPaths []string
		apiEndpointResp    map[string]apiResponse
		expectErr          bool
		errContains        string
		expectedTools      []string
		notExpectedTools   []string
		minToolsCount      int
	}{
		{
			name:               "invalid TrentoURL - parse error",
			trentoURL:          "http://exa mple.com", // space in host triggers parse error
			autodiscoveryPaths: []string{"/api/all/openapi"},
			expectErr:          true,
			errContains:        "parse error",
		},
		{
			name:               "invalid TrentoURL - missing scheme",
			trentoURL:          "trento.example.com", // no scheme
			autodiscoveryPaths: []string{"/api/all/openapi"},
			expectErr:          true,
			errContains:        "missing scheme",
		},
		{
			name:               "invalid TrentoURL - missing host",
			trentoURL:          "http:///api", // scheme present, host missing
			autodiscoveryPaths: []string{"/api/all/openapi"},
			expectErr:          true,
			errContains:        "missing host",
		},
		{
			name:               "successful autodiscovery with both endpoints working",
			trentoURL:          "https://trento.example.com",
			autodiscoveryPaths: []string{"/api/all/openapi", "/wanda/api/all/openapi"},
			apiEndpointResp: map[string]apiResponse{
				"/api/all/openapi": {
					statusCode: http.StatusOK,
					content:    createOASContentWithOperation(t, "getTrentoAPI", "TrentoAPI"),
				},
				"/wanda/api/all/openapi": {
					statusCode: http.StatusOK,
					content:    createOASContentWithOperation(t, "getWandaAPI", "WandaAPI"),
				},
			},
			expectErr:     false,
			expectedTools: []string{"getTrentoAPI", "getWandaAPI", "info"},
			minToolsCount: 3, // 2 operations + info from each spec
		},
		{
			name:      "autodiscovery fails if any endpoint fails (Trento API works, Wanda API fails)",
			trentoURL: "https://trento.example.com/",
			apiEndpointResp: map[string]apiResponse{
				"/api/all/openapi": {
					statusCode: http.StatusOK,
					content:    createOASContentWithOperation(t, "getTrentoAPI", "TrentoAPI"),
				},
				"/wanda/api/all/openapi": {
					statusCode: http.StatusNotFound,
					content:    "Not Found",
				},
			},
			expectErr:   true,
			errContains: "failed to read API spec from",
		},
		{
			name:      "autodiscovery fails if any endpoint fails (Wanda API works, Trento API fails)",
			trentoURL: "https://trento.example.com",
			apiEndpointResp: map[string]apiResponse{
				"/api/all/openapi": {
					statusCode: http.StatusInternalServerError,
					content:    "Server Error",
				},
				"/wanda/api/all/openapi": {
					statusCode: http.StatusOK,
					content:    createOASContentWithOperation(t, "getWandaAPI", "WandaAPI"),
				},
			},
			expectErr:   true,
			errContains: "failed to read API spec from",
		},
		{
			name:      "autodiscovery fails when both endpoints fail",
			trentoURL: "https://trento.example.com",
			apiEndpointResp: map[string]apiResponse{
				"/api/all/openapi": {
					statusCode: http.StatusNotFound,
					content:    "Not Found",
				},
				"/wanda/api/all/openapi": {
					statusCode: http.StatusInternalServerError,
					content:    "Server Error",
				},
			},
			expectErr:   true,
			errContains: "failed to read API spec from",
		},
		{
			name:      "autodiscovery fails with invalid JSON from endpoint",
			trentoURL: "https://trento.example.com",
			apiEndpointResp: map[string]apiResponse{
				"/api/all/openapi": {
					statusCode: http.StatusOK,
					content:    `{ "invalid": "json"`,
				},
				"/wanda/api/all/openapi": {
					statusCode: http.StatusOK,
					content:    `{ "another": "invalid json"`,
				},
			},
			expectErr:   true,
			errContains: "failed to parse OpenAPI spec",
		},
		{
			name:        "fails when no Trento URL provided for autodiscovery",
			trentoURL:   "",
			expectErr:   true,
			errContains: "no OAS paths provided and no Trento URL configured for autodiscovery",
		},
		{
			name:               "fails when no autodiscovery paths configured",
			trentoURL:          "https://trento.example.com",
			autodiscoveryPaths: []string{},
			expectErr:          true,
			errContains:        "no OAS paths provided and no autodiscovery paths configured",
		},
		{
			name:               "handles trailing slash in Trento URL correctly",
			trentoURL:          "https://trento.example.com/////",
			autodiscoveryPaths: []string{"/api/all/openapi"},
			apiEndpointResp: map[string]apiResponse{
				"/api/all/openapi": {
					statusCode: http.StatusOK,
					content:    createOASContentWithOperation(t, "getTrentoAPI", "TrentoAPI"),
				},
			},
			expectErr:     false,
			expectedTools: []string{"getTrentoAPI", "info"},
			minToolsCount: 2,
		},
		{
			name:               "successful autodiscovery with custom paths",
			trentoURL:          "https://trento.example.com",
			autodiscoveryPaths: []string{"/api/v1/openapi", "/custom/api/openapi"},
			apiEndpointResp: map[string]apiResponse{
				"/api/v1/openapi": {
					statusCode: http.StatusOK,
					content:    createOASContentWithOperation(t, "getCustomAPI", "CustomAPI"),
				},
				"/custom/api/openapi": {
					statusCode: http.StatusOK,
					content:    createOASContentWithOperation(t, "getSpecialAPI", "SpecialAPI"),
				},
			},
			expectErr:     false,
			expectedTools: []string{"getCustomAPI", "getSpecialAPI", "info"},
			minToolsCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := server.CreateMCPServer(t.Context(), &server.ServeOptions{Name: "test", Version: "v1"})

			// Create a test server that handles multiple endpoints
			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if resp, exists := tt.apiEndpointResp[r.URL.Path]; exists {
					w.WriteHeader(resp.statusCode)
					_, _ = w.Write([]byte(resp.content))

					return
				}
				// Default to 404 for unknown paths
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("Not Found"))
			}))
			defer testServer.Close()

			// Replace the trentoURL with our test server URL for the test
			testTrentoURL := tt.trentoURL
			if tt.trentoURL != "" && len(tt.apiEndpointResp) > 0 {
				testTrentoURL = testServer.URL
			}

			// Set default autodiscovery paths if not specified in test
			autodiscoveryPaths := tt.autodiscoveryPaths
			if len(autodiscoveryPaths) == 0 && tt.trentoURL != "" && !strings.Contains(tt.errContains, "no autodiscovery paths") {
				autodiscoveryPaths = []string{"/api/all/openapi", "/wanda/api/all/openapi"}
			}

			serveOpts := &server.ServeOptions{
				Name:               "trento-mcp-server",
				Version:            "1.0.0",
				OASPath:            []string{}, // Empty to trigger autodiscovery
				TrentoURL:          testTrentoURL,
				TagFilter:          []string{}, // No filtering for these tests
				AutodiscoveryPaths: autodiscoveryPaths,
			}

			// Execute the function under test
			_, tools, err := server.HandleToolsRegistration(t.Context(), srv, serveOpts)

			// Assertions
			if tt.expectErr {
				require.Error(t, err)

				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, tools)

				if tt.minToolsCount > 0 {
					assert.GreaterOrEqual(t, len(tools), tt.minToolsCount,
						"Expected at least %d tools, got %d: %v", tt.minToolsCount, len(tools), tools)
				}

				for _, expectedTool := range tt.expectedTools {
					assert.Contains(t, tools, expectedTool,
						"Expected tool '%s' not found in tools: %v", expectedTool, tools)
				}

				for _, notExpectedTool := range tt.notExpectedTools {
					assert.NotContains(t, tools, notExpectedTool,
						"Unexpected tool '%s' found in tools: %v", notExpectedTool, tools)
				}
			}
		})
	}
}

func TestHandleToolsRegistrationMixedScenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		oasPath       []string
		trentoURL     string
		expectErr     bool
		errContains   string
		expectedTools []string
		description   string
	}{
		{
			name:          "explicit paths provided should not trigger autodiscovery",
			oasPath:       []string{},                   // Will be set to temp file path
			trentoURL:     "https://trento.example.com", // Should be ignored
			expectErr:     false,
			expectedTools: []string{"getExplicitTest", "info"},
			description:   "When explicit OAS paths are provided, autodiscovery should not be attempted",
		},
		{
			name:        "explicit path failure should fail immediately (not try autodiscovery)",
			oasPath:     []string{"/nonexistent/file.json"},
			trentoURL:   "https://trento.example.com",
			expectErr:   true,
			errContains: "failed to read API spec from /nonexistent/file.json",
			description: "Explicit path failures should not fall back to autodiscovery",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := server.CreateMCPServer(t.Context(), &server.ServeOptions{Name: "test", Version: "v1"})

			// For the first test, create a temp file
			var actualOASPath []string

			if len(tt.oasPath) == 0 {
				tmpFile := createTempOASFile(t, createOASContentWithOperation(t, "getExplicitTest", "ExplicitAPI"))
				actualOASPath = []string{tmpFile}
			} else {
				actualOASPath = tt.oasPath
			}

			serveOpts := &server.ServeOptions{
				Name:      "trento-mcp-server",
				Version:   "1.0.0",
				OASPath:   actualOASPath,
				TrentoURL: tt.trentoURL,
				TagFilter: []string{},
			}

			// Execute the function under test
			_, tools, err := server.HandleToolsRegistration(t.Context(), srv, serveOpts)

			// Assertions
			if tt.expectErr {
				require.Error(t, err, tt.description)

				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err, tt.description)
				require.NotNil(t, tools)

				for _, expectedTool := range tt.expectedTools {
					assert.Contains(t, tools, expectedTool)
				}
			}
		})
	}
}

func TestServerURLBehavior(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		isRemote          bool
		trentoURL         string
		originalServerURL string
	}{
		{
			name:              "remote URL with TrentoURL should leave server untouched",
			isRemote:          true,
			trentoURL:         "https://trento.example.com",
			originalServerURL: "https://trento.example.com/api/v1",
		},
		{
			name:              "local file with no TrentoURL should leave server untouched",
			isRemote:          false,
			trentoURL:         "",
			originalServerURL: "https://trento.example.com/wanda/api/v1",
		},
		{
			name:              "local file with TrentoURL should leave server untouched",
			isRemote:          false,
			trentoURL:         "https://trento.example.com",
			originalServerURL: "https://trento.example.com/wanda/api/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var oasPath string

			srv := server.CreateMCPServer(t.Context(), &server.ServeOptions{Name: "test", Version: "v1"})

			oasContent := createOASContentWithServer(t, "testOp", "TestAPI", tt.originalServerURL)

			if tt.isRemote {
				// Create a test HTTP server
				testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(oasContent))
				}))
				defer testServer.Close()

				oasPath = testServer.URL + "/openapi.json"
			} else {
				// Create a local file
				oasPath = createTempOASFile(t, oasContent)
			}

			serveOpts := &server.ServeOptions{
				Name:      "trento-mcp-server",
				Version:   "1.0.0",
				OASPath:   []string{oasPath},
				TrentoURL: tt.trentoURL,
				TagFilter: []string{},
			}

			oasDoc, err := server.LoadOpenAPISpec(t.Context(), oasPath, serveOpts)
			require.NoError(t, err)

			_, _, err = server.HandleToolsRegistration(t.Context(), srv, serveOpts)
			require.NoError(t, err)

			// Server URL should remain untouched
			assert.NotNil(t, oasDoc.Servers)

			if len(oasDoc.Servers) > 0 {
				assert.Equal(t, tt.originalServerURL, oasDoc.Servers[0].URL)
			}
		})
	}
}

// Helper types and functions for autodiscovery tests

type apiResponse struct {
	statusCode int
	content    string
}

// createOASContentWithOperation creates OAS content with a specific operation for testing.
func createOASContentWithOperation(t *testing.T, operationID, tag string) string {
	t.Helper()

	return fmt.Sprintf(`{
	"openapi": "3.0.0",
	"info": {
		"title": "%s API",
		"version": "1.0.0"
	},
	"paths": {
		"/test": {
			"get": {
				"operationId": "%s",
				"summary": "A test endpoint for %s",
				"tags": ["%s"],
				"responses": {
					"200": {
						"description": "OK"
					}
				}
			}
		}
	}
}`, tag, operationID, tag, tag)
}

// createOASContentWithServer creates OAS content with a specific server URL.
func createOASContentWithServer(t *testing.T, operationID, tag, serverURL string) string {
	t.Helper()

	return fmt.Sprintf(`{
	"openapi": "3.0.0",
	"info": {
		"title": "%s API",
		"version": "1.0.0"
	},
	"servers": [
		{
			"url": "%s"
		}
	],
	"paths": {
		"/test": {
			"get": {
				"operationId": "%s",
				"summary": "A test endpoint for %s",
				"tags": ["%s"],
				"responses": {
					"200": {
						"description": "OK"
					}
				}
			}
		}
	}
}`, tag, serverURL, operationID, tag, tag)
}
