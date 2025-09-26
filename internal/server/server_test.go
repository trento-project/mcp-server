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

//nolint:paralleltest
func TestServe(t *testing.T) {
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
	//nolint:paralleltest
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := createTempOASFile(t, tt.oasContent)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			port := getAvailablePort(t)
			serveOpts := &server.ServeOptions{
				Port:      port,
				OASPath:   []string{tmpFile},
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

	// Connect server and client over an in-memory transport using the official go-sdk client
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	// Connect the server side first so it is ready to accept the client initialize
	_, err := srv.Connect(ctx, serverTransport, nil)
	require.NoError(t, err, "failed to connect server")

	// Create the client implementation and connect
	clientImpl := &mcp.Implementation{Name: "test-client", Version: "0.1.0"}
	client := mcp.NewClient(clientImpl, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err, "failed to connect client")

	defer func() { _ = cs.Close() }()

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
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

			ctx := context.Background()
			srv := server.CreateMCPServer(ctx, &server.ServeOptions{Name: "test", Version: "v1"})

			// Create a temporary OAS file for each test case
			tmpFile := createTempOASFile(t, tt.oasContent)

			serveOpts := &server.ServeOptions{
				OASPath:   []string{tmpFile},
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

			ctx := context.Background()
			srv := server.CreateMCPServer(ctx, &server.ServeOptions{Name: "test", Version: "v1"})
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

			ctx := context.Background()

			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.oasContent))
			}))
			defer testServer.Close()

			serveOpts := &server.ServeOptions{
				Name:        "trento-mcp-server",
				Version:     "1.0.0",
				OASPath:     []string{testServer.URL + "/openapi.json"},
				TrentoURL:   tt.trentoURL,
				TagFilter:   tt.tagFilter,
				InsecureTLS: false,
			}

			srv := server.CreateMCPServer(ctx, serveOpts)
			require.NotNil(t, srv)

			srv, tools, err := server.HandleToolsRegistration(ctx, srv, serveOpts)

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

//nolint:paralleltest
func TestWaitForShutdown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		startFn         func(context.Context, *mcp.Server, string, string, chan<- error) (server.StoppableServer, error)
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
				mcpSrv *mcp.Server,
				addr string, headerName string,
				errChan chan<- error,
			) (server.StoppableServer, error) {
				return server.StartStreamableHTTPServer(ctx,
					mcpSrv, addr, headerName, errChan)
			},
			checkPath: "/mcp",
			expectErr: false,
		},
		{
			name: "SSE graceful shutdown",
			startFn: func(
				ctx context.Context, mcpSrv *mcp.Server,
				addr string, headerName string,
				errChan chan<- error,
			) (server.StoppableServer, error) {
				return server.StartSSEServer(ctx, mcpSrv, addr, headerName, errChan)
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
				headerName := "X-Test-API-Key"
				errChan := make(chan error, 1)

				httpServer, err := tt.startFn(ctx, mcpSrv, addr, headerName, errChan)
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

func TestLoadOpenAPISpec_MultipleFiles(t *testing.T) {
	t.Parallel()
	oasContent1 := createSimpleOASContent()
	oasContent2 := strings.Replace(oasContent1, "getTest", "getTest2", 1)

	tmpFile1 := createTempOASFile(t, oasContent1)
	tmpFile2 := createTempOASFile(t, oasContent2)

	srv := server.CreateMCPServer(context.Background(), &server.ServeOptions{Name: "test", Version: "v1"})
	serveOpts := &server.ServeOptions{OASPath: []string{tmpFile1, tmpFile2}}
	_, tools, err := server.HandleToolsRegistration(context.Background(), srv, serveOpts)
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
func setupServerTest(t *testing.T, ctx context.Context) (*mcp.Server, int, string) {
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

func TestHandleAPIKeyAuth(t *testing.T) {
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
			server.HandleAPIKeyAuth(req, headerName)

			// Assertions
			actualAPIKey, isSet := os.LookupEnv(bearerTokenEnv)
			assert.Equal(t, tt.expectEnvSet, isSet)

			if tt.expectEnvSet {
				assert.Equal(t, tt.expectedAPIKey, actualAPIKey)
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

			ctx := context.Background()
			serveOpts := &server.ServeOptions{
				Name:        "trento-mcp-server",
				Version:     "1.0.0",
				OASPath:     []string{tt.oasPath},
				InsecureTLS: false,
			}

			var cleanup func()
			var path string

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

			oasDoc, err := server.LoadOpenAPISpec(ctx, path, serveOpts)

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
		name          string
		oasContent    string
		statusCode    int
		insecureTLS   bool
		expectErr     bool
		oasPath       string
		errContains   string
		expectedTitle string
	}{
		{
			name:          "valid OAS from HTTP URL",
			oasContent:    createSimpleOASContent(),
			statusCode:    http.StatusOK,
			insecureTLS:   false,
			expectErr:     false,
			oasPath:       "",
			expectedTitle: "Simple API",
		},
		{
			name:          "valid OAS from HTTPS URL with insecure TLS",
			oasContent:    createSimpleOASContent(),
			statusCode:    http.StatusOK,
			insecureTLS:   true,
			expectErr:     false,
			oasPath:       "",
			expectedTitle: "Simple API",
		},
		{
			name:        "404 status code",
			oasContent:  createSimpleOASContent(),
			statusCode:  http.StatusNotFound,
			insecureTLS: false,
			expectErr:   true,
			oasPath:     "",
			errContains: "status code: 404",
		},
		{
			name:        "invalid JSON",
			oasContent:  `{ "invalid": "json"`,
			statusCode:  http.StatusOK,
			insecureTLS: false,
			expectErr:   true,
			oasPath:     "",
			errContains: "failed to parse OpenAPI spec",
		},
		{
			name:        "network error",
			oasContent:  createSimpleOASContent(),
			statusCode:  http.StatusOK,
			insecureTLS: false,
			expectErr:   true,
			oasPath:     "http://non-existent-server.com/openapi.json",
			errContains: "failed to fetch OpenAPI spec",
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

			ctx := context.Background()
			serveOpts := &server.ServeOptions{
				Name:        "trento-mcp-server",
				Version:     "1.0.0",
				OASPath:     []string{""},
				InsecureTLS: tt.insecureTLS,
			}

			// If oasPath is unset, use the test server url.
			if tt.oasPath == "" {
				serveOpts.OASPath[0] = testServer.URL + "/openapi.json"
			} else {
				serveOpts.OASPath[0] = tt.oasPath
			}

			oasDoc, err := server.LoadOpenAPISpecFromURL(ctx, serveOpts.OASPath[0], serveOpts)

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
