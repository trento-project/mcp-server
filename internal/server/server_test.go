// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

// Package server_test is the where the server logic is tested.
//
//nolint:lll
package server_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trento-project/mcp-server/internal/server"
	"github.com/trento-project/mcp-server/internal/utils"
)

// waitForShutdownSingle is a test helper that wraps a single server in a ServerGroup
// for compatibility with existing tests.
func waitForShutdownSingle(ctx context.Context, t *testing.T, srv utils.StoppableServer, serverErrChan <-chan error) error {
	t.Helper()

	serverGroup := utils.NewServerGroup()
	serverGroup.Add(srv)

	return server.WaitForShutdown(ctx, serverGroup, serverErrChan)
}

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

//nolint:paralleltest
func TestWaitForShutdown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		startFn         func(context.Context, *mcp.Server, string, string, chan<- error) (utils.StoppableServer, error)
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
			) (utils.StoppableServer, error) {
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
			) (utils.StoppableServer, error) {
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

				err := waitForShutdownSingle(ctx, t, mockServer, serverErrChan)

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
					waitErrChan <- waitForShutdownSingle(ctx, t, mockServer, serverErrChan)

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
				mcpSrv, port, addr := setupServerTest(ctx, t)
				headerName := "X-Test-API-Key"
				errChan := make(chan error, 1)

				httpServer, err := tt.startFn(ctx, mcpSrv, addr, headerName, errChan)
				require.NoError(t, err)
				require.NotNil(t, httpServer)

				waitErrChan := make(chan error, 1)

				go func() {
					waitErrChan <- waitForShutdownSingle(ctx, t, httpServer, errChan)

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
