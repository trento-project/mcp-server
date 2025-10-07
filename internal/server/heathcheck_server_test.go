// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

//nolint:lll
package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trento-project/mcp-server/internal/server"
	"github.com/trento-project/mcp-server/internal/utils"
)

func TestHealthCheckers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		checkerType  string
		serveOpts    *server.ServeOptions
		expectedCode int
		expectedBody string
	}{
		{
			name:        "liveness checker success",
			checkerType: "liveness",
			serveOpts: &server.ServeOptions{
				Name:      "test-server",
				Version:   "1.0.0",
				TrentoURL: "http://example.com",
				Port:      99999,
				Transport: utils.TransportStreamable,
			},
			expectedCode: http.StatusOK,
			expectedBody: "version",
		},
		{
			name:        "readiness checker with invalid MCP port",
			checkerType: "readiness",
			serveOpts: &server.ServeOptions{
				Name:      "test-server",
				Version:   "1.0.0",
				TrentoURL: "http://example.com",
				Port:      99999,
				Transport: utils.TransportStreamable,
			},
			expectedCode: http.StatusServiceUnavailable,
		},
		{
			name:        "readiness checker with SSE transport",
			checkerType: "readiness",
			serveOpts: &server.ServeOptions{
				Name:      "test-server",
				Version:   "1.0.0",
				TrentoURL: "http://example.com",
				Port:      99999,
				Transport: utils.TransportSSE,
			},
			expectedCode: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var handler http.Handler

			switch tt.checkerType {
			case "liveness":
				handler = server.CreateLivenessChecker(tt.serveOpts)
			case "readiness":
				handler = server.CreateReadinessChecker(tt.serveOpts)
			default:
				t.Fatalf("unknown checker type: %s", tt.checkerType)
			}

			req := httptest.NewRequest(http.MethodGet, "/"+tt.checkerType, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedCode, rec.Code)

			if tt.expectedBody != "" {
				assert.Contains(t, rec.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestCheckSingleAPIServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		serverResponse func(w http.ResponseWriter, r *http.Request)
		serverURL      string
		serverName     string
		expectError    bool
		errorContains  string
	}{
		{
			name: "successful health check",
			serverResponse: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodHead, r.Method)
				assert.Equal(t, "test-server/1.0.0", r.Header.Get("User-Agent"))
				w.WriteHeader(http.StatusOK)
			},
			serverName:  "test-api",
			expectError: false,
		},
		{
			name: "redirect response (should pass)",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusFound)
			},
			serverName:  "redirect-api",
			expectError: false,
		},
		{
			name: "auth challenge (should fail)",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			serverName:    "auth-api",
			expectError:   true,
			errorContains: "server error",
		},
		{
			name: "not found (should fail)",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			serverName:    "notfound-api",
			expectError:   true,
			errorContains: "server error",
		},
		{
			name: "server error (should fail)",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			serverName:    "error-api",
			expectError:   true,
			errorContains: "server error",
		},
		{
			name: "bad gateway (should fail)",
			serverResponse: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
			},
			serverName:    "gateway-api",
			expectError:   true,
			errorContains: "server error",
		},
		{
			name:          "empty URL (should fail)",
			serverURL:     "",
			serverName:    "empty-api",
			expectError:   true,
			errorContains: "server URL is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var testServer *httptest.Server

			serverURL := tt.serverURL

			if tt.serverResponse != nil {
				testServer = httptest.NewServer(http.HandlerFunc(tt.serverResponse))
				defer testServer.Close()

				serverURL = testServer.URL
			}

			serveOpts := &server.ServeOptions{
				Name:                  "test-server",
				Version:               "1.0.0",
				InsecureSkipTLSVerify: true,
			}

			err := server.CheckSingleAPIServer(t.Context(), serverURL, tt.serverName, serveOpts)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCheckAPIServerConnectivity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		trentoStatus   int
		emptyTrentoURL bool
		expectError    bool
		errorContains  string
	}{
		{
			name:         "trento server healthy",
			trentoStatus: http.StatusOK,
			expectError:  false,
		},
		{
			name:          "trento server returns 404",
			trentoStatus:  http.StatusNotFound,
			expectError:   true,
			errorContains: "trento-api",
		},
		{
			name:          "trento server error",
			trentoStatus:  http.StatusInternalServerError,
			expectError:   true,
			errorContains: "trento-api",
		},
		{
			name:           "empty trento URL",
			emptyTrentoURL: true,
			expectError:    true,
			errorContains:  "server URL is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Set up base serve options
			serveOpts := &server.ServeOptions{
				Name:                  "test-server",
				Version:               "1.0.0",
				InsecureSkipTLSVerify: true,
			}

			var trentoServer *httptest.Server

			// Set up Trento server
			if !tt.emptyTrentoURL {
				trentoServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tt.trentoStatus)
				}))
				defer trentoServer.Close()

				serveOpts.TrentoURL = trentoServer.URL
			}

			// Execute the test
			err := server.CheckAPIServerConnectivity(t.Context(), serveOpts)

			// Verify results
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCheckOASDocsConnectivity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		oasPaths      []string
		oasStatuses   []int
		expectError   bool
		errorContains []string
	}{
		{
			name:        "no OAS paths",
			oasPaths:    []string{},
			expectError: false,
		},
		{
			name:        "only local OAS files",
			oasPaths:    []string{"local-file.json", "another-file.yaml"},
			expectError: false,
		},
		{
			name:        "single remote OAS server healthy",
			oasPaths:    []string{"http://remote-oas.com/docs"},
			oasStatuses: []int{http.StatusOK},
			expectError: false,
		},
		{
			name:          "single remote OAS server error",
			oasPaths:      []string{"http://remote-oas.com/docs"},
			oasStatuses:   []int{http.StatusInternalServerError},
			expectError:   true,
			errorContains: []string{"oas-server"},
		},
		{
			name:        "multiple remote OAS servers healthy",
			oasPaths:    []string{"http://oas1.com/docs", "http://oas2.com/docs"},
			oasStatuses: []int{http.StatusOK, http.StatusAccepted},
			expectError: false,
		},
		{
			name:          "multiple remote OAS servers with one error",
			oasPaths:      []string{"http://oas1.com/docs", "http://oas2.com/docs"},
			oasStatuses:   []int{http.StatusOK, http.StatusInternalServerError},
			expectError:   true,
			errorContains: []string{"oas-server"},
		},
		{
			name:          "multiple remote OAS servers all error",
			oasPaths:      []string{"http://oas1.com/docs", "http://oas2.com/docs"},
			oasStatuses:   []int{http.StatusNotFound, http.StatusBadGateway},
			expectError:   true,
			errorContains: []string{"oas-server"},
		},
		{
			name:        "mixed local and remote OAS paths - remote healthy",
			oasPaths:    []string{"local-file.json", "http://remote-oas.com/docs"},
			oasStatuses: []int{http.StatusOK},
			expectError: false,
		},
		{
			name:          "mixed local and remote OAS paths - remote error",
			oasPaths:      []string{"local-file.json", "http://remote-oas.com/docs"},
			oasStatuses:   []int{http.StatusInternalServerError},
			expectError:   true,
			errorContains: []string{"oas-server"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			serveOpts := &server.ServeOptions{
				Name:                  "test-server",
				Version:               "1.0.0",
				InsecureSkipTLSVerify: true,
			}

			var (
				servers     []*httptest.Server
				remotePaths []string
			)

			// Set up test servers for remote URLs
			statusIndex := 0

			for _, path := range tt.oasPaths {
				if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(tt.oasStatuses[statusIndex])
						statusIndex++
					}))
					servers = append(servers, server)
					remotePaths = append(remotePaths, server.URL)
				} else {
					remotePaths = append(remotePaths, path)
				}
			}

			serveOpts.OASPath = remotePaths

			// Cleanup servers
			defer func() {
				for _, s := range servers {
					s.Close()
				}
			}()

			// Execute the test
			err := server.CheckOASDocsConnectivity(t.Context(), serveOpts)

			// Verify results
			if tt.expectError {
				require.Error(t, err)

				for _, expectedErr := range tt.errorContains {
					assert.Contains(t, err.Error(), expectedErr)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestStartHealthServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		healthPort  int
		mcpPort     int
		transport   utils.TransportType
		expectError bool
	}{
		{
			name:       "successful server start with streamable transport",
			healthPort: 0, // Use any available port
			mcpPort:    8080,
			transport:  utils.TransportStreamable,
		},
		{
			name:       "successful server start with SSE transport",
			healthPort: 0,
			mcpPort:    8081,
			transport:  utils.TransportSSE,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			errChan := make(chan error, 1)

			serveOpts := &server.ServeOptions{
				Name:      "test-server",
				Version:   "1.0.0",
				TrentoURL: "http://example.com",
			}

			// Start health server
			healthServer := server.StartHealthServer(t.Context(), serveOpts, errChan)
			require.NotNil(t, healthServer)

			// Clean up
			shutdownCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			err := healthServer.Shutdown(shutdownCtx)
			require.NoError(t, err)

			// Verify no errors were sent to the channel
			select {
			case err := <-errChan:
				t.Fatalf("unexpected error from health server: %v", err)
			default:
				// Expected: no errors
			}
		})
	}
}
