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

func TestCheckAPIServerConnectivity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		trentoStatus   int
		trentoURL      string
		skipFakeServer bool
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
			errorContains: "returned a non-200 status code (404)",
		},
		{
			name:          "trento server error",
			trentoStatus:  http.StatusInternalServerError,
			expectError:   true,
			errorContains: "returned a non-200 status code (500)",
		},
		{
			name:           "empty trento URL",
			trentoURL:      "",
			skipFakeServer: true,
			expectError:    true,
			errorContains:  "the Trento server URL is empty",
		},
		{
			name:           "trento URL with trailing slashes",
			trentoURL:      "http://trento.example.com/",
			skipFakeServer: true,
			expectError:    true,
			errorContains:  `http://trento.example.com/api/healthz`,
		},
		{
			name:           "trento URL without trailing slashes",
			trentoURL:      "http://trento.example.com",
			skipFakeServer: true,
			expectError:    true,
			errorContains:  `Get "http://trento.example.com/api/healthz`,
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
				TrentoURL:             tt.trentoURL,
			}

			var trentoServer *httptest.Server

			// Set up the fake Trento server, unless the test skips it.
			if !tt.skipFakeServer {
				trentoServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					assert.Equal(t, "/api/healthz", req.URL.Path)
					assert.True(t, strings.HasPrefix(req.Header.Get("User-Agent"), "test-server/1.0.0"))
					w.WriteHeader(tt.trentoStatus)
				}))
				defer trentoServer.Close()

				serveOpts.TrentoURL = trentoServer.URL
			}

			// Execute the test
			err := server.CheckAPIServerConnectivity(t.Context(), serveOpts, http.DefaultClient)

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
			// Expected: no errors
			default:
			}
		})
	}
}
