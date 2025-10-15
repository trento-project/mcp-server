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

func TestCheckAPIServiceHealth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		oasPath        string
		healthPath     string
		serverStatus   int
		skipFakeServer bool
		expectError    bool
		errorContains  string
	}{
		{
			name:         "API server healthy via OAS path",
			oasPath:      "dummy/api/all/openapi", // will be overridden by fake server
			healthPath:   "/api/healthz",
			serverStatus: http.StatusOK,
			expectError:  false,
		},
		{
			name:         "Wanda server healthy via OAS path",
			oasPath:      "dummy/wanda/api/all/openapi", // will be overridden by fake server
			healthPath:   "/wanda/api/healthz",
			serverStatus: http.StatusOK,
			expectError:  false,
		},
		{
			name:          "server returns 404",
			oasPath:       "dummy/api/all/openapi",
			healthPath:    "/api/healthz",
			serverStatus:  http.StatusNotFound,
			expectError:   true,
			errorContains: "returned a non-200 status code (404)",
		},
		{
			name:          "server returns 500",
			oasPath:       "dummy/wanda/api/all/openapi",
			healthPath:    "/wanda/api/healthz",
			serverStatus:  http.StatusInternalServerError,
			expectError:   true,
			errorContains: "returned a non-200 status code (500)",
		},
		{
			name:           "invalid OAS URL",
			oasPath:        "not-a-valid-url",
			healthPath:     "/api/healthz",
			skipFakeServer: true,
			expectError:    true,
			errorContains:  "unsupported protocol scheme",
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
				HealthAPIPath:         "/api/healthz",
			}

			var (
				testServer  *httptest.Server
				testOASPath string
				healthURL   string
			)

			// Set up the fake server, unless the test skips it

			if !tt.skipFakeServer {
				testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					assert.Equal(t, tt.healthPath, req.URL.Path)
					assert.True(t, strings.HasPrefix(req.Header.Get("User-Agent"), "test-server/1.0.0"))
					w.WriteHeader(tt.serverStatus)
				}))
				defer testServer.Close()

				// Build the OAS path based on the expected health path
				oasPathSuffix := "/api/all/openapi"
				if tt.healthPath == "/wanda/api/healthz" {
					oasPathSuffix = "/wanda/api/all/openapi"
				}

				testOASPath = testServer.URL + oasPathSuffix
				healthURL = testServer.URL + tt.healthPath
			} else {
				testOASPath = tt.oasPath
				healthURL = tt.oasPath // For invalid URLs, this will fail appropriately
			}

			// Execute the test
			err := server.CheckAPIServiceHealth(t.Context(), healthURL, testOASPath, serveOpts, http.DefaultClient)

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

func TestCreateOASPathHealthChecks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		serveOpts          *server.ServeOptions
		expectedCheckCount int
		expectedCheckNames []string
	}{
		{
			name: "explicit OAS paths",
			serveOpts: &server.ServeOptions{
				OASPath: []string{
					"http://example.com/api/all/openapi",
					"http://example.com/wanda/api/all/openapi",
				},
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedCheckCount: 2,
			expectedCheckNames: []string{"web-api", "wanda-api"},
		},
		{
			name: "autodiscovery paths with TrentoURL",
			serveOpts: &server.ServeOptions{
				TrentoURL: "http://trento.example.com",
				AutodiscoveryPaths: []string{
					"/api/all/openapi",
					"/wanda/api/all/openapi",
				},
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedCheckCount: 2,
			expectedCheckNames: []string{"web-api", "wanda-api"},
		},
		{
			name: "no OAS paths and no TrentoURL",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedCheckCount: 0,
			expectedCheckNames: []string{},
		},
		{
			name: "single OAS path",
			serveOpts: &server.ServeOptions{
				OASPath: []string{
					"http://example.com/api/all/openapi",
				},
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedCheckCount: 1,
			expectedCheckNames: []string{"web-api"},
		},
		{
			name: "repeated OAS paths - should create checks for each",
			serveOpts: &server.ServeOptions{
				OASPath: []string{
					"http://example.com/api/all/openapi",
					"http://example.com/api/all/openapi",
					"http://example.com/wanda/api/all/openapi",
				},
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedCheckCount: 3,
			expectedCheckNames: []string{"web-api", "web-api", "wanda-api"},
		},
		{
			name: "local file OAS paths only",
			serveOpts: &server.ServeOptions{
				OASPath: []string{
					"/tmp/openapi.json",
					"/home/user/specs/wanda-openapi.yaml",
				},
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedCheckCount: 0,
			expectedCheckNames: []string{},
		},
		{
			name: "mixed HTTP and local file OAS paths",
			serveOpts: &server.ServeOptions{
				OASPath: []string{
					"http://example.com/api/all/openapi",
					"/tmp/local-openapi.json",
					"http://example.com/wanda/api/all/openapi",
					"/etc/openapi/spec.yaml",
				},
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedCheckCount: 2,
			expectedCheckNames: []string{"web-api", "wanda-api"},
		},
		{
			name: "non-HTTP protocols - FTP",
			serveOpts: &server.ServeOptions{
				OASPath: []string{
					"ftp://ftp.example.com/api/all/openapi",
					"ftp://ftp.example.com/wanda/api/all/openapi",
				},
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedCheckCount: 2,
			expectedCheckNames: []string{"web-api", "wanda-api"},
		},
		{
			name: "mixed protocols - HTTP, HTTPS, FTP",
			serveOpts: &server.ServeOptions{
				OASPath: []string{
					"http://example.com/api/all/openapi",
					"https://secure.example.com/api/all/openapi",
					"ftp://ftp.example.com/wanda/api/all/openapi",
				},
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedCheckCount: 3,
			expectedCheckNames: []string{"web-api", "web-api", "wanda-api"},
		},
		{
			name: "file:// protocol paths",
			serveOpts: &server.ServeOptions{
				OASPath: []string{
					"file:///tmp/openapi.json",
					"file:///home/user/specs/openapi.yaml",
				},
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedCheckCount: 0, // file:// URLs don't have a host
			expectedCheckNames: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			httpClient := &http.Client{Timeout: 5 * time.Second}
			checks := server.CreateOASPathHealthChecks(tt.serveOpts, httpClient)

			assert.Len(t, checks, tt.expectedCheckCount)

			for i, check := range checks {
				if i < len(tt.expectedCheckNames) {
					assert.Equal(t, tt.expectedCheckNames[i], check.Name)
				}
			}
		})
	}
}

func TestCreateSingleOASHealthCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		oasPath       string
		serveOpts     *server.ServeOptions
		expectedName  string
		expectError   bool
		errorContains string
	}{
		{
			name:    "valid web API OAS path",
			oasPath: "http://example.com/api/all/openapi",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "web-api",
			expectError:  false,
		},
		{
			name:    "valid Wanda API OAS path",
			oasPath: "http://example.com/wanda/api/all/openapi",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "wanda-api",
			expectError:  false,
		},
		{
			name:    "invalid OAS path - not a URL",
			oasPath: "not-a-valid-url",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectError:   true,
			errorContains: "failed to extract host",
		},
		{
			name:    "OAS path without host",
			oasPath: "/just/a/path",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectError:   true,
			errorContains: "failed to extract host",
		},
		{
			name:    "custom health API path",
			oasPath: "http://example.com/api/all/openapi",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/custom/health",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "web-api",
			expectError:  false,
		},
		{
			name:    "HTTPS protocol",
			oasPath: "https://secure.example.com/api/all/openapi",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "web-api",
			expectError:  false,
		},
		{
			name:    "FTP protocol with host",
			oasPath: "ftp://ftp.example.com/api/all/openapi",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "web-api",
			expectError:  false,
		},
		{
			name:    "FTP protocol with wanda path",
			oasPath: "ftp://ftp.example.com/wanda/api/all/openapi",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "wanda-api",
			expectError:  false,
		},
		{
			name:    "local file path - no host",
			oasPath: "/tmp/openapi.json",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectError:   true,
			errorContains: "failed to extract host",
		},
		{
			name:    "local file path with wanda in name",
			oasPath: "/home/user/wanda/openapi.yaml",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectError:   true,
			errorContains: "failed to extract host",
		},
		{
			name:    "file:// protocol",
			oasPath: "file:///tmp/openapi.json",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectError:   true,
			errorContains: "failed to extract host",
		},
		{
			name:    "URL with port number",
			oasPath: "http://example.com:8080/api/all/openapi",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "web-api",
			expectError:  false,
		},
		{
			name:    "URL with port number and wanda path",
			oasPath: "http://example.com:4001/wanda/api/all/openapi",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "wanda-api",
			expectError:  false,
		},
		{
			name:    "URL with subdomain",
			oasPath: "http://api.subdomain.example.com/api/all/openapi",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "web-api",
			expectError:  false,
		},
		{
			name:    "empty OAS path",
			oasPath: "",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectError:   true,
			errorContains: "failed to extract host",
		},
		{
			name:    "URL with query parameters",
			oasPath: "http://example.com/api/all/openapi?version=1.0",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "web-api",
			expectError:  false,
		},
		{
			name:    "URL with fragment",
			oasPath: "http://example.com/wanda/api/all/openapi#section",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "wanda-api",
			expectError:  false,
		},
		{
			name:    "wanda in hostname, not in path",
			oasPath: "http://demo-wanda.deleteme.svc.cluster.local:4000/api/all/openapi",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "wanda-api",
			expectError:  false,
		},
		{
			name:    "wanda in hostname with different path",
			oasPath: "http://wanda.example.com/openapi.json",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "wanda-api",
			expectError:  false,
		},
		{
			name:    "wanda in subdomain",
			oasPath: "http://wanda.trento.example.com/api/v1/openapi",
			serveOpts: &server.ServeOptions{
				HealthAPIPath:         "/api/healthz",
				InsecureSkipTLSVerify: true,
			},
			expectedName: "wanda-api",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			httpClient := &http.Client{Timeout: 5 * time.Second}
			check, err := server.CreateSingleOASHealthCheck(tt.oasPath, tt.serveOpts, httpClient)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedName, check.Name)
				assert.NotNil(t, check.Check)
			}
		})
	}
}

func TestCheckMCPServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		serveOpts     *server.ServeOptions
		expectError   bool
		errorContains string
	}{
		{
			name: "streamable transport - connection failure expected",
			serveOpts: &server.ServeOptions{
				Port:      99999,
				Transport: utils.TransportStreamable,
				Version:   "1.0.0",
			},
			expectError:   true,
			errorContains: "MCP client failed to connect",
		},
		{
			name: "SSE transport - connection failure expected",
			serveOpts: &server.ServeOptions{
				Port:      99998,
				Transport: utils.TransportSSE,
				Version:   "1.0.0",
			},
			expectError:   true,
			errorContains: "MCP client failed to connect",
		},
		{
			name: "unknown transport type",
			serveOpts: &server.ServeOptions{
				Port:      5000,
				Transport: "invalid-transport",
				Version:   "1.0.0",
			},
			expectError:   true,
			errorContains: "unknown transport type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			err := server.CheckMCPServer(ctx, tt.serveOpts)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
