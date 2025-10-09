// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trento-project/mcp-server/internal/utils"
)

func TestTransportType_String(t *testing.T) {
	t.Parallel()

	var tt utils.TransportType = "test"

	assert.Equal(t, "test", tt.String())
}

func TestTransportType_Set(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		value       string
		expectErr   bool
		expectedVal utils.TransportType
	}{
		{
			name:        "set sse",
			value:       "sse",
			expectErr:   false,
			expectedVal: utils.TransportSSE,
		},
		{
			name:        "set streamable",
			value:       "streamable",
			expectErr:   false,
			expectedVal: utils.TransportStreamable,
		},
		{
			name:        "set invalid",
			value:       "invalid",
			expectErr:   true,
			expectedVal: "", // The value should not change
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var tt utils.TransportType

			err := tt.Set(tc.value)

			if tc.expectErr {
				require.Error(t, err)
				assert.Equal(t, utils.TransportType(""), tt) // Ensure value is unchanged on error
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedVal, tt)
			}
		})
	}
}

func TestTransportType_Type(t *testing.T) {
	t.Parallel()

	var tt utils.TransportType

	assert.Equal(t, "string", tt.Type())
}

func TestLogLevel_String(t *testing.T) {
	t.Parallel()

	var ll utils.LogLevel = "test"

	assert.Equal(t, "test", ll.String())
}

func TestLogLevel_Set(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		value       string
		expectErr   bool
		expectedVal utils.LogLevel
	}{
		{
			name:        "set debug",
			value:       "debug",
			expectErr:   false,
			expectedVal: utils.LogLevelDebug,
		},
		{
			name:        "set info",
			value:       "info",
			expectErr:   false,
			expectedVal: utils.LogLevelInfo,
		},
		{
			name:        "set warning",
			value:       "warning",
			expectErr:   false,
			expectedVal: utils.LogLevelWarning,
		},
		{
			name:        "set error",
			value:       "error",
			expectErr:   false,
			expectedVal: utils.LogLevelError,
		},
		{
			name:        "set invalid",
			value:       "invalid",
			expectErr:   true,
			expectedVal: "", // The value should not change
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var ll utils.LogLevel

			err := ll.Set(tc.value)

			if tc.expectErr {
				require.Error(t, err)
				assert.Equal(t, utils.LogLevel(""), ll) // Ensure value is unchanged on error
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedVal, ll)
			}
		})
	}
}

func TestLogLevel_Type(t *testing.T) {
	t.Parallel()

	var ll utils.LogLevel

	assert.Equal(t, "string", ll.Type())
}

func TestFlagType_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		flagType utils.FlagType
		expected string
	}{
		{
			name:     "FlagTypeInt",
			flagType: utils.FlagTypeInt,
			expected: "int",
		},
		{
			name:     "FlagTypeString",
			flagType: utils.FlagTypeString,
			expected: "string",
		},
		{
			name:     "FlagTypeStringSlice",
			flagType: utils.FlagTypeStringSlice,
			expected: "stringSlice",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, tc.flagType.String())
		})
	}
}

func TestFlagType_Constants(t *testing.T) {
	t.Parallel()

	// Test that constants have expected values
	assert.Equal(t, utils.FlagTypeInt, utils.FlagType("int"))
	assert.Equal(t, utils.FlagTypeString, utils.FlagType("string"))
	assert.Equal(t, utils.FlagTypeStringSlice, utils.FlagType("stringSlice"))

	// Test that all constants are distinct
	flagTypes := []utils.FlagType{
		utils.FlagTypeInt,
		utils.FlagTypeString,
		utils.FlagTypeStringSlice,
	}

	for i := range flagTypes {
		for j := i + 1; j < len(flagTypes); j++ {
			assert.NotEqual(t, flagTypes[i], flagTypes[j], "FlagType constants should be unique")
		}
	}
}

// mockStoppableServer is a mock implementation for testing ServerGroup.
type mockStoppableServer struct {
	shutdownErr    error
	shutdownCalled bool
	shutdownFunc   func(ctx context.Context) error
}

func (m *mockStoppableServer) Shutdown(ctx context.Context) error {
	m.shutdownCalled = true
	if m.shutdownFunc != nil {
		return m.shutdownFunc(ctx)
	}

	return m.shutdownErr
}

func TestNewServerGroup(t *testing.T) {
	t.Parallel()

	sg := utils.NewServerGroup()

	assert.NotNil(t, sg)

	err := sg.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestServerGroup_Add(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		serverCount int
		description string
	}{
		{
			name:        "add single server",
			serverCount: 1,
			description: "should add one server and shutdown successfully",
		},
		{
			name:        "add multiple servers",
			serverCount: 5,
			description: "should add multiple servers and shutdown all",
		},
		{
			name:        "add many servers",
			serverCount: 20,
			description: "should handle many servers efficiently",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sg := utils.NewServerGroup()
			servers := make([]*mockStoppableServer, tt.serverCount)

			// Create and add servers
			for i := range tt.serverCount {
				servers[i] = &mockStoppableServer{}
				sg.Add(servers[i])
			}

			// Test shutdown to verify all servers were added
			err := sg.Shutdown(context.Background())
			require.NoError(t, err, tt.description)

			// Verify all servers were shutdown
			for i, server := range servers {
				assert.True(t, server.shutdownCalled, "server %d should have been shutdown", i)
			}
		})
	}
}

func TestServerGroup_Shutdown(t *testing.T) {
	t.Parallel()

	// Predefined errors for consistent comparison
	var (
		err1 = errors.New("error1")
		err2 = errors.New("error2")
		err3 = errors.New("error3")
	)

	tests := []struct {
		name           string
		servers        []*mockStoppableServer
		expectErr      bool
		expectedErrors []error
		description    string
	}{
		{
			name:        "empty group",
			servers:     []*mockStoppableServer{},
			expectErr:   false,
			description: "shutdown should succeed with no servers",
		},
		{
			name: "successful shutdown of multiple servers",
			servers: []*mockStoppableServer{
				{},
				{},
				{},
			},
			expectErr:   false,
			description: "all servers should shutdown successfully",
		},
		{
			name: "single server with error",
			servers: []*mockStoppableServer{
				{},
				{shutdownErr: err2},
				{},
			},
			expectErr:      true,
			expectedErrors: []error{err2},
			description:    "should return the single error",
		},
		{
			name: "multiple servers with errors",
			servers: []*mockStoppableServer{
				{shutdownErr: err1},
				{},
				{shutdownErr: err3},
			},
			expectErr:      true,
			expectedErrors: []error{err1, err3},
			description:    "should return joined errors",
		},
		{
			name: "all servers fail",
			servers: []*mockStoppableServer{
				{shutdownErr: err1},
				{shutdownErr: err2},
				{shutdownErr: err3},
			},
			expectErr:      true,
			expectedErrors: []error{err1, err2, err3},
			description:    "should return all errors joined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sg := utils.NewServerGroup()

			// Add servers to group
			for _, server := range tt.servers {
				sg.Add(server)
			}

			// Execute shutdown
			err := sg.Shutdown(context.Background())

			// Verify error expectation
			if tt.expectErr {
				require.Error(t, err, tt.description)
				// Check that all expected errors are present in the joined error
				for _, expectedErr := range tt.expectedErrors {
					require.ErrorIs(t, err, expectedErr, "expected error should be present in joined error")
				}
			} else {
				require.NoError(t, err, tt.description)
			}

			// Verify all servers had their Shutdown method called
			for i, server := range tt.servers {
				assert.True(t, server.shutdownCalled, "server %d should have been called for shutdown", i)
			}
		})
	}
}
