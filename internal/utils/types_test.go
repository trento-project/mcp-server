// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
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
