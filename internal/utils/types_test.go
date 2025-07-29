// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
			var tt utils.TransportType
			err := tt.Set(tc.value)

			if tc.expectErr {
				assert.Error(t, err)
				assert.Equal(t, utils.TransportType(""), tt) // Ensure value is unchanged on error
			} else {
				assert.NoError(t, err)
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
