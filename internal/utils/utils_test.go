// SPDX-FileCopyrightText: SUSE LLC
// SPDX-License-Identifier: Apache-2.0

// Copyright 2026 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trento-project/mcp-server/internal/utils"
)

func TestValidateHTTPURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		url         string
		expectErr   bool
		errContains string
	}{
		{
			name:      "valid HTTP URL",
			url:       "http://example.com",
			expectErr: false,
		},
		{
			name:      "valid HTTPS URL",
			url:       "https://example.com",
			expectErr: false,
		},
		{
			name:        "invalid URL",
			url:         "ftp://example.com",
			expectErr:   true,
			errContains: "unsupported protocol scheme",
		},
		{
			name:        "missing host",
			url:         "http://",
			expectErr:   true,
			errContains: "missing host",
		},
		{
			name:        "nil URL",
			url:         "",
			expectErr:   true,
			errContains: "missing URL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var parsedURL *url.URL
			var err error

			if tc.url != "" {
				parsedURL, err = url.Parse(tc.url)
				require.NoError(t, err)
			}

			err = utils.ValidateHTTPURL(parsedURL)

			if tc.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
