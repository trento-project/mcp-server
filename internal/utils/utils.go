// Copyright 2026 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package utils //nolint:revive

import (
	"fmt"
	"net/url"
)

const (
	// HTTPScheme is the HTTPS scheme
	HTTPScheme = "http"
	// HTTPSScheme is the HTTP scheme
	HTTPSScheme = "https"
)

// ValidateHTTPURL validates scheme and host constraints for outbound HTTP requests.
func ValidateHTTPURL(parsedURL *url.URL) error {
	if parsedURL == nil {
		return fmt.Errorf("invalid URL: missing URL")
	}

	if parsedURL.Scheme != HTTPScheme && parsedURL.Scheme != HTTPSScheme {
		return fmt.Errorf("invalid URL: unsupported protocol scheme %q", parsedURL.Scheme)
	}

	if parsedURL.Host == "" {
		return fmt.Errorf("invalid URL: missing host in %s", parsedURL.String())
	}

	return nil
}
