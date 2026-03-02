// Copyright 2026 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"fmt"
	"net/url"
)

const (
	HttpScheme  = "http"
	HttpsScheme = "https"
)

// ValidateHTTPURL validates scheme and host constraints for outbound HTTP requests.
func ValidateHTTPURL(parsedURL *url.URL) error {
	if parsedURL == nil {
		return fmt.Errorf("invalid URL: missing URL")
	}

	if parsedURL.Scheme != HttpScheme && parsedURL.Scheme != HttpsScheme {
		return fmt.Errorf("invalid URL: unsupported protocol scheme %q", parsedURL.Scheme)
	}

	if parsedURL.Host == "" {
		return fmt.Errorf("invalid URL: missing host in %s", parsedURL.String())
	}

	return nil
}
