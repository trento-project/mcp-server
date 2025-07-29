// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package utils //nolint:revive

import "fmt"

// TransportType is an enum for the available transport types.
type TransportType string

const (
	// TransportSSE uses Server-Sent Events.
	TransportSSE TransportType = "sse"

	// TransportStreamable uses streamable HTTP.
	TransportStreamable TransportType = "streamable"
)

// String returns the string representation of the TransportType.
func (t *TransportType) String() string {
	return string(*t)
}

// Set sets the TransportType from a string.
func (t *TransportType) Set(v string) error {
	switch v {
	case "sse", "streamable":
		*t = TransportType(v)
		return nil
	default:
		return fmt.Errorf("invalid transport type: %s, must be one of 'sse' or 'streamable'", v)
	}
}

// Type returns the type of the TransportType for pflag.
func (t *TransportType) Type() string {
	return "string"
}
