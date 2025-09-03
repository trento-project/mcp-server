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
func (*TransportType) Type() string {
	return "string"
}

// LogLevel represents the logging level.
type LogLevel string

const (
	// LogLevelDebug represents debug level logging.
	LogLevelDebug LogLevel = "debug"

	// LogLevelInfo represents info level logging.
	LogLevelInfo LogLevel = "info"

	// LogLevelWarning represents warning level logging.
	LogLevelWarning LogLevel = "warning"

	// LogLevelError represents error level logging.
	LogLevelError LogLevel = "error"
)

// String returns the string representation of the LogLevel.
func (l *LogLevel) String() string {
	return string(*l)
}

// Set sets the LogLevel from a string.
func (l *LogLevel) Set(v string) error {
	switch v {
	case "debug", "info", "warning", "error":
		*l = LogLevel(v)

		return nil
	default:
		return fmt.Errorf("invalid log level: %s, must be one of 'debug', 'info', 'warning', or 'error'", v)
	}
}

// Type returns the type of the LogLevel for pflag.
func (*LogLevel) Type() string {
	return "string"
}
