// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trento-project/mcp-server/internal/utils"
)

func TestCreateLogger(t *testing.T) {
	t.Parallel()

	// These tests manipulate a global resource (os.Stdout), so they cannot run in parallel.
	// Redirect stdout to a buffer
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	defer func() { os.Stdout = oldStdout }()

	// Create logger with info level. This will write to our pipe.
	logger := utils.CreateLogger(utils.LogLevelInfo)

	// Log some messages with attributes
	logger.InfoContext(t.Context(), "info message", "key", "value")
	logger.DebugContext(t.Context(), "debug message") // This should not be logged

	// Restore stdout and read from buffer
	err := w.Close()
	require.NoError(t, err)

	var buf bytes.Buffer

	_, err = io.Copy(&buf, r)
	require.NoError(t, err)

	// Assertions
	logOutput := buf.String()
	assert.Contains(t, logOutput, "INFO info message")
	assert.Contains(t, logOutput, "key=value")
	assert.NotContains(t, logOutput, "DEBUG debug message")
}

func TestParseLogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		level    utils.LogLevel
		expected slog.Level
	}{
		{"debug", utils.LogLevelDebug, slog.LevelDebug},
		{"info", utils.LogLevelInfo, slog.LevelInfo},
		{"warning", utils.LogLevelWarning, slog.LevelWarn},
		{"error", utils.LogLevelError, slog.LevelError},
		{"default for invalid", "invalid", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, utils.ParseLogLevel(tt.level))
		})
	}
}

func TestDefaultTextHandlerMethods(t *testing.T) {
	// This test is primarily for code coverage of the unexported DefaultTextHandler's
	// WithAttrs and WithGroup methods. These methods are currently no-ops but are
	// called by the slog.Logger's corresponding methods.
	t.Parallel()

	logger := utils.CreateLogger(utils.LogLevelInfo)

	// Calling these methods is sufficient to cover the no-op implementations.
	_ = logger.With("key", "value")
	_ = logger.WithGroup("my_group")
}

func TestLogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		expectErr bool
		expected  utils.LogLevel
	}{
		{"valid debug", "debug", false, utils.LogLevelDebug},
		{"valid info", "info", false, utils.LogLevelInfo},
		{"valid warning", "warning", false, utils.LogLevelWarning},
		{"valid error", "error", false, utils.LogLevelError},
		{"invalid level", "invalid", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var level utils.LogLevel
			err := level.Set(tt.input)

			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid log level")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, level)
				assert.Equal(t, tt.input, level.String())
				assert.Equal(t, "string", level.Type())
			}
		})
	}
}
