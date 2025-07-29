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
	// These tests manipulate a global resource (os.Stdout), so they cannot run in parallel.
	// Redirect stdout to a buffer
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	// Create logger with info level. This will write to our pipe.
	logger := utils.CreateLogger(0)

	// Log some messages
	logger.Info("info message")
	logger.Debug("debug message") // This should not be logged

	// Restore stdout and read from buffer
	err := w.Close()
	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)

	// Assertions
	logOutput := buf.String()
	assert.Contains(t, logOutput, "INFO info message")
	assert.NotContains(t, logOutput, "DEBUG debug message")
}

func TestParseLogLevel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		level    int
		expected slog.Level
	}{
		{"debug", -1, slog.LevelDebug},
		{"info", 0, slog.LevelInfo},
		{"warn", 1, slog.LevelWarn},
		{"error", 2, slog.LevelError},
		{"default for high number", 99, slog.LevelInfo},
		{"default for low number", -99, slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, utils.ParseLogLevel(tt.level))
		})
	}
}
