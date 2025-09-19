// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

//nolint:tparallel,paralleltest
package utils_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trento-project/mcp-server/internal/utils"
)

func TestCreateLogger(t *testing.T) {
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

// runCaptureTest is a helper function to execute CaptureLibraryLogs with a temporary logger
// and return the captured log output and any error.
func runCaptureTest(t *testing.T, level slog.Level, action func() error) (string, error) {
	t.Helper()

	// Save original stdout/stderr and logger to verify restoration
	originalStdout := os.Stdout
	originalStderr := os.Stderr
	originalLogger := slog.Default()

	defer func() {
		os.Stdout = originalStdout
		os.Stderr = originalStderr

		slog.SetDefault(originalLogger)
	}()

	// Setup a logger that writes to a buffer
	var logBuf bytes.Buffer

	handler := slog.NewTextHandler(&logBuf, &slog.HandlerOptions{
		Level: level,
		// Remove time for predictable output
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}

			return a
		},
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	// Call the function under test
	err := utils.CaptureLibraryLogs(context.Background(), action)

	// Verify stdout/stderr are restored
	assert.Equal(t, originalStdout, os.Stdout, "os.Stdout should be restored")
	assert.Equal(t, originalStderr, os.Stderr, "os.Stderr should be restored")

	return logBuf.String(), err
}

func TestCaptureLibraryLogs(t *testing.T) {
	tests := []struct {
		name            string
		action          func() error
		expectedErr     error
		expectedLogs    []string
		notExpectedLogs []string
		logLevel        slog.Level
	}{
		{
			name: "should capture unstructured output from stdout at DEBUG level",
			action: func() error {
				fmt.Println("hello from stdout") //nolint:forbidigo,revive

				return nil
			},
			expectedLogs: []string{
				`level=DEBUG msg="unstructured output from library" output="hello from stdout" source=openapi-mcp`,
			},
			logLevel: slog.LevelDebug,
		},
		{
			name: "should capture unstructured output from stderr at DEBUG level",
			action: func() error {
				_, err := fmt.Fprintln(os.Stderr, "hello from stderr") //nolint:forbidigo,revive

				return err
			},
			expectedLogs: []string{
				`level=DEBUG msg="unstructured output from library" output="hello from stderr" source=openapi-mcp`,
			},
			logLevel: slog.LevelDebug,
		},
		{
			name: "should parse and log [INFO] messages",
			action: func() error {
				fmt.Println("[INFO] this is an info message") //nolint:forbidigo,revive

				return nil
			},
			expectedLogs: []string{
				`level=INFO msg="this is an info message" source=openapi-mcp`,
			},
			logLevel: slog.LevelInfo,
		},
		{
			name: "should parse and log [WARN] messages",
			action: func() error {
				fmt.Println("[WARN] this is a warning") //nolint:forbidigo,revive

				return nil
			},
			expectedLogs: []string{
				`level=WARN msg="this is a warning" source=openapi-mcp`,
			},
			logLevel: slog.LevelWarn,
		},
		{
			name: "should parse and log [ERROR] messages",
			action: func() error {
				fmt.Println("[ERROR] this is an error") //nolint:forbidigo,revive

				return nil
			},
			expectedLogs: []string{
				`level=ERROR msg="this is an error" source=openapi-mcp`,
			},
			logLevel: slog.LevelError,
		},
		{
			name: "should handle mixed structured and unstructured output",
			action: func() error {
				fmt.Println("unstructured line")      //nolint:forbidigo,revive
				fmt.Println("[INFO] structured line") //nolint:forbidigo,revive

				return nil
			},
			expectedLogs: []string{
				`level=DEBUG msg="unstructured output from library" output="unstructured line" source=openapi-mcp`,
				`level=INFO msg="structured line" source=openapi-mcp`,
			},
			logLevel: slog.LevelDebug,
		},
		{
			name: "should return error from action",
			action: func() error {
				fmt.Println("about to fail") //nolint:forbidigo,revive

				return assert.AnError
			},
			expectedErr: assert.AnError,
			expectedLogs: []string{
				`level=DEBUG msg="unstructured output from library" output="about to fail" source=openapi-mcp`,
			},
			logLevel: slog.LevelDebug,
		},
		{
			name: "should not log debug messages if log level is info",
			action: func() error {
				fmt.Println("this is a debug message")        //nolint:forbidigo,revive
				fmt.Println("[INFO] this is an info message") //nolint:forbidigo,revive

				return nil
			},
			expectedLogs: []string{
				`level=INFO msg="this is an info message" source=openapi-mcp`,
			},
			notExpectedLogs: []string{
				`level=DEBUG`,
			},
			logLevel: slog.LevelInfo,
		},
		{
			name:     "should handle empty output",
			action:   func() error { return nil },
			logLevel: slog.LevelDebug,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logOutput, err := runCaptureTest(t, tt.logLevel, tt.action)

			// Assertions
			if tt.expectedErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err, "action should not return an error")
			}

			if len(tt.expectedLogs) == 0 && len(tt.notExpectedLogs) == 0 {
				assert.Empty(t, strings.TrimSpace(logOutput))
			}

			for _, expected := range tt.expectedLogs {
				assert.Contains(t, logOutput, expected)
			}

			for _, notExpected := range tt.notExpectedLogs {
				assert.NotContains(t, logOutput, notExpected)
			}
		})
	}
}
