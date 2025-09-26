// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

// Package utils implements extra functionality like logging.
package utils //nolint:revive

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// CreateLogger creates and configures an slog logger.
func CreateLogger(logLevel LogLevel) *slog.Logger {
	return slog.New(NewDefaultTextHandler(
		os.Stdout,
		ParseLogLevel(logLevel),
	))
}

// ParseLogLevel converts a LogLevel representation to slog.Level.
//
//nolint:revive
func ParseLogLevel(logLevel LogLevel) slog.Level {
	switch logLevel {
	case LogLevelDebug:
		return slog.LevelDebug
	case LogLevelInfo:
		return slog.LevelInfo
	case LogLevelWarning:
		return slog.LevelWarn
	case LogLevelError:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// CaptureLibraryLogs captures stdout and stderr from a function call and redirects it to the application's logger.
// This is useful for libraries that log directly to stdout or stderr.
func CaptureLibraryLogs(ctx context.Context, action func() error) error {
	originalStdout := os.Stdout
	originalStderr := os.Stderr

	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe for output capture: %w", err)
	}

	os.Stdout = w
	os.Stderr = w

	// Restore stdout and stderr when we're done
	defer func() {
		os.Stdout = originalStdout
		os.Stderr = originalStderr
	}()

	// Channel to receive the error from the action
	actionErrChan := make(chan error, 1)

	go func() {
		actionErrChan <- action()
	}()

	// Goroutine to read from the pipe and log
	var wg sync.WaitGroup

	wg.Go(func() {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()

			switch {
			case strings.HasPrefix(line, "[WARN]"):
				slog.WarnContext(ctx, strings.TrimSpace(strings.TrimPrefix(line, "[WARN]")), "source", "openapi-mcp")
			case strings.HasPrefix(line, "[ERROR]"):
				slog.ErrorContext(ctx, strings.TrimSpace(strings.TrimPrefix(line, "[ERROR]")), "source", "openapi-mcp")
			case strings.HasPrefix(line, "[INFO]"):
				slog.InfoContext(ctx, strings.TrimSpace(strings.TrimPrefix(line, "[INFO]")), "source", "openapi-mcp")
			default:
				// Also capture unstructured output from stdout (e.g. schema dumps)
				slog.DebugContext(ctx, "unstructured output from library", "output", line, "source", "openapi-mcp")
			}
		}
	})

	// Wait for the action to complete
	actionErr := <-actionErrChan

	// Close the writer to unblock the scanner and signal the end of output
	closeErr := w.Close()

	// Wait for the logging goroutine to finish processing all lines
	wg.Wait()

	return errors.Join(actionErr, closeErr)
}

// TODO(agamez): use it as a dependency,
// once available at https://pkg.go.dev/github.com/trento-project/agent@v0.0.0-20250417081934-5aa03367504a/pkg/utils

// DefaultTextHandler is a type temporarily extracted
// from https://github.com/trento-project/agent/blob/main/pkg/utils/log.go.
type DefaultTextHandler struct {
	w     io.Writer
	level slog.Level
}

// NewDefaultTextHandler is a function temporarily extracted
// from https://github.com/trento-project/agent/blob/main/pkg/utils/log.go.
func NewDefaultTextHandler(w io.Writer, level slog.Level) *DefaultTextHandler {
	return &DefaultTextHandler{w: w, level: level}
}

// Enabled is a function temporarily extracted
// from https://github.com/trento-project/agent/blob/main/pkg/utils/log.go.
func (h *DefaultTextHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle is a function temporarily extracted
// from https://github.com/trento-project/agent/blob/main/pkg/utils/log.go.
func (h *DefaultTextHandler) Handle(_ context.Context, r slog.Record) error {
	// Format time as YYYY-MM-DD hh:mm:ss
	timeStr := r.Time.Format("2006-01-02 15:04:05")

	// Map slog.Level to uppercase string (WARNING for WARN, etc.)
	levelStr := r.Level.String()

	// Start building the log line
	line := fmt.Sprintf("%s %s %s", timeStr, levelStr, r.Message)

	// Append all key-value attributes
	r.Attrs(func(attr slog.Attr) bool {
		line += fmt.Sprintf(" %s=%v", attr.Key, attr.Value.Any())

		return true
	})

	// Write the line
	_, err := fmt.Fprintln(h.w, line)

	return err
}

// WithAttrs is a function temporarily extracted
// from https://github.com/trento-project/agent/blob/main/pkg/utils/log.go.
func (h *DefaultTextHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	// do nothing, all attributes are processed in Handle
	return h
}

// WithGroup is a function temporarily extracted
// from https://github.com/trento-project/agent/blob/main/pkg/utils/log.go.
func (h *DefaultTextHandler) WithGroup(_ string) slog.Handler {
	// TODO: handle group
	return h
}
