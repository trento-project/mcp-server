// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trento-project/mcp-server/cmd"
)

// A map of helper commands for TestMain to dispatch.
//
//nolint:gochecknoglobals
var helperCommands = map[string]func(){
	"main": main,
}

// TestMainExec is an integration test that runs the compiled binary.
// It helps ensure the main function is covered and the binary can start.
func TestMainExec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		args           []string
		expectErr      bool
		outputContains string
	}{
		{
			name:           "should show version with --version flag",
			args:           []string{"--version"},
			expectErr:      false,
			outputContains: cmd.Version(),
		},
		{
			name:           "should show help with --help flag",
			args:           []string{"--help"},
			expectErr:      false,
			outputContains: "trento-mcp-server",
		},
		{
			name:           "should return error for invalid flag",
			args:           []string{"--invalid-flag"},
			expectErr:      true,
			outputContains: "unknown flag: --invalid-flag",
		},
		{
			name:           "should return error for non-existent oas file",
			args:           []string{"--oasPath", "/tmp/non-existent-file.json"},
			expectErr:      true,
			outputContains: "failed to read the API spec",
		},
		{
			name:           "should return error for invalid transport",
			args:           []string{"--transport", "invalid"},
			expectErr:      true,
			outputContains: "invalid transport type",
		},
		{
			name:           "should return error for invalid port value",
			args:           []string{"--port", "not-a-number"},
			expectErr:      true,
			outputContains: "invalid argument",
		},
		{
			name:           "should return error for invalid verbosity value",
			args:           []string{"--verbosity", "not-a-number"},
			expectErr:      true,
			outputContains: "invalid argument",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmdArgs := append([]string{"main"}, tt.args...)
			command := exec.CommandContext(t.Context(), os.Args[0], cmdArgs...) //nolint:gosec
			command.Env = os.Environ()

			output, err := command.CombinedOutput()

			if tt.expectErr {
				require.Error(t, err, "Command should have failed")
			} else {
				require.NoError(t, err, "Command should exit cleanly. Output: %s", string(output))
			}

			assert.Contains(t, string(output), tt.outputContains)
		})
	}
}

// TestMain acts as a dispatcher. When the test binary is re-executed with a
// command-line argument, it runs the corresponding helper command and exits,
// instead of running tests. This allows us to test the `main` function itself.
func TestMain(_ *testing.M) {
	flag.Parse()
	args := flag.Args()

	if len(args) > 0 {
		if helper, ok := helperCommands[args[0]]; ok {
			// We are in the subprocess. Run the helper command.
			// We need to adjust os.Args for the cobra command to work correctly.
			os.Args = append([]string{os.Args[0]}, args[1:]...)

			helper()
		}
	}
}
