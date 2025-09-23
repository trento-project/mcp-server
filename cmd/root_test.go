// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package cmd_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trento-project/mcp-server/cmd"
	"github.com/trento-project/mcp-server/internal/server"
	"github.com/trento-project/mcp-server/internal/utils"
)

//nolint:paralleltest
func TestParseFlagsCorrect(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expConf     server.ServeOptions
		errExpected bool
	}{
		{
			name: "all arguments are captured",
			args: []string{
				"--port", "9090",
				"--oas-path", "/tmp/api.json",
				"--transport", "sse",
				"--trento-url", "http://trento.example.com",
				"--header-name", "X-My-Header",
				"--tag-filter", "A,B",
				"--verbosity", "debug",
				"--insecure-tls",
			},
			expConf: server.ServeOptions{
				Port:             9090,
				OASPath:          "/tmp/api.json",
				Transport:        utils.TransportSSE,
				TrentoURL:        "http://trento.example.com",
				TrentoHeaderName: "X-My-Header",
				TagFilter:        []string{"A", "B"},
				InsecureTLS:      true,
			},
			errExpected: false,
		},
		{
			name: "default values",
			args: []string{},
			expConf: server.ServeOptions{
				Port:             5000,
				OASPath:          "./api/openapi.json",
				Transport:        utils.TransportStreamable,
				TrentoURL:        "https://demo.trento-project.io",
				TrentoHeaderName: "X-TRENTO-MCP-APIKEY",
				TagFilter:        []string{},
			},
			errExpected: false,
		},
		{
			name: "invalid transport",
			args: []string{"--transport", "invalid-transport"},
			expConf: server.ServeOptions{
				Port:             5000,
				OASPath:          "./api/openapi.json",
				Transport:        "invalid-transport",
				TrentoURL:        "https://demo.trento-project.io",
				TrentoHeaderName: "X-TRENTO-MCP-APIKEY",
				TagFilter:        []string{},
			},
			errExpected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Do not run in parallel because they modify a global variable (serveOpts)
			b := bytes.NewBufferString("")
			command := cmd.NewRootCmd()
			// We only want to test flags, not the server execution
			command.RunE = func(_ *cobra.Command, _ []string) error { return nil }
			command.SetOut(b)
			command.SetErr(b)
			cmd.SetFlags(command)
			command.SetArgs(tt.args)
			err := command.Execute()

			if !tt.errExpected {
				require.NoError(t, err)

				opts := cmd.ServeOpts()
				// Name and Version are set automatically.
				tt.expConf.Name = opts.Name
				tt.expConf.Version = opts.Version
				assert.Equal(t, tt.expConf, opts)
			} else {
				require.Error(t, err)
			}
		})
	}
}

//nolint:paralleltest
func TestInitLogger(t *testing.T) {
	tests := []struct {
		name        string
		verbosity   string
		errExpected bool
	}{
		{"valid verbosity debug", "debug", false},
		{"valid verbosity info", "info", false},
		{"valid verbosity warn", "warn", false},
		{"valid verbosity warning", "warning", false},
		{"valid verbosity error", "error", false},
		{"invalid verbosity", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			defer viper.Reset()

			rootCmd := cmd.NewRootCmd()
			// We only want to test flags, not the server execution
			rootCmd.RunE = func(_ *cobra.Command, _ []string) error { return nil }
			cmd.SetFlags(rootCmd)

			// Set verbosity through viper, which is then read by ConfigureCLI
			viper.Set("verbosity", tt.verbosity)

			err := cmd.ConfigureCLI(rootCmd, []string{})
			if tt.errExpected {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				err = cmd.InitLogger()
				require.NoError(t, err)
			}
		})
	}
}

//nolint:paralleltest
func TestConfigureCLI(t *testing.T) {
	// Do not run in parallel as it modifies global state
	tests := []struct {
		name          string
		viperSettings map[string]any
		envVars       map[string]string
		expected      server.ServeOptions
	}{
		{
			name: "custom configuration values",
			viperSettings: map[string]any{
				"port":             1234,
				"oasPath":          "/tmp/oas.json",
				"transport":        "sse",
				"trentoURL":        "http://trento.test",
				"trentoHeaderName": "X-Test-Header",
				"tagFilter":        []string{"C", "D"},
			},
			expected: server.ServeOptions{
				Port:             1234,
				OASPath:          "/tmp/oas.json",
				Transport:        utils.TransportSSE,
				TrentoURL:        "http://trento.test",
				TrentoHeaderName: "X-Test-Header",
				TagFilter:        []string{"C", "D"},
			},
		},
		{
			name:          "default values",
			viperSettings: map[string]any{},
			envVars:       map[string]string{},
			expected: server.ServeOptions{
				Port:             5000,
				OASPath:          "./api/openapi.json",
				Transport:        utils.TransportStreamable,
				TrentoURL:        "https://demo.trento-project.io",
				TrentoHeaderName: "X-TRENTO-MCP-APIKEY",
				TagFilter:        []string{},
			},
		},
		{
			name: "environment variables",
			envVars: map[string]string{
				"TRENTO_MCP_PORT":             "8888",
				"TRENTO_MCP_OASPATH":          "/env/oas.json",
				"TRENTO_MCP_TRANSPORT":        "streamable",
				"TRENTO_MCP_TRENTOURL":        "https://env.trento.io",
				"TRENTO_MCP_TRENTOHEADERNAME": "X-Env-Header",
				"TRENTO_MCP_TAGFILTER":        "X,Y",
				"TRENTO_MCP_VERBOSITY":        "info",
			},
			expected: server.ServeOptions{
				Port:             8888,
				OASPath:          "/env/oas.json",
				Transport:        utils.TransportStreamable,
				TrentoURL:        "https://env.trento.io",
				TrentoHeaderName: "X-Env-Header",
				TagFilter:        []string{"X", "Y"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			defer viper.Reset()

			// Set environment variables
			for key, val := range tt.envVars {
				t.Setenv(key, val)
			}

			rootCmd := cmd.NewRootCmd()
			rootCmd.RunE = func(_ *cobra.Command, _ []string) error { return nil }
			cmd.SetFlags(rootCmd)

			// Set values in viper
			for key, val := range tt.viperSettings {
				viper.Set(key, val)
			}

			err := cmd.ConfigureCLI(rootCmd, []string{})
			require.NoError(t, err)

			opts := cmd.ServeOpts()

			// Name and Version are set automatically.
			tt.expected.Name = opts.Name
			tt.expected.Version = opts.Version

			assert.Equal(t, tt.expected, opts)
		})
	}
}

//nolint:paralleltest
func TestReadConfigFile(t *testing.T) {
	tests := []struct {
		name          string
		configContent string
		setConfigFile bool
		configFile    string
		expected      map[string]any
	}{
		{
			name:          "single value",
			configContent: "port: 1234",
			setConfigFile: true,
			expected:      map[string]any{"port": 1234},
		},
		{
			name: "all keys set",
			configContent: `port: 9999
oas-path: /custom/api.json
transport: streamable
trento-url: https://custom.trento.io
header-name: X-Custom-Header
tag-filter:
  - tag1
  - tag2
verbosity: info`,
			setConfigFile: true,
			expected: map[string]any{
				"port":        9999,
				"oas-path":    "/custom/api.json",
				"transport":   "streamable",
				"trento-url":  "https://custom.trento.io",
				"header-name": "X-Custom-Header",
				"tag-filter":  []any{"tag1", "tag2"},
				"verbosity":   "info",
			},
		},
		{
			name:          "empty config",
			configContent: "",
			setConfigFile: true,
			expected:      map[string]any{},
		},
		{
			name:          "non-existent config file",
			setConfigFile: true,
			configFile:    "/non/existent/config.yaml",
			expected:      map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			defer viper.Reset()

			if tt.setConfigFile {
				if tt.configFile != "" {
					viper.SetConfigFile(tt.configFile)
				} else {
					tmpFile, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
					require.NoError(t, err)

					if tt.configContent != "" {
						_, err = tmpFile.WriteString(tt.configContent)
						require.NoError(t, err)
					}

					err = tmpFile.Close()
					require.NoError(t, err)

					viper.SetConfigFile(tmpFile.Name())
				}
			}

			err := cmd.ReadConfigFile()
			require.NoError(t, err)

			for key, expected := range tt.expected {
				assert.Equal(t, expected, viper.Get(key))
			}
		})
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()

	v := cmd.Version()
	assert.Contains(t, v, "devel")
}
