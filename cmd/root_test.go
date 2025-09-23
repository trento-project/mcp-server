// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package cmd_test

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trento-project/mcp-server/cmd"
	"github.com/trento-project/mcp-server/internal/server"
	"github.com/trento-project/mcp-server/internal/utils"
)

//nolint:paralleltest
func TestExecute(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		expConf server.ServeOptions
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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bytes.NewBufferString("")
			command := cmd.NewRootCmd()
			// We only want to test flags, not the server execution
			command.RunE = func(_ *cobra.Command, _ []string) error { return nil }
			command.SetOut(b)
			command.SetErr(b)
			cmd.SetFlags(command)
			command.SetArgs(tt.args)
			err := command.Execute()

			require.NoError(t, err)

			opts := cmd.ServeOpts()
			// Name and Version are set automatically.
			tt.expConf.Name = opts.Name
			tt.expConf.Version = opts.Version
			assert.Equal(t, tt.expConf, opts)
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

func TestConfigureCLI(t *testing.T) {
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
				"TRENTO_MCP_CONFIG":           "/env/config.yaml",
				"TRENTO_MCP_INSECURETLS":      "true",
			},
			expected: server.ServeOptions{
				Port:             8888,
				OASPath:          "/env/oas.json",
				Transport:        utils.TransportStreamable,
				TrentoURL:        "https://env.trento.io",
				TrentoHeaderName: "X-Env-Header",
				TagFilter:        []string{"X", "Y"},
				InsecureTLS:      true,
			},
		},
		{
			name: "invalid transport",
			viperSettings: map[string]any{
				"transport": "invalid-transport",
			},
			expected: server.ServeOptions{
				Port:             5000,
				OASPath:          "./api/openapi.json",
				Transport:        "invalid-transport",
				TrentoURL:        "https://demo.trento-project.io",
				TrentoHeaderName: "X-TRENTO-MCP-APIKEY",
				TagFilter:        []string{},
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

//nolint:paralleltest
func TestServeOpts(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	rootCmd := cmd.NewRootCmd()
	rootCmd.RunE = func(_ *cobra.Command, _ []string) error { return nil }
	cmd.SetFlags(rootCmd)

	err := cmd.ConfigureCLI(rootCmd, []string{})
	require.NoError(t, err)

	// Get the serve options
	opts := cmd.ServeOpts()

	// Verify default values
	expected := server.ServeOptions{
		Port:             5000,
		OASPath:          "./api/openapi.json",
		Transport:        utils.TransportStreamable,
		TrentoURL:        "https://demo.trento-project.io",
		TrentoHeaderName: "X-TRENTO-MCP-APIKEY",
		TagFilter:        []string{},
		InsecureTLS:      false,
	}

	// Name and Version are set automatically
	assert.NotEmpty(t, opts.Name)
	assert.NotEmpty(t, opts.Version)
	assert.Contains(t, opts.Version, "devel")

	// Check all other fields match expected defaults
	assert.Equal(t, expected.Port, opts.Port)
	assert.Equal(t, expected.OASPath, opts.OASPath)
	assert.Equal(t, expected.Transport, opts.Transport)
	assert.Equal(t, expected.TrentoURL, opts.TrentoURL)
	assert.Equal(t, expected.TrentoHeaderName, opts.TrentoHeaderName)
	assert.Equal(t, expected.TagFilter, opts.TagFilter)
	assert.Equal(t, expected.InsecureTLS, opts.InsecureTLS)
}

//nolint:paralleltest
func TestCreateAndBindFlags(t *testing.T) {
	// Reset viper for clean state
	viper.Reset()
	defer viper.Reset()

	// Create a test command
	testCmd := &cobra.Command{}

	// Define test flag configs
	flagConfigs := []utils.FlagConfig{
		{
			Key:          "testPort",
			DefaultValue: 8080,
			FlagType:     utils.FlagTypeInt,
			FlagName:     "test-port",
			Short:        "p",
			Description:  "Test port flag",
		},
		{
			Key:          "testPath",
			DefaultValue: "/default/path",
			FlagType:     utils.FlagTypeString,
			FlagName:     "test-path",
			Short:        "f",
			Description:  "Test path flag",
		},
	}

	// Call CreateAndBindFlags
	cmd.CreateAndBindFlags(flagConfigs, testCmd)

	// Verify flags were created
	portFlag := testCmd.Flags().Lookup("test-port")
	require.NotNil(t, portFlag)
	assert.Equal(t, "p", portFlag.Shorthand)
	assert.Equal(t, "Test port flag", portFlag.Usage)

	pathFlag := testCmd.Flags().Lookup("test-path")
	require.NotNil(t, pathFlag)
	assert.Equal(t, "f", pathFlag.Shorthand)
	assert.Equal(t, "Test path flag", pathFlag.Usage)

	// Verify bindings work by setting flag values and checking viper
	err := testCmd.Flags().Set("test-port", "9090")
	require.NoError(t, err)
	assert.Equal(t, 9090, viper.Get("testPort"))

	err = testCmd.Flags().Set("test-path", "/custom/path")
	require.NoError(t, err)
	assert.Equal(t, "/custom/path", viper.Get("testPath"))
}

func TestFlagConfigs(t *testing.T) {
	t.Parallel()

	configs := cmd.FlagConfigs()

	// Verify we have the expected number of configs
	assert.Len(t, configs, 9)

	// Test basic properties of each flag configuration
	expectedFlags := []struct {
		key      string
		flagName string
		short    string
	}{
		{"port", "port", "p"},
		{"oasPath", "oas-path", "P"},
		{"transport", "transport", "t"},
		{"trentoURL", "trento-url", "u"},
		{"trentoHeaderName", "header-name", "H"},
		{"tagFilter", "tag-filter", "f"},
		{"insecureTLS", "insecure-tls", "i"},
		{"verbosity", "verbosity", "v"},
		{"config", "config", "c"},
	}

	for i, expected := range expectedFlags {
		assert.Equal(t, expected.key, configs[i].Key, "config %d key mismatch", i)
		assert.Equal(t, expected.flagName, configs[i].FlagName, "config %d flag name mismatch", i)
		assert.Equal(t, expected.short, configs[i].Short, "config %d short mismatch", i)
	}
}

func TestGetConfigDescription(t *testing.T) {
	t.Parallel()

	description := cmd.GetConfigDescription()

	// The description should contain the expected format
	expectedPaths := "./trento-mcp-server.config.yaml or /etc/trento/trento-mcp-server.config.yaml"
	expectedDescription := fmt.Sprintf("config file path (default search: %s)", expectedPaths)

	assert.Equal(t, expectedDescription, description)
}

//nolint:paralleltest
func TestSetFlags(t *testing.T) {
	// Reset viper for clean state
	viper.Reset()
	defer viper.Reset()

	// Create a test command
	testCmd := &cobra.Command{}

	// Call SetFlags
	cmd.SetFlags(testCmd)

	// Get all flag configurations
	flagConfigs := cmd.FlagConfigs()

	// Verify that all flags from flagConfigs were created on the command
	for _, config := range flagConfigs {
		var flagSet *pflag.FlagSet
		if config.IsPersistent {
			flagSet = testCmd.PersistentFlags()
		} else {
			flagSet = testCmd.Flags()
		}

		flag := flagSet.Lookup(config.FlagName)
		require.NotNil(t, flag, "Flag %s should be created", config.FlagName)
		assert.Equal(t, config.Short, flag.Shorthand, "Flag %s should have correct shorthand", config.FlagName)
		assert.Equal(t, config.Description, flag.Usage, "Flag %s should have correct description", config.FlagName)

		// Verify viper defaults are set
		assert.Equal(t, config.DefaultValue, viper.Get(config.Key), "Viper default should be set for key %s", config.Key)
	}
}
