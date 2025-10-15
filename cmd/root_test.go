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
				"--autodiscovery-paths", "/foo,/bar",
				"--enable-health-check",
				"--header-name", "X-My-Header",
				"--health-port", "1234",
				"--insecure-skip-tls-verify",
				"--oas-path", "/tmp/api.json",
				"--port", "9090",
				"--tag-filter", "A,B",
				"--transport", "sse",
				"--trento-url", "http://trento.example.com",
				"--verbosity", "debug",
			},
			expConf: server.ServeOptions{
				AutodiscoveryPaths:    []string{"/foo", "/bar"},
				EnableHealthCheck:     true,
				HeaderName:            "X-My-Header",
				HealthPort:            1234,
				InsecureSkipTLSVerify: true,
				OASPath:               []string{"/tmp/api.json"},
				Port:                  9090,
				TagFilter:             []string{"A", "B"},
				Transport:             utils.TransportSSE,
				TrentoURL:             "http://trento.example.com",
			},
		},
		{
			name: "default values",
			args: []string{},
			expConf: server.ServeOptions{
				AutodiscoveryPaths: []string{"/api/all/openapi", "/wanda/api/all/openapi"},
				EnableHealthCheck:  false,
				HeaderName:         "X-TRENTO-MCP-APIKEY",
				HealthPort:         8080,
				OASPath:            []string{},
				Port:               5000,
				TagFilter:          []string{},
				Transport:          utils.TransportStreamable,
				TrentoURL:          "https://demo.trento-project.io",
			},
		},
		{
			name: "invalid transport",
			args: []string{"--transport", "invalid-transport"},
			expConf: server.ServeOptions{
				AutodiscoveryPaths: []string{"/api/all/openapi", "/wanda/api/all/openapi"},
				EnableHealthCheck:  false,
				HeaderName:         "X-TRENTO-MCP-APIKEY",
				HealthPort:         8080,
				OASPath:            []string{},
				Port:               5000,
				TagFilter:          []string{},
				Transport:          "invalid-transport",
				TrentoURL:          "https://demo.trento-project.io",
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
				"HEADER_NAME": "X-Test-Header",
				"OAS_PATH":    []string{"/tmp/oas.json"},
				"PORT":        1234,
				"TAG_FILTER":  []string{"C", "D"},
				"TRANSPORT":   "sse",
				"TRENTO_URL":  "http://trento.test",
			},
			expected: server.ServeOptions{
				AutodiscoveryPaths: []string{"/api/all/openapi", "/wanda/api/all/openapi"},
				HeaderName:         "X-Test-Header",
				HealthPort:         8080,
				OASPath:            []string{"/tmp/oas.json"},
				Port:               1234,
				TagFilter:          []string{"C", "D"},
				Transport:          utils.TransportSSE,
				TrentoURL:          "http://trento.test",
			},
		},
		{
			name:          "default values",
			viperSettings: map[string]any{},
			envVars:       map[string]string{},
			expected: server.ServeOptions{
				AutodiscoveryPaths: []string{"/api/all/openapi", "/wanda/api/all/openapi"},
				EnableHealthCheck:  false,
				HeaderName:         "X-TRENTO-MCP-APIKEY",
				HealthPort:         8080,
				OASPath:            []string{},
				Port:               5000,
				TagFilter:          []string{},
				Transport:          utils.TransportStreamable,
				TrentoURL:          "https://demo.trento-project.io",
			},
		},
		{
			name: "environment variables",
			envVars: map[string]string{
				"TRENTO_MCP_CONFIG":                   "/env/config.yaml",
				"TRENTO_MCP_ENABLE_HEALTH_CHECK":      "true",
				"TRENTO_MCP_HEADER_NAME":              "X-Env-Header",
				"TRENTO_MCP_INSECURE_SKIP_TLS_VERIFY": "true",
				"TRENTO_MCP_OAS_PATH":                 "/env/oas.json,/another/path.json",
				"TRENTO_MCP_PORT":                     "8888",
				"TRENTO_MCP_TAG_FILTER":               "X,Y",
				"TRENTO_MCP_TRANSPORT":                "streamable",
				"TRENTO_MCP_TRENTO_URL":               "https://env.trento.io",
				"TRENTO_MCP_VERBOSITY":                "info",
			},
			expected: server.ServeOptions{
				AutodiscoveryPaths:    []string{"/api/all/openapi", "/wanda/api/all/openapi"},
				EnableHealthCheck:     true,
				HeaderName:            "X-Env-Header",
				HealthPort:            8080,
				InsecureSkipTLSVerify: true,
				OASPath:               []string{"/env/oas.json", "/another/path.json"},
				Port:                  8888,
				TagFilter:             []string{"X", "Y"},
				Transport:             utils.TransportStreamable,
				TrentoURL:             "https://env.trento.io",
			},
		},
		{
			name: "invalid transport",
			viperSettings: map[string]any{
				"transport": "invalid-transport",
			},
			expected: server.ServeOptions{
				AutodiscoveryPaths: []string{"/api/all/openapi", "/wanda/api/all/openapi"},
				EnableHealthCheck:  false,
				HeaderName:         "X-TRENTO-MCP-APIKEY",
				HealthPort:         8080,
				OASPath:            []string{},
				Port:               5000,
				TagFilter:          []string{},
				Transport:          "invalid-transport",
				TrentoURL:          "https://demo.trento-project.io",
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
			configContent: "PORT=1234",
			setConfigFile: true,
			expected:      map[string]any{"PORT": "1234"},
		},
		{
			name: "all keys set",
			configContent: `PORT=9999
AUTODISCOVERY_PATHS=/foo,/bar
ENABLE_HEALTH_CHECK=true
HEADER_NAME=X-My-Header
HEALTH_PORT=4321
INSECURE_SKIP_TLS_VERIFY=true
OAS_PATH=/custom/api.json
PORT=9999
TAG_FILTER=tag1,tag2
TRANSPORT=sse
TRENTO_URL=https://custom.trento.io
VERBOSITY=info
`,
			setConfigFile: true,
			expected: map[string]any{
				"AUTODISCOVERY_PATHS":      "/foo,/bar",
				"ENABLE_HEALTH_CHECK":      "true",
				"HEADER_NAME":              "X-My-Header",
				"HEALTH_PORT":              "4321",
				"INSECURE_SKIP_TLS_VERIFY": "true",
				"OAS_PATH":                 "/custom/api.json",
				"PORT":                     "9999",
				"TAG_FILTER":               "tag1,tag2",
				"TRANSPORT":                "sse",
				"TRENTO_URL":               "https://custom.trento.io",
				"VERBOSITY":                "info",
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
			configContent: "",
			setConfigFile: true,
			configFile:    "/non/existent/config",
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
					tmpFile, err := os.CreateTemp(t.TempDir(), "tmp-config-*")
					require.NoError(t, err)

					if tt.configContent != "" {
						_, err = tmpFile.WriteString(tt.configContent)
						require.NoError(t, err)
					}

					err = tmpFile.Close()
					require.NoError(t, err)

					// Set the file, like passing --config flag
					viper.Set(cmd.ConfigKeyConfig, tmpFile.Name())
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
		AutodiscoveryPaths:    []string{"/api/all/openapi", "/wanda/api/all/openapi"},
		EnableHealthCheck:     false,
		HeaderName:            "X-TRENTO-MCP-APIKEY",
		HealthPort:            8080,
		InsecureSkipTLSVerify: false,
		Name:                  "trento-mcp-server",
		OASPath:               []string{},
		Port:                  5000,
		TagFilter:             []string{},
		Transport:             utils.TransportStreamable,
		TrentoURL:             "https://demo.trento-project.io",
		Version:               "devel",
	}

	assert.EqualExportedValues(t, expected, opts)
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
	assert.Len(t, configs, 12)

	// Test basic properties of each flag configuration
	expectedFlags := []struct {
		key      string
		flagName string
		short    string
	}{
		{"AUTODISCOVERY_PATHS", "autodiscovery-paths", "A"},
		{"CONFIG", "config", "c"},
		{"ENABLE_HEALTH_CHECK", "enable-health-check", "d"},
		{"HEADER_NAME", "header-name", "H"},
		{"HEALTH_PORT", "health-port", "z"},
		{"INSECURE_SKIP_TLS_VERIFY", "insecure-skip-tls-verify", "i"},
		{"OAS_PATH", "oas-path", "P"},
		{"PORT", "port", "p"},
		{"TAG_FILTER", "tag-filter", "f"},
		{"TRANSPORT", "transport", "t"},
		{"TRENTO_URL", "trento-url", "u"},
		{"VERBOSITY", "verbosity", "v"},
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
	expectedPaths := "/etc/trento/trento-mcp-server or /usr/etc/trento/trento-mcp-server"
	expectedDescription := fmt.Sprintf("Configuration file path (default search: %s)", expectedPaths)

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
