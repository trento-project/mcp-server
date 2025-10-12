// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

// Package cmd holds the definition of CLI commands.
package cmd

import (
	"fmt"
	"os"

	"github.com/carlmjohnson/versioninfo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/trento-project/mcp-server/internal/server"
	"github.com/trento-project/mcp-server/internal/utils"
)

var (
	// version will be set via ldflags.
	version string //nolint:gochecknoglobals

	// serveOpts are the options passed to the server.
	serveOpts server.ServeOptions //nolint:gochecknoglobals

	// rootCmd represents the base command when called without any subcommands.
	rootCmd *cobra.Command //nolint:gochecknoglobals

	// Default values.
	//nolint:gochecknoglobals
	defaultAutodiscoveryPaths = []string{"/api/latest/openapi", "/wanda/api/latest/openapi"}
	//nolint:gochecknoglobals
	defaultConfigPaths = []string{"/etc/trento/", "/usr/etc/trento/"}
	//nolint:gochecknoglobals
	defaultOASPath = []string{}
	//nolint:gochecknoglobals
	defaultTagFilter = []string{}
	//nolint:gochecknoglobals
	defaultTransport = string(utils.TransportStreamable)
)

const (
	name = "trento-mcp-server"

	// Default values.
	defaultConfig                = ""
	defaultEnableHealthCheck     = false
	defaultHeaderName            = "X-TRENTO-MCP-APIKEY"
	defaultHealthPort            = 8080
	defaultInsecureSkipTLSVerify = false
	defaultPort                  = 5000
	defaultTrentoURL             = "https://demo.trento-project.io"
	defaultVerbosity             = "info"

	// Configuration keys.
	configKeyAutodiscoveryPaths    = "AUTODISCOVERY_PATHS"
	configKeyConfig                = "CONFIG"
	configKeyEnableHealthCheck     = "ENABLE_HEALTH_CHECK"
	configKeyHeaderName            = "HEADER_NAME"
	configKeyHealthPort            = "HEALTH_PORT"
	configKeyInsecureSkipTLSVerify = "INSECURE_SKIP_TLS_VERIFY"
	configKeyOASPath               = "OAS_PATH"
	configKeyPort                  = "PORT"
	configKeyTagFilter             = "TAG_FILTER"
	configKeyTransport             = "TRANSPORT"
	configKeyTrentoURL             = "TRENTO_URL"
	configKeyVerbosity             = "VERBOSITY"
)

// init creates a new command, append the runtime version and set flags.
// note that here the flags have not being parsed yet.
func init() {
	rootCmd = newRootCmd()
	setFlags(rootCmd)
	rootCmd.SetVersionTemplate(`{{printf "%s" .Version}}
`)
}

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:               name,
		Short:             "Trento MCP Server",
		Long:              `MCP server to interact with Trento`,
		PersistentPreRunE: configureCLI,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return server.Serve(cmd.Context(), &serveOpts)
		},
		Version: Version(),
	}
}

// flagConfigs returns the config flags for this CLI.
func flagConfigs() []utils.FlagConfig {
	return []utils.FlagConfig{
		{
			Key:          configKeyAutodiscoveryPaths,
			DefaultValue: defaultAutodiscoveryPaths,
			FlagType:     utils.FlagTypeStringSlice,
			FlagName:     "autodiscovery-paths",
			Short:        "A",
			Description:  "Custom paths for API autodiscovery",
		},
		{
			Key:          configKeyConfig,
			DefaultValue: defaultConfig,
			FlagType:     utils.FlagTypeString,
			FlagName:     "config",
			IsPersistent: true,
			Short:        "c",
			Description:  getConfigDescription(),
		},
		{
			Key:          configKeyEnableHealthCheck,
			DefaultValue: defaultEnableHealthCheck,
			FlagType:     utils.FlagTypeBool,
			FlagName:     "enable-health-check",
			Short:        "d",
			Description:  "Enable the health check server",
		},
		{
			Key:          configKeyHeaderName,
			DefaultValue: defaultHeaderName,
			FlagType:     utils.FlagTypeString,
			FlagName:     "header-name",
			Short:        "H",
			Description:  "The header name to be used for the passing the Trento API key to the MCP server",
		},
		{
			Key:          configKeyHealthPort,
			DefaultValue: defaultHealthPort,
			FlagType:     utils.FlagTypeInt,
			FlagName:     "health-port",
			Short:        "z",
			Description:  "The port on which to run the health check server",
		},
		{
			Key:          configKeyInsecureSkipTLSVerify,
			DefaultValue: defaultInsecureSkipTLSVerify,
			FlagType:     utils.FlagTypeBool,
			FlagName:     "insecure-skip-tls-verify",
			IsPersistent: false,
			Short:        "i",
			Description:  "Skip TLS certificate verification when fetching OpenAPI spec from HTTPS URLs",
		},
		{
			Key:          configKeyOASPath,
			DefaultValue: defaultOASPath,
			FlagType:     utils.FlagTypeStringSlice,
			FlagName:     "oas-path",
			Short:        "P",
			Description:  "Path to the OpenAPI spec file(s)",
		},
		{
			Key:          configKeyPort,
			DefaultValue: defaultPort,
			FlagType:     utils.FlagTypeInt,
			FlagName:     "port",
			Short:        "p",
			Description:  "The port on which to run the MCP server",
		},
		{
			Key:          configKeyTagFilter,
			DefaultValue: defaultTagFilter,
			FlagType:     utils.FlagTypeStringSlice,
			FlagName:     "tag-filter",
			Short:        "f",
			Description:  "Only include operations with at least one of these tags",
		},
		{
			Key:          configKeyTransport,
			DefaultValue: defaultTransport,
			FlagType:     utils.FlagTypeString,
			FlagName:     "transport",
			Short:        "t",
			Description:  `The protocol to use, choose "streamable" or "sse"`,
		},
		{
			Key:          configKeyTrentoURL,
			DefaultValue: defaultTrentoURL,
			FlagType:     utils.FlagTypeString,
			FlagName:     "trento-url",
			Short:        "u",
			Description:  "URL for the target Trento server",
		},
		{
			Key:          configKeyVerbosity,
			DefaultValue: defaultVerbosity,
			FlagType:     utils.FlagTypeString,
			FlagName:     "verbosity",
			IsPersistent: true,
			Short:        "v",
			Description:  "log level verbosity (debug, info, warning, error)",
		},
	}
}

// configureCLI prepares the CLI, initializes the logger an
// reads the config file if any. Finally, it unmarshal the
// configuration into the server options passed through.
func configureCLI(_ *cobra.Command, _ []string) error {
	// Set the logger temporarily, it can change once the config file is read
	err := initLogger()
	if err != nil {
		return fmt.Errorf("failed init logger before reading config file: %w", err)
	}

	// Try reading a file with the configuration
	err = readConfigFile()
	if err != nil {
		return fmt.Errorf("failed read config file: %w", err)
	}

	// Set the global logger, with the proper level
	err = initLogger()
	if err != nil {
		return fmt.Errorf("failed init logger: %w", err)
	}

	// Normalize string slice flags/env vars
	normalizeStringSlice(configKeyOASPath)
	normalizeStringSlice(configKeyTagFilter)
	normalizeStringSlice(configKeyAutodiscoveryPaths)

	// Set serveOpts from Viper after flags are parsed
	err = viper.Unmarshal(&serveOpts)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

// ServeOpts returns the serveOpts set by the command args.
func ServeOpts() server.ServeOptions {
	return serveOpts
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// Version returns the ver "version" is set via ldflags,
// if not set, just the go debug vcs info.
func Version() string {
	if version != "" {
		return version
	}

	return versioninfo.Short()
}
