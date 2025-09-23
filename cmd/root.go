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
	defaultTagFilter   = []string{}                        //nolint:gochecknoglobals
	defaultTransport   = string(utils.TransportStreamable) //nolint:gochecknoglobals
	defaultConfigPaths = []string{".", "/etc/trento/"}     //nolint:gochecknoglobals
)

const (
	name = "trento-mcp-server"

	// Default values.
	defaultVerbosity        = "info"
	defaultOASPath          = "./api/openapi.json"
	defaultPort             = 5000
	defaultTrentoHeaderName = "X-TRENTO-MCP-APIKEY"
	defaultTrentoURL        = "https://demo.trento-project.io"
	defaultConfig           = ""
	defaultInsecureTLS      = false

	// Configuration keys.
	configKeyPort             = "port"
	configKeyOASPath          = "oasPath"
	configKeyTransport        = "transport"
	configKeyTrentoURL        = "trentoURL"
	configKeyTrentoHeaderName = "trentoHeaderName"
	configKeyTagFilter        = "tagFilter"
	configKeyVerbosity        = "verbosity"
	configKeyConfig           = "config"
	configKeyInsecureTLS      = "insecureTLS"
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
			Key:          configKeyPort,
			DefaultValue: defaultPort,
			FlagType:     utils.FlagTypeInt,
			FlagName:     "port",
			Short:        "p",
			Description:  "The port on which to run the server",
		},
		{
			Key:          configKeyOASPath,
			DefaultValue: defaultOASPath,
			FlagType:     utils.FlagTypeString,
			FlagName:     "oasPath",
			Short:        "P",
			Description:  "Path to the OpenAPI spec file",
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
			Key:          configKeyTrentoHeaderName,
			DefaultValue: defaultTrentoHeaderName,
			FlagType:     utils.FlagTypeString,
			FlagName:     "header-name",
			Short:        "H",
			Description:  "The header name to be used for the Trento API key",
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
			Key:          configKeyInsecureTLS,
			DefaultValue: defaultInsecureTLS,
			FlagType:     utils.FlagTypeBool,
			FlagName:     "insecure-tls",
			IsPersistent: false,
			Short:        "i",
			Description:  "Skip TLS certificate verification when fetching OpenAPI spec from HTTPS URLs",
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
		{
			Key:          configKeyConfig,
			DefaultValue: defaultConfig,
			FlagType:     utils.FlagTypeString,
			FlagName:     "config",
			IsPersistent: true,
			Short:        "c",
			Description:  getConfigDescription(),
		},
	}
}

// configureCLI prepares the CLI, initializes the logger an
// reads the config file if any. Finally, it unmarshal the
// configuration into the server options passed through.
func configureCLI(_ *cobra.Command, _ []string) error {
	// Set the global logger
	err := initLogger()
	if err != nil {
		return fmt.Errorf("failed init logger: %w", err)
	}

	// try reading a file with the configuration
	err = readConfigFile()
	if err != nil {
		return fmt.Errorf("failed read config file: %w", err)
	}

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
