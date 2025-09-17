// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

// Package cmd holds the definition of CLI commands.
package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/carlmjohnson/versioninfo"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/trento-project/mcp-server/internal/server"
	"github.com/trento-project/mcp-server/internal/utils"
)

var (
	// version will be set via ldflags.
	logLevel  utils.LogLevel      //nolint:gochecknoglobals // initialized in initLogger
	serveOpts server.ServeOptions //nolint:gochecknoglobals
	version   string              //nolint:gochecknoglobals

	// rootCmd represents the base command when called without any subcommands.
	rootCmd *cobra.Command //nolint:gochecknoglobals
)

const (
	name                    = "trento-mcp-server"
	defaultVerbosity        = "info"
	defaultOASPath          = "./api/openapi.json"
	defaultPort             = 5000
	defaultTrentoHeaderName = "X-TRENTO-MCP-APIKEY"
	defaultTrentoURL        = "https://demo.trento-project.io"

	// Configuration file settings
	configFileName = "trento-mcp-server.config"
	configFileType = "yaml"

	// Environment variable prefix
	envPrefix = "TRENTO_MCP"

	// Configuration keys (to avoid repetition and typos)
	configKeyPort             = "port"
	configKeyOASPath          = "oasPath"
	configKeyTransport        = "transport"
	configKeyTrentoURL        = "trentoURL"
	configKeyTrentoHeaderName = "trentoHeaderName"
	configKeyTagFilter        = "tagFilter"
	configKeyVerbosity        = "verbosity"
	configKeyConfig           = "config"
)

var (
	defaultTagFilter = []string{"MCP"}
	defaultTransport = string(utils.TransportStreamable)

	// Configuration search paths
	configPaths = []string{".", "/etc/trento/"}
)

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:               name,
		Short:             "Trento MCP Server",
		Long:              `MCP server to interact with Trento`,
		PersistentPreRunE: initLogger,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Set serveOpts from Viper after flags are parsed
			if err := viper.Unmarshal(&serveOpts); err != nil {
				return fmt.Errorf("failed to unmarshal config: %w", err)
			}

			// Ensure transport has a valid default if not set
			if serveOpts.Transport == "" {
				serveOpts.Transport = utils.TransportStreamable
			}

			return server.Serve(cmd.Context(), &serveOpts)
		},
		Version: Version(),
	}
}

// setFlags defines which flags this CLI command will accept.
func setFlags(cmd *cobra.Command) {
	// Initialize Viper
	viper.SetConfigName(configFileName)
	viper.SetConfigType(configFileType)

	// Add configuration search paths
	for _, path := range configPaths {
		viper.AddConfigPath(path)
	}

	// Enable environment variables with prefix
	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv()

	// MCP SERVER
	cmd.Flags().IntP("port", "p", defaultPort, "The port on which to run the server")
	viper.SetDefault(configKeyPort, defaultPort)
	viper.BindPFlag(configKeyPort, cmd.Flags().Lookup("port"))

	cmd.Flags().StringP("oasPath", "P", defaultOASPath, "Path to the OpenAPI spec file")
	viper.SetDefault(configKeyOASPath, defaultOASPath)
	viper.BindPFlag(configKeyOASPath, cmd.Flags().Lookup("oasPath"))

	cmd.Flags().StringP("transport", "t", defaultTransport, `The protocol to use, choose "streamable" or "sse"`)
	viper.SetDefault(configKeyTransport, defaultTransport)
	viper.BindPFlag(configKeyTransport, cmd.Flags().Lookup("transport"))

	// Trento
	cmd.Flags().StringP("trento-url", "u", defaultTrentoURL, "URL for the target Trento server")
	viper.SetDefault(configKeyTrentoURL, defaultTrentoURL)
	viper.BindPFlag(configKeyTrentoURL, cmd.Flags().Lookup("trento-url"))

	cmd.Flags().StringP("header-name", "H", defaultTrentoHeaderName, "The header name to be used for the Trento API key")
	viper.SetDefault(configKeyTrentoHeaderName, defaultTrentoHeaderName)
	viper.BindPFlag(configKeyTrentoHeaderName, cmd.Flags().Lookup("header-name"))

	cmd.Flags().StringSliceP("tag-filter", "f", defaultTagFilter, "Only include operations with at least one of these tags")
	viper.SetDefault(configKeyTagFilter, defaultTagFilter)
	viper.BindPFlag(configKeyTagFilter, cmd.Flags().Lookup("tag-filter"))

	// OTHERS
	cmd.PersistentFlags().StringP("verbosity", "v", defaultVerbosity, "log level verbosity (debug, info, warning, error)")
	viper.SetDefault(configKeyVerbosity, defaultVerbosity)
	viper.BindPFlag(configKeyVerbosity, cmd.PersistentFlags().Lookup("verbosity"))

	cmd.PersistentFlags().StringP("config", "c", "", "config file path (default search: ./trento-mcp-server.config.yaml or /etc/trento/trento-mcp-server.config.yaml)")
	viper.BindPFlag(configKeyConfig, cmd.PersistentFlags().Lookup("config"))

	// Set version and name
	serveOpts.Version = Version()
	serveOpts.Name = name
}

// init creates a new command, append the runtime version and set flags.
// note that here the flags have not being parsed yet.
func init() {
	rootCmd = newRootCmd()
	setFlags(rootCmd)
	rootCmd.SetVersionTemplate(`{{printf "%s" .Version}}
`)
}

// initLogger creates a new logger once the flags have been parsed,
// this way, the log level is being properly set.
func initLogger(_ *cobra.Command, _ []string) error {
	// Set logLevel from Viper (flags, env vars, or config file)
	if lvl := viper.GetString(configKeyVerbosity); lvl != "" {
		logLevel = utils.LogLevel(lvl)
	} else {
		logLevel = defaultVerbosity // fallback to default
	}

	logger := utils.CreateLogger(logLevel)

	slog.SetDefault(logger)

	// Log configuration search paths for user visibility
	slog.Debug("configuration search paths initialized",
		"config.name", configFileName,
		"config.type", configFileType,
		"search.paths", configPaths,
		"env.prefix", envPrefix,
	)

	// Handle custom config file path if specified
	configPath := viper.GetString(configKeyConfig)
	if configPath != "" {
		viper.SetConfigFile(configPath)
	}

	// Read config file after logger is initialized
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			slog.Debug("no configuration file found, using default values",
				"config.path", configPath,
				"used", viper.ConfigFileUsed(),
			)
		} else {
			slog.Warn("failed to read configuration file",
				"config.path", configPath,
				"config.used", viper.ConfigFileUsed(),
				"error", err,
			)
		}
	}

	slog.Debug("CLI initialization completed, ready to invoke the server",
		"logger.level", logLevel,
	)

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
