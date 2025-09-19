// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

// Package cmd holds the definition of CLI commands.
package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/trento-project/mcp-server/internal/utils"
)

const (
	// Configuration file settings.
	configFileName = "trento-mcp-server.config"
	configFileType = "yaml"

	// Environment variable prefix.
	envPrefix = "TRENTO_MCP"
)

// setFlags defines which flags this CLI command will accept.
func setFlags(cmd *cobra.Command) {
	// Define all flag configurations
	flagConfigs := flagConfigs()

	// Set default values for viper
	for _, config := range flagConfigs {
		viper.SetDefault(config.Key, config.DefaultValue)
	}

	// Initialize Viper
	viper.SetConfigName(configFileName)
	viper.SetConfigType(configFileType)

	// Add configuration search paths
	for _, path := range defaultConfigPaths {
		viper.AddConfigPath(path)
	}

	// Enable environment variables with prefix
	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv()

	// Define and bind the flags with viper
	createAndBindFlags(flagConfigs, cmd)

	// Set version and name
	serveOpts.Version = Version()
	serveOpts.Name = name
}

// initLogger creates a new logger once the flags have been parsed,
// this way, the log level is being properly set.
func initLogger() error {
	lvl := viper.GetString(configKeyVerbosity)
	if lvl == "" {
		lvl = defaultVerbosity // fallback to default
	}

	var logLevel utils.LogLevel

	err := logLevel.Set(lvl)
	if err != nil {
		return err
	}

	logger := utils.CreateLogger(logLevel)

	slog.SetDefault(logger)

	slog.Debug("logger initialization completed",
		"logger.level", lvl,
	)

	return nil
}

// readConfigFile tries to read the configuration from a file.
func readConfigFile() error {
	// Log configuration search paths for user visibility
	slog.Debug("configuration search paths initialized",
		"config.name", configFileName,
		"config.type", configFileType,
		"search.paths", defaultConfigPaths,
		"env.prefix", envPrefix,
	)

	// Handle custom config file path if specified
	configPath := viper.GetString(configKeyConfig)
	if configPath != "" {
		viper.SetConfigFile(configPath)
	}

	// Read config file after logger is initialized
	err := viper.ReadInConfig()
	if err != nil {
		var configErr viper.ConfigFileNotFoundError
		if errors.As(err, &configErr) {
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

	return nil
}

// createAndBindFlags defines and binds the flags with viper.
func createAndBindFlags(flagConfigs []utils.FlagConfig, cmd *cobra.Command) {
	// Define flags
	for _, config := range flagConfigs {
		flagSet := cmd.Flags()
		if config.IsPersistent {
			flagSet = cmd.PersistentFlags()
		}

		switch config.FlagType {
		case utils.FlagTypeInt:
			if intVal, ok := config.DefaultValue.(int); ok {
				flagSet.IntP(config.FlagName, config.Short, intVal, config.Description)
			}
		case utils.FlagTypeString:
			if stringVal, ok := config.DefaultValue.(string); ok {
				flagSet.StringP(config.FlagName, config.Short, stringVal, config.Description)
			}
		case utils.FlagTypeStringSlice:
			if sliceVal, ok := config.DefaultValue.([]string); ok {
				flagSet.StringSliceP(config.FlagName, config.Short, sliceVal, config.Description)
			}
		default:
			panic(fmt.Sprintf("unknown flag type: %s", config.FlagType))
		}
	}

	// Bind flags to viper keys
	for _, config := range flagConfigs {
		flagSet := cmd.Flags()
		if config.IsPersistent {
			flagSet = cmd.PersistentFlags()
		}

		bindFlag(config.Key, flagSet.Lookup(config.FlagName))
	}
}

// bindFlag is a helper to bind flag and panic on error.
func bindFlag(key string, flag *pflag.Flag) {
	err := viper.BindPFlag(key, flag)
	if err != nil {
		panic(fmt.Sprintf("failed to bind flag %s: %v", key, err))
	}
}

// getConfigDescription generates the dynamic description for the config flag.
func getConfigDescription() string {
	paths := make([]string, len(defaultConfigPaths))

	for i, path := range defaultConfigPaths {
		// Trim trailing slashes to avoid double slashes
		cleanPath := strings.TrimSuffix(path, "/")
		if cleanPath == "." {
			paths[i] = fmt.Sprintf("./%s.%s", configFileName, configFileType)
		} else {
			paths[i] = fmt.Sprintf("%s/%s.%s", cleanPath, configFileName, configFileType)
		}
	}

	return fmt.Sprintf("config file path (default search: %s)", strings.Join(paths, " or "))
}
