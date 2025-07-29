// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

// Package cmd holds the definition of CLI commands.
package cmd

import (
	"log/slog"
	"os"

	"github.com/carlmjohnson/versioninfo"
	"github.com/spf13/cobra"
	"github.com/trento-project/mcp-server/internal/server"
	"github.com/trento-project/mcp-server/internal/utils"
)

var (
	// version will be set via ldflags.
	logLevel  int                 //nolint:gochecknoglobals
	serveOpts server.ServeOptions //nolint:gochecknoglobals
	version   string              //nolint:gochecknoglobals

	// rootCmd represents the base command when called without any subcommands.
	rootCmd *cobra.Command //nolint:gochecknoglobals
)

const (
	name                               = "trento-mcp-server"
	defaultPort                        = 5000
	defaultOASPath                     = "./api/openapi.json"
	defaultMcpBaseURL                  = ""
	defaultOauthEnabled                = false
	defaultOauthAuthorizationServerURL = "https://my-idp.example.com/.well-known/openid-configuration"
	defaultOauthIssuer                 = "https://my-idp.example.com/"
	defaultOauthValidateURL            = "https://my-idp.example.com/userinfo"
	defaultTrentoURL                   = "https://demo.trento-project.io"
	defaultTrentoUsername              = "demo"
	defaultTrentoPassword              = "demopass"
	defaultLogLevel                    = 0
)

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:               name,
		Short:             "Trento MCP Server",
		Long:              `MCP server to interact with Trento`,
		PersistentPreRunE: initLogger,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return server.Serve(cmd.Context(), &serveOpts)
		},
		Version: Version(),
	}
}

// setFlags defines which flags this CLI command will accept.
func setFlags(cmd *cobra.Command) {
	// MCP SERVER
	cmd.Flags().IntVarP(&serveOpts.Port, "port", "p", defaultPort, "The port on which to run the server")
	cmd.Flags().StringVarP(&serveOpts.OASPath, "oasPath", "P", defaultOASPath, "Path to the OpenAPI spec file")
	serveOpts.Transport = utils.TransportStreamable // Set default value for transport
	cmd.Flags().Var(&serveOpts.Transport, "transport", "The protocol to use, choose 'streamable' (default) or 'sse'")
	cmd.Flags().StringVar(&serveOpts.McpBaseURL, "base-url", defaultMcpBaseURL, "Base URL where the mcp is deployed, if none, http://localhost:port is used'") //nolint:lll
	// OAUTH
	cmd.Flags().BoolVar(&serveOpts.OauthEnabled, "oauth-enabled", defaultOauthEnabled, "Enable the oauth authentication in the MCP")                                                       //nolint:lll
	cmd.Flags().StringVar(&serveOpts.OauthAuthorizationServerURL, "oauth-authorization-server-url", defaultOauthAuthorizationServerURL, "URL for the oauth-authorization-server endpoint") //nolint:lll
	cmd.Flags().StringVar(&serveOpts.OauthIssuer, "oauth-issuer", defaultOauthIssuer, "Issuer for the oauth flow")                                                                         //nolint:lll
	cmd.Flags().StringVar(&serveOpts.OauthValidateURL, "oauth-validate-url", defaultOauthValidateURL, "URL for token validation")                                                          //nolint:lll
	// Trento
	cmd.Flags().StringVar(&serveOpts.TrentoURL, "trento-url", defaultTrentoURL, "URL for the target Trento server")                     //nolint:lll
	cmd.Flags().StringVar(&serveOpts.TrentoUsername, "trento-username", defaultTrentoUsername, "Username for the target Trento server") //nolint:lll
	cmd.Flags().StringVar(&serveOpts.TrentoPassword, "trento-password", defaultTrentoPassword, "Password for the target Trento server") //nolint:lll
	// OTHERS
	cmd.PersistentFlags().IntVarP(&logLevel, "verbosity", "v", defaultLogLevel, "log level verbosity (-1: debug, 0: info, 1: warning, 2: error)") //nolint:lll

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
	logger := utils.CreateLogger(logLevel)

	slog.SetDefault(logger)

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
