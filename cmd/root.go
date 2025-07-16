// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

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
	logLevel  int
	serveOpts server.ServeOptions
	version   string

	// rootCmd represents the base command when called without any subcommands.
	rootCmd *cobra.Command
)

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "trento-mcp-server",
		Short:             "Trento MCP Server",
		Long:              `MCP server to interact with Trento`,
		PersistentPreRunE: initLogger,
		RunE: func(_ *cobra.Command, _ []string) error {
			return server.Serve(serveOpts)
		},
		Version: Version(),
	}
}

// setFlags defines which flags this CLI command will accept.
func setFlags(cmd *cobra.Command) {
	// MCP SERVER
	cmd.Flags().IntVarP(&serveOpts.Port, "port", "p", 5000, "The port on which to run the server")
	cmd.Flags().StringVarP(&serveOpts.OASPath, "oasPath", "P", "./api/openapi.json", "Path to the OpenAPI spec file")
	cmd.Flags().StringVar(&serveOpts.Transport, "transport", "sse", "The protocol to use, choose 'streamable' or 'sse'")
	cmd.Flags().StringVar(&serveOpts.McpBaseUrl, "base-url", "", "Base URL where the mcp is deployed, if none, http://localhost:port is used'")
	// OAUTH
	cmd.Flags().BoolVar(&serveOpts.OauthEnabled, "oauth-enabled", false, "Enable the oauth authentication in the MCP")
	cmd.Flags().StringVar(&serveOpts.OauthAuthorizationServerURL, "oauth-authorization-server-url", "https://my-idp.example.com/.well-known/openid-configuration", "URL for the oauth-authorization-server endpoint") //nolint:lll,golines
	cmd.Flags().StringVar(&serveOpts.OauthIssuer, "oauth-issuer", "https://my-idp.example.com/", "Issuer for the oauth flow")
	cmd.Flags().StringVar(&serveOpts.OauthValidateURL, "oauth-validate-url", "https://my-idp.example.com/userinfo", "URL for token validation")
	// Trento
	cmd.Flags().StringVar(&serveOpts.TrentoUrl, "trento-url", "https://demo.trento-project.io", "URL for the target Trento server")
	cmd.Flags().StringVar(&serveOpts.TrentoUsername, "trento-username", "demo", "Username for the target Trento server")
	cmd.Flags().StringVar(&serveOpts.TrentoPassword, "trento-password", "demopass", "Password for the target Trento server")
	// OTHERS
	cmd.PersistentFlags().IntVarP(&logLevel, "verbosity", "v", 0, "log level verbosity (-1: debug, 0: info, 1: warning, 2: error)")
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

	slog.Debug("CLI initialization completed, ready to invoke the server")

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
