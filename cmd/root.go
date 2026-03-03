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
	"github.com/trento-project/mcp-server/internal/agent"
	"github.com/trento-project/mcp-server/internal/agui"
	"github.com/trento-project/mcp-server/internal/server"
	"github.com/trento-project/mcp-server/internal/telemetry"
	"github.com/trento-project/mcp-server/internal/utils"
	"go.opentelemetry.io/otel/trace"
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
	defaultAutodiscoveryPaths = []string{"/api/all/openapi", "/wanda/api/all/openapi"}
	//nolint:gochecknoglobals
	defaultConfigPaths = []string{"/etc/trento/", "/usr/etc/trento/"}
	//nolint:gochecknoglobals
	defaultOASPath = []string{}
	//nolint:gochecknoglobals
	defaultTagFilter = []string{"MCP"}
	//nolint:gochecknoglobals
	defaultTransport = string(utils.TransportStreamable)
)

const (
	name = "mcp-server-trento"

	// Default values.
	defaultConfig                = ""
	defaultEnableHealthCheck     = false
	defaultHeaderName            = "Authorization"
	defaultHealthAPIPath         = "/api/healthz"
	defaultHealthPort            = 8080
	defaultInsecureSkipTLSVerify = false
	defaultPort                  = 5000
	defaultTrentoURL             = ""
	defaultVerbosity             = "debug"

	// Configuration keys.
	configKeyAutodiscoveryPaths    = "AUTODISCOVERY_PATHS"
	configKeyConfig                = "CONFIG"
	configKeyEnableHealthCheck     = "ENABLE_HEALTH_CHECK"
	configKeyHeaderName            = "HEADER_NAME"
	configKeyHealthAPIPath         = "HEALTH_API_PATH"
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
	rootCmd.AddCommand(newAGUICmd())
}

func newAGUICmd() *cobra.Command {
	var addr string
	var mcpURL string
	var mcpToken string
	var systemPrompt string
	var geminiAPIKey string
	var pgURL string
	var otelEndpoint string
	cmd := &cobra.Command{
		Use:   "agui",
		Short: "Run an AG-UI compatible server",
		Long:  "Run an AG-UI protocol compliant server with SSE streaming and RAG support",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			// Get Gemini API key from env if not provided
			if geminiAPIKey == "" {
				geminiAPIKey = os.Getenv("GEMINI_API_KEY")
			}
			if geminiAPIKey == "" {
				return fmt.Errorf("Gemini API key required: use --gemini-api-key flag or GEMINI_API_KEY environment variable")
			}

			// Initialize OTEL providers for metrics and tracing
			endpoint := otelEndpoint
			if endpoint == "" {
				endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
			}
			var metrics *telemetry.Metrics
			var tracer trace.Tracer
			if endpoint != "" {
				provider, err := telemetry.InitializeOTLP(ctx, endpoint)
				if err != nil {
					slog.WarnContext(ctx, "OTEL init failed; continuing without telemetry", "error", err)
				} else {
					defer func() {
						if err := provider.Shutdown(ctx); err != nil {
							slog.WarnContext(ctx, "OTEL shutdown failed", "error", err)
						}
					}()
					meter := provider.MetricProvider.Meter("trento-agent")
					metrics, err = telemetry.InitializeMetrics(ctx, meter)
					if err != nil {
						slog.WarnContext(ctx, "OTEL metrics init failed; continuing without metrics", "error", err)
					}
					tracer = provider.TraceProvider.Tracer("trento-agent")
				}
			}

			// Initialize agent service with RAG support
			service, err := agent.NewAgentService(ctx, mcpURL, mcpToken, systemPrompt, geminiAPIKey, pgURL, metrics, tracer)
			if err != nil {
				return err
			}
			defer service.Close()

			// Run SSE-based AG-UI server (preferred)
			s := agui.NewSSEServer(service, addr)
			return s.Run(ctx)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", ":8081", "address to bind the AG-UI server")
	cmd.Flags().StringVar(&mcpURL, "mcp-url", "http://localhost:5000", "MCP server URL")
	cmd.Flags().StringVar(&mcpToken, "mcp-token", "trento_pat_pT7P0Mk8ScOuWSaNHAzGrXDwQ08QdBEE7p9648kg_bEwXNodY_PIRqvw1Thu5kK3F_DFPJRtJV6ngDxdjfv9Lw", "Bearer token to use as Authorization header when connecting to MCP server (optional)")
	cmd.Flags().StringVar(&systemPrompt, "system-prompt", "", "Optional system prompt override for the agent (defaults to Trento assistant prompt)")
	cmd.Flags().StringVar(&geminiAPIKey, "gemini-api-key", "", "Gemini API key for LLM and embeddings (or set GEMINI_API_KEY env var)")
	cmd.Flags().StringVar(&pgURL, "pg-url", "postgres://postgres:postgres@localhost:5434/trento_rag?sslmode=disable", "PostgreSQL connection URL for RAG vector store")
	cmd.Flags().StringVar(&otelEndpoint, "otel-endpoint", "localhost:4317", "OTEL gRPC endpoint (host:port); set empty to disable")
	return cmd
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
			Description:  "Enable the health check server (default false)",
		},
		{
			Key:          configKeyHeaderName,
			DefaultValue: defaultHeaderName,
			FlagType:     utils.FlagTypeString,
			FlagName:     "header-name",
			Short:        "H",
			Description:  "The header name to be used for the passing the Trento PAT to the MCP server",
		},
		{
			Key:          configKeyHealthAPIPath,
			DefaultValue: defaultHealthAPIPath,
			FlagType:     utils.FlagTypeString,
			FlagName:     "health-api-path",
			Short:        "a",
			Description:  "The API path used for health checks on target servers",
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
			Short:        "i",
			Description:  "Skip TLS certificate verification when fetching OpenAPI spec from HTTPS URLs (default false)",
		},
		{
			Key:          configKeyOASPath,
			DefaultValue: defaultOASPath,
			FlagType:     utils.FlagTypeStringSlice,
			FlagName:     "oas-path",
			Short:        "P",
			Description:  "Path to the OpenAPI spec file(s) (default [])",
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
			Description:  "URL for the target Trento server (default \"\")",
		},
		{
			Key:          configKeyVerbosity,
			DefaultValue: defaultVerbosity,
			FlagType:     utils.FlagTypeString,
			FlagName:     "verbosity",
			IsPersistent: true,
			Short:        "v",
			Description:  "Log level verbosity (debug, info, warning, error)",
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

	// // If no TrentoURL or no OASPaths are provided, just error
	// if serveOpts.TrentoURL == "" && len(serveOpts.OASPath) == 0 {
	// 	return errors.New("either a Trento URL or at least one OAS path must be provided")
	// }

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
