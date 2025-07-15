// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/carlmjohnson/versioninfo"
	"github.com/getkin/kin-openapi/openapi3"
	mcpserver "github.com/jedisct1/openapi-mcp/pkg/mcp/server"
	"github.com/jedisct1/openapi-mcp/pkg/openapi2mcp"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// ServeOptions encapsulates the available command-line options.
type ServeOptions struct {
	Logger                      *otelzap.SugaredLogger
	McpBaseUrl                  string
	OASPath                     string
	OauthAuthorizationServerURL string
	OauthEnabled                bool
	OauthIssuer                 string
	OauthValidateURL            string
	OtelDebug                   bool
	OtelEnable                  bool
	OtelEnableLogger            bool
	OtelEnableMetrics           bool
	OtelEnableTracer            bool
	OtelExporterOtlpEndpoint    string
	OtelExporterOtlpProtocol    string
	Port                        int
	Tracer                      trace.Tracer
	Transport                   string
	TrentoPassword              string
	TrentoUrl                   string
	TrentoUsername              string
}

// Serve is the root command that is run when no other sub-commands are present.
func Serve(serveOpts ServeOptions) (err error) { // Named return for err
	ctx := context.Background()
	log := serveOpts.Logger

	log.DebugwContext(ctx, "starting Serve() command", "server.options", serveOpts)

	otelShutdown, initErr := initOtel(ctx, &serveOpts)
	if initErr != nil {
		log.ErrorwContext(ctx, "otel initialization failed", zap.Error(initErr))
		return initErr
	}
	defer func() {
		// It will hold the error from runServer (if any) when this defer executes.
		if shutdownErr := otelShutdown(ctx); shutdownErr != nil {
			log.ErrorwContext(ctx, "otel shutdown failed", zap.Error(shutdownErr))
			err = errors.Join(err, shutdownErr)
		}
	}()

	// Call the main server logic.
	err = runServer(ctx, &serveOpts, log)
	return err
}

func runServer(baseCtx context.Context, serveOpts *ServeOptions, log *otelzap.SugaredLogger) error {
	listenAddr := fmt.Sprintf(":%d", serveOpts.Port)

	// Create main server span.
	spanCtx, span := serveOpts.Tracer.Start(baseCtx, "Serve()",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attribute.String("server.address", listenAddr)),
		trace.WithAttributes(attribute.String("server.options", fmt.Sprintf("%+v", serveOpts))),
		trace.WithAttributes(attribute.String("env.OTEL_EXPORTER_OTLP_ENDPOINT", os.Getenv(OTEL_EXPORTER_OTLP_ENDPOINT))),
		trace.WithAttributes(attribute.String("env.OTEL_EXPORTER_OTLP_PROTOCOL", os.Getenv(OTEL_EXPORTER_OTLP_PROTOCOL))),
	)
	defer span.End()

	span.AddEvent("server initialization started")

	mcpSrv, err := createMCPServer(spanCtx, serveOpts, log)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to create MCP server")
		return err
	}

	switch serveOpts.Transport {
	case "sse":
		// startSSEServer logs and handles fatal errors internally if server fails to start
		err := startSSEServer(spanCtx, mcpSrv, listenAddr, log, span, serveOpts)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to start SSE server")
			return err
		}

		span.AddEvent("MCP server configured")
		span.SetStatus(codes.Ok, "Serve() went OK")

	case "streamable":
		// startHTTPServer logs and handles fatal errors internally if server fails to start
		streamableServer, err := startHTTPServer(spanCtx, mcpSrv, listenAddr, log, span, serveOpts)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to start HTTP server")
			return err
		}

		span.AddEvent("MCP server configured")
		span.SetStatus(codes.Ok, "Serve() went OK")

		waitForShutdownStreamable(spanCtx, streamableServer, log, span)
	default:
		return fmt.Errorf("invalid transport type: %s", serveOpts.Transport)
	}

	// So, if we reach here, it means graceful shutdown (or forced exit within waitForShutdown).
	return nil
}

func initOtel(ctx context.Context, serveOpts *ServeOptions) (otelShutdown func(context.Context) error, err error) {
	// Determine OTLP endpoint and protocol, preferring flags over environment variables
	otlpEndpoint := serveOpts.OtelExporterOtlpEndpoint
	if otlpEndpoint != "" {
		os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", otlpEndpoint)
	}

	otlpProtocol := serveOpts.OtelExporterOtlpProtocol
	if otlpProtocol != "" {
		os.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", otlpProtocol)
	}

	otelShutdown, err = setupOTelSDK(ctx, serveOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to set up the OTEL stack: %w", err)
	}

	// Set up the tracer.
	serveOpts.Tracer = otel.Tracer(
		"trento-mcp-server",
		trace.WithInstrumentationVersion(versioninfo.Short()),
	)
	return otelShutdown, nil
}

func createMCPServer(ctx context.Context, serveOpts *ServeOptions, log *otelzap.SugaredLogger) (*mcpserver.MCPServer, error) {
	// Load OpenAPI spec.
	oasDoc, err := openapi2mcp.LoadOpenAPISpec(serveOpts.OASPath)
	if err != nil {
		log.ErrorwContext(ctx, "failed to read the API spec", zap.Error(err))
		return nil, fmt.Errorf("failed to read the API spec: %w", err)
	}

	// Overwrite the Trento URL in the OpenAPI
	if len(oasDoc.Servers) > 0 {
		oasDoc.Servers[0].URL = serveOpts.TrentoUrl
	} else {
		oasDoc.Servers = append(oasDoc.Servers, &openapi3.Server{
			URL: serveOpts.TrentoUrl,
		})
	}

	// Create MCP server options.
	opts := []mcpserver.ServerOption{
		mcpserver.WithLogging(),
		mcpserver.WithRecovery(),
	}

	// Create MCP server.
	srv := mcpserver.NewMCPServer("trento-mcp-server", oasDoc.Info.Version, opts...)

	// Extract the API operations.
	operations := openapi2mcp.ExtractOpenAPIOperations(oasDoc)

	// Register them as MCP tools.
	openapi2mcp.RegisterOpenAPITools(srv, operations, oasDoc, nil)

	return srv, nil
}

func startHTTPServer(
	ctx context.Context,
	mcpSrv *mcpserver.MCPServer,
	listenAddr string,
	log *otelzap.SugaredLogger,
	span trace.Span,
	serveOpts *ServeOptions,
) (*CustomStreamableHTTPServer, error) {
	// Wrapper to pass the url and other params in the future
	authContextFuncWrapper := func(c context.Context, r *http.Request) context.Context {
		if !serveOpts.OauthEnabled {
			return authContextFuncNoOauth(c, r, serveOpts.OauthValidateURL, serveOpts.TrentoUrl, serveOpts.TrentoUsername, serveOpts.TrentoPassword)
		}

		return authContextFunc(c, r, serveOpts.OauthValidateURL, serveOpts.TrentoUrl, serveOpts.TrentoUsername, serveOpts.TrentoPassword)
	}

	// Create the server, using custom one to handle mcp auth
	streamableServer := NewCustomStreamableHTTPServer(mcpSrv, "/mcp", authContextFuncWrapper, serveOpts)

	// Run the http server for the mcp in a separate goroutine.
	go func() {
		log.InfowContext(ctx, "mcp server via HTTP starting", "server.address", listenAddr)
		if err := streamableServer.Start(listenAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			log.FatalwContext(ctx, "failed to serve MCP server via HTTP", zap.Error(err))
		}
	}()
	log.InfowContext(ctx, "mcp server via HTTP listening successfully", "server.address", listenAddr)
	return streamableServer, nil
}

func startSSEServer(
	ctx context.Context,
	mcpSrv *mcpserver.MCPServer,
	listenAddr string,
	log *otelzap.SugaredLogger,
	span trace.Span,
	serveOpts *ServeOptions,
) error {

	authContextFuncWrapper := func(c context.Context, r *http.Request) context.Context {
		if !serveOpts.OauthEnabled {
			return authContextFuncNoOauth(c, r, serveOpts.OauthValidateURL, serveOpts.TrentoUrl, serveOpts.TrentoUsername, serveOpts.TrentoPassword)
		}

		return authContextFunc(c, r, serveOpts.OauthValidateURL, serveOpts.TrentoUrl, serveOpts.TrentoUsername, serveOpts.TrentoPassword)
	}

	// Create the server, using custom one to handle mcp auth
	sseServer := mcpserver.NewSSEServer(mcpSrv, mcpserver.WithSSEContextFunc(authContextFuncWrapper))

	// Run the http server for the mcp in a separate goroutine.
	log.InfowContext(ctx, "mcp server via SSE starting", "server.address", listenAddr)
	if err := sseServer.Start(listenAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		log.FatalwContext(ctx, "failed to serve MCP server via HTTP", zap.Error(err))
	}

	log.InfowContext(ctx, "mcp server via SSE listening successfully", "server.address", listenAddr)

	return nil
}

func waitForShutdownStreamable(ctx context.Context, streamableServer *CustomStreamableHTTPServer, log *otelzap.SugaredLogger, span trace.Span) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	log.InfowContext(ctx, "shutting down mcp server")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := streamableServer.Shutdown(shutdownCtx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		log.FatalwContext(ctx, "failed to shut the mcp server down, forcing exit", zap.Error(err))
	}
	log.InfowContext(ctx, "mcp server shut down successfully")
}
