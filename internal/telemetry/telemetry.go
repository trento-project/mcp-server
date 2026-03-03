package telemetry

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
)

// Provider holds both metric and trace providers.
type Provider struct {
	MetricProvider *metric.MeterProvider
	TraceProvider  *trace.TracerProvider
}

// InitializeOTLP sets up OTEL exporters for metrics and traces, sending to the given endpoint.
// endpoint should be in format "localhost:4317" for gRPC.
func InitializeOTLP(ctx context.Context, endpoint string) (*Provider, error) {
	slog.InfoContext(ctx, "initializing OTEL", "endpoint", endpoint)

	// Create resource
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("trento-agent"),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create resource", "error", err)
		return nil, err
	}

	// Initialize metric exporter (optional - Phoenix only supports traces)
	metricExporter, err := otlpmetricgrpc.New(
		ctx,
		otlpmetricgrpc.WithEndpoint(endpoint),
		otlpmetricgrpc.WithInsecure(),
	)
	var meterProvider *metric.MeterProvider
	if err != nil {
		slog.WarnContext(ctx, "metrics exporter not available (this is normal for Phoenix/trace-only backends)", "error", err)
		// Create a no-op meter provider
		meterProvider = metric.NewMeterProvider()
	} else {
		// Create metric provider with exporter
		meterProvider = metric.NewMeterProvider(
			metric.WithResource(res),
			metric.WithReader(metric.NewPeriodicReader(metricExporter)),
		)
		slog.InfoContext(ctx, "metrics exporter initialized successfully")
	}

	// Initialize trace exporter
	traceExporter, err := otlptracegrpc.New(
		ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		slog.ErrorContext(ctx, "failed to create trace exporter", "error", err)
		return nil, err
	}

	// Create trace provider
	traceProvider := trace.NewTracerProvider(
		trace.WithResource(res),
		trace.WithBatcher(traceExporter),
	)

	otel.SetMeterProvider(meterProvider)
	otel.SetTracerProvider(traceProvider)

	slog.InfoContext(ctx, "OTEL initialized successfully")
	return &Provider{
		MetricProvider: meterProvider,
		TraceProvider:  traceProvider,
	}, nil
}

// Shutdown gracefully shuts down both providers.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p.MetricProvider != nil {
		if err := p.MetricProvider.Shutdown(ctx); err != nil {
			slog.WarnContext(ctx, "failed to shutdown metric provider (non-fatal)", "error", err)
			// Don't return error - metrics are optional
		}
	}
	if err := p.TraceProvider.Shutdown(ctx); err != nil {
		slog.ErrorContext(ctx, "failed to shutdown trace provider", "error", err)
		return err
	}
	slog.InfoContext(ctx, "OTEL providers shut down successfully")
	return nil
}
