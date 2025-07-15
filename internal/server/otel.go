// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/carlmjohnson/versioninfo"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutlog"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	logger "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

// See https://opentelemetry.io/docs/languages/sdk-configuration/otlp-exporter/#protocol-configuration
const (
	GRPC          = "grpc"
	HTTP_JSON     = "http/json"
	HTTP_PROTOBUF = "http/protobuf"

	OTEL_EXPORTER_OTLP_ENDPOINT         = "OTEL_EXPORTER_OTLP_ENDPOINT"
	OTEL_EXPORTER_OTLP_LOGS_PROTOCOL    = "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL"
	OTEL_EXPORTER_OTLP_METRICS_PROTOCOL = "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"
	OTEL_EXPORTER_OTLP_PROTOCOL         = "OTEL_EXPORTER_OTLP_PROTOCOL"
	OTEL_EXPORTER_OTLP_TRACES_PROTOCOL  = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"
)

var (
	metricInterval         = 1 * time.Minute
	runtimeMetricsInterval = 15 * time.Second
	traceBatchTimeout      = 5 * time.Second
)

// setupOTelSDK bootstraps the OpenTelemetry pipeline.
// If it does not return an error, make sure to call shutdown for proper cleanup.
func setupOTelSDK(
	ctx context.Context,
	opts *ServeOptions,
) (func(context.Context) error, error) {
	var (
		err           error
		shutdownFuncs []func(context.Context) error
	)

	// shutdown calls cleanup functions registered via shutdownFuncs.
	// The errors from the calls are joined.
	// Each registered cleanup will be invoked once.
	shutdown := func(ctx context.Context) error {
		var err error
		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}

		shutdownFuncs = nil

		return err
	}

	// If OTEL is not enabled, return early.
	if !opts.OtelEnable {
		return shutdown, err
	}

	// handleErr calls shutdown for cleanup and makes sure that all errors are returned.
	handleErr := func(inErr error) {
		err = errors.Join(inErr, shutdown(ctx))
	}

	// Set up propagator.
	prop := newPropagator()
	otel.SetTextMapPropagator(prop)

	// Set up res.
	res, err := newResource()
	if err != nil {
		handleErr(err)

		return shutdown, err
	}

	if opts.OtelEnableTracer {
		// Set up trace provider.
		tracerProvider, err := newTraceProvider(res, opts)
		if err != nil {
			handleErr(err)

			return shutdown, err
		}

		shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)
		otel.SetTracerProvider(tracerProvider)
	}

	if opts.OtelEnableMetrics {
		// Set up meter provider.
		meterProvider, err := newMeterProvider(res, opts)
		if err != nil {
			handleErr(err)

			return shutdown, err
		}

		shutdownFuncs = append(shutdownFuncs, meterProvider.Shutdown)
		otel.SetMeterProvider(meterProvider)
	}

	if opts.OtelEnableLogger {
		// Set up logger provider.
		loggerProvider, err := newLoggerProvider(res, opts)
		if err != nil {
			handleErr(err)

			return shutdown, err
		}

		shutdownFuncs = append(shutdownFuncs, loggerProvider.Shutdown)
		global.SetLoggerProvider(loggerProvider)
	}

	return shutdown, err
}

func newPropagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}

func newTraceProvider(
	res *resource.Resource,
	opts *ServeOptions,
) (*trace.TracerProvider, error) {
	tracerProviderOpts := []trace.TracerProviderOption{
		trace.WithResource(res),
	}

	if os.Getenv(OTEL_EXPORTER_OTLP_TRACES_PROTOCOL) == HTTP_JSON ||
		os.Getenv(OTEL_EXPORTER_OTLP_TRACES_PROTOCOL) == HTTP_PROTOBUF ||
		os.Getenv(OTEL_EXPORTER_OTLP_PROTOCOL) == HTTP_JSON ||
		os.Getenv(OTEL_EXPORTER_OTLP_PROTOCOL) == HTTP_PROTOBUF {
		// If using "http/*" as the OTLP transport, configure the proper exporter.
		httpTraceExporter, err := otlptracehttp.New(
			context.Background(),
			otlptracehttp.WithInsecure(),
		)
		if err != nil {
			return nil, err
		}

		tracerProviderOpts = append(
			tracerProviderOpts,
			trace.WithBatcher(httpTraceExporter, trace.WithBatchTimeout(traceBatchTimeout)),
		)
	} else if os.Getenv(OTEL_EXPORTER_OTLP_TRACES_PROTOCOL) == GRPC || os.Getenv(OTEL_EXPORTER_OTLP_PROTOCOL) == GRPC {
		// If using "grpc" as the OTLP transport, configure the proper exporter, configure the proper exporter.
		grpcTraceExporter, err := otlptracegrpc.New(
			context.Background(),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return nil, err
		}

		tracerProviderOpts = append(tracerProviderOpts, trace.WithBatcher(grpcTraceExporter, trace.WithBatchTimeout(traceBatchTimeout)))
	} else if !opts.OtelDebug {
		return nil, errors.New("unset or misconfigured OTLP transport, please set the OTEL_EXPORTER_OTLP_PROTOCOL or OTEL_EXPORTER_OTLP_TRACES_PROTOCOL env var")
	}

	// if debug is enabled, export traces via stdout
	if opts.OtelDebug {
		stdTraceExporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, err
		}

		tracerProviderOpts = append(
			tracerProviderOpts,
			trace.WithBatcher(stdTraceExporter, trace.WithBatchTimeout(traceBatchTimeout)),
		)
	}

	traceProvider := trace.NewTracerProvider(tracerProviderOpts...)

	return traceProvider, nil
}

func newMeterProvider(
	res *resource.Resource,
	opts *ServeOptions,
) (*metric.MeterProvider, error) {
	var exporter metric.Exporter

	metricProviderOpts := []metric.Option{
		metric.WithResource(res),
	}

	if os.Getenv(OTEL_EXPORTER_OTLP_METRICS_PROTOCOL) == HTTP_JSON ||
		os.Getenv(OTEL_EXPORTER_OTLP_METRICS_PROTOCOL) == HTTP_PROTOBUF ||
		os.Getenv(OTEL_EXPORTER_OTLP_PROTOCOL) == HTTP_JSON ||
		os.Getenv(OTEL_EXPORTER_OTLP_PROTOCOL) == HTTP_PROTOBUF {
		// If using "http/*" as the OTLP transport, configure the proper exporter.
		httpMetricExporter, err := otlpmetrichttp.New(
			context.Background(),
			otlpmetrichttp.WithInsecure(),
		)
		if err != nil {
			return nil, err
		}

		exporter = httpMetricExporter
	} else if os.Getenv(OTEL_EXPORTER_OTLP_METRICS_PROTOCOL) == GRPC || os.Getenv(OTEL_EXPORTER_OTLP_PROTOCOL) == GRPC {
		// If using "grpc" as the OTLP transport, configure the proper exporter, configure the proper exporter.
		grpcMetricExporter, err := otlpmetricgrpc.New(
			context.Background(),
			otlpmetricgrpc.WithInsecure(),
		)
		if err != nil {
			return nil, err
		}

		exporter = grpcMetricExporter
	} else if !opts.OtelDebug {
		return nil, errors.New("unset or misconfigured OTLP transport, please set the OTEL_EXPORTER_OTLP_PROTOCOL or OTEL_EXPORTER_OTLP_METRICS_PROTOCOL env var")
	}

	metricProviderOpts = append(metricProviderOpts, metric.WithReader(
		metric.NewPeriodicReader(exporter,
			metric.WithInterval(metricInterval),
			metric.WithProducer(runtime.NewProducer()),
		)))

	// if debug is enabled, export metrics via stdout
	if opts.OtelDebug {
		stdMetricExporter, err := stdoutmetric.New()
		if err != nil {
			return nil, err
		}

		metricProviderOpts = append(metricProviderOpts, metric.WithReader(
			metric.NewPeriodicReader(stdMetricExporter,
				metric.WithInterval(metricInterval),
				metric.WithProducer(runtime.NewProducer()),
			)))
	}

	meterProvider := metric.NewMeterProvider(metricProviderOpts...)

	// Start go runtime metric collection.
	err := runtime.Start(runtime.WithMinimumReadMemStatsInterval(runtimeMetricsInterval))
	if err != nil {
		return nil, err
	}

	return meterProvider, nil
}

func newLoggerProvider(
	res *resource.Resource,
	opts *ServeOptions,
) (*logger.LoggerProvider, error) {
	loggerProviderOpts := []logger.LoggerProviderOption{
		logger.WithResource(res),
	}

	if os.Getenv(OTEL_EXPORTER_OTLP_LOGS_PROTOCOL) == HTTP_JSON ||
		os.Getenv(OTEL_EXPORTER_OTLP_LOGS_PROTOCOL) == HTTP_PROTOBUF ||
		os.Getenv(OTEL_EXPORTER_OTLP_PROTOCOL) == HTTP_JSON ||
		os.Getenv(OTEL_EXPORTER_OTLP_PROTOCOL) == HTTP_PROTOBUF {
		// If using "http" as the OTLP transport, configure the proper exporter.
		httpLogExporter, err := otlploghttp.New(
			context.Background(),
			otlploghttp.WithInsecure(),
		)
		if err != nil {
			return nil, err
		}

		loggerProviderOpts = append(
			loggerProviderOpts,
			logger.WithProcessor(logger.NewBatchProcessor(httpLogExporter)),
		)
	} else if os.Getenv(OTEL_EXPORTER_OTLP_LOGS_PROTOCOL) == GRPC || os.Getenv(OTEL_EXPORTER_OTLP_PROTOCOL) == GRPC {
		// If using "grpc" as the OTLP transport, configure the proper exporter, configure the proper exporter.
		grpcLogExporter, err := otlploggrpc.New(
			context.Background(),
			otlploggrpc.WithInsecure(),
		)
		if err != nil {
			return nil, err
		}

		loggerProviderOpts = append(loggerProviderOpts, logger.WithProcessor(logger.NewBatchProcessor(grpcLogExporter)))
	} else if !opts.OtelDebug {
		return nil, errors.New("unset or misconfigured OTLP transport, please set the OTEL_EXPORTER_OTLP_PROTOCOL or OTEL_EXPORTER_OTLP_LOGS_PROTOCOL env var")
	}

	// if debug is enabled, export logger via stdout
	if opts.OtelDebug {
		stdLogExporter, err := stdoutlog.New()
		if err != nil {
			return nil, err
		}

		loggerProviderOpts = append(
			loggerProviderOpts,
			logger.WithProcessor(logger.NewBatchProcessor(stdLogExporter)),
		)
	}

	loggerProvider := logger.NewLoggerProvider(loggerProviderOpts...)

	return loggerProvider, nil
}

func newResource() (*resource.Resource, error) {
	hostName, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			resource.Default().SchemaURL(),
			semconv.ServiceNameKey.String("trento-mcp-server"),
			semconv.ServiceVersionKey.String(versioninfo.Short()),
			semconv.TelemetrySDKLanguageGo,
			semconv.HostNameKey.String(hostName),
			semconv.ProcessPIDKey.Int64(int64(os.Getpid())),
		),
	)
	if err != nil {
		return nil, err
	}

	return r, nil
}
