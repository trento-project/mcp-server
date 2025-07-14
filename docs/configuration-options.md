# Configuration Options

This document provides an overview of how to configure the `mcp-server-trento` server, including command-line parameters and environment variables.

## Command-Line Parameters

The `mcp-server-trento` binary accepts several command-line flags to configure its behavior. You can pass these flags when running the binary directly or via the Makefile.

| Flag                               | Default                                                       | Description                                                                                       |
| ---------------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `--port`, `-p`                     | 5000                                                          | The port on which to run the server                                                               |
| `--oasPath`, `-P`                  | ./api/openapi.json                                            | Path to the OpenAPI spec file                                                                     |
| `--transport`                      | sse                                                           | The protocol to use, choose 'streamable' or 'sse'                                                 |
| `--base-url`                       | ""                                                            | Base URL where the mcp is deployed, if none, <http://localhost:port> is used                      |
| `--oauth-enabled`                  | false                                                         | Enable the oauth authentication in the MCP                                                        |
| `--oauth-authorization-server-url` | <https://my-idp.example.com/.well-known/openid-configuration> | URL for the OAuth authorization server endpoint                                                   |
| `--oauth-issuer`                   | <https://my-idp.example.com/>                                 | Issuer for the OAuth flow                                                                         |
| `--oauth-validate-url`             | <https://my-idp.example.com/userinfo>                         | URL for token validation                                                                          |
| `--trento-url`                     | <https://demo.trento-project.io>                              | URL for the target Trento server                                                                  |
| `--trento-username`                | demo                                                          | Username for the target Trento server                                                             |
| `--trento-password`                | demopass                                                      | Password for the target Trento server                                                             |
| `--enable-otel`, `-o`              | false                                                         | Enable OpenTelemetry globally                                                                     |
| `--with-tracer`, `-t`              | true                                                          | Enable OpenTelemetry tracing                                                                      |
| `--with-logging`, `-l`             | true                                                          | Enable OpenTelemetry logging                                                                      |
| `--with-metrics`, `-m`             | true                                                          | Enable OpenTelemetry metrics                                                                      |
| `--otel-debug`                     | false                                                         | Enable OpenTelemetry debug mode                                                                   |
| `--otel-exporter-otlp-endpoint`    | <http://localhost:4317>                                       | OTLP exporter endpoint (overrides OTEL_EXPORTER_OTLP_ENDPOINT env var)                            |
| `--otel-exporter-otlp-protocol`    | grpc                                                          | OTLP exporter protocol (e.g., grpc, http/protobuf; overrides OTEL_EXPORTER_OTLP_PROTOCOL env var) |
| `--verbosity`, `-v`                | 0                                                             | Log level verbosity (-1: debug, 0: info, 5: fatal)                                                |

You can see all available flags by running:

```console
./mcp-server-trento --help
```

## Environment Variables

You can also configure `mcp-server-trento` using environment variables, especially for OTEL and OAuth settings. These are useful for containerized deployments and CI/CD pipelines.

| Variable                              | Description                                                            |
| ------------------------------------- | ---------------------------------------------------------------------- |
| `OTEL_EXPORTER_OTLP_ENDPOINT`         | OTLP exporter endpoint (overridden by `--otel-exporter-otlp-endpoint`) |
| `OTEL_EXPORTER_OTLP_PROTOCOL`         | OTLP exporter protocol (overridden by `--otel-exporter-otlp-protocol`) |
| `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`  | OTLP traces protocol (http/json, http/protobuf, grpc)                  |
| `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` | OTLP metrics protocol (http/json, http/protobuf, grpc)                 |
| `OTEL_EXPORTER_OTLP_LOGS_PROTOCOL`    | OTLP logs protocol (http/json, http/protobuf, grpc)                    |
| `PORT`                                | The port on which to run the server (overridden by `--port`)           |
| `OAS_PATH`                            | Path to the OpenAPI spec file (overridden by `--oasPath`)              |

## Example Usage

### Run with Custom Port and OTEL Endpoint

```console
./mcp-server-trento --port 8080 --enable-otel --otel-exporter-otlp-endpoint http://otel-collector:4317
```

Or with environment variables:

```console
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
export PORT=8080
./mcp-server-trento --enable-otel
```
