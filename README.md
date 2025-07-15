<!--
  ~ Copyright 2025 SUSE LLC
  ~ SPDX-License-Identifier: Apache-2.0
-->

# Trento MCP Server

[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=flat-square&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=trento&config=%7B%22type%22%3A%20%22http%22%2C%22url%22%3A%20%22http%3A%2F%2Flocalhost%3A5000%2Fmcp%22%7D)

> [!WARNING]
> This project is still in very early stages of development and may not be fully functional or stable. For now, it serves as a proof of concept and a starting point for building MCP servers that integrate with the Trento API.

`Trento MCP Server` is a Model Context Protocol (MCP) server application written in Go. It leverages [github.com/jedisct1/openapi-mcp](https://github.com/jedisct1/openapi-mcp/) to generate tools and server logic based on the API specification defined in `api/openapi.json`. This approach ensures that the server remains consistent with the OpenAPI spec and can be easily extended or updated as the API evolves.

## Features

- **OpenAPI-Driven Tool Generation:**
  - The server uses the OpenAPI specification in `api/openapi.json` to automatically generate tools and endpoints, ensuring strong alignment between the API contract and implementation.
- **Security:**
  - Acts as a resource server, enforcing access control and protecting resources.
  - Delegates authorization to an external authorization server, following best practices for secure, standards-based authentication and authorization flows.
  - Once the authorization request is successful, the server creates a session in the Trento API using a hardcoded username and password. This session is then used to interact with the Trento API on behalf of the authenticated user.
- **Container-Ready:**
  - Includes a Dockerfile for easy containerization and deployment.
- **Observability with OpenTelemetry (OTEL):**
  - Integrated with OpenTelemetry for distributed tracing, metrics, and logging.
  - Supports OTLP exporters (gRPC and HTTP) and can be configured via environment variables.
  - Enables monitoring and observability for production and development environments.

## Getting Started

Go to the the [documentation](docs/README.md) for detailed information on how to set up, configure, and use the `Trento MCP Server`. We recommend starting with the [VS Code integration guide](docs/integration-vscode.md) to learn how to use it along with Visual Studio Code. Alternatively, you can refer to the [SUSE AI integration guide](docs/integration-suse-ai.md) to understand how to deploy and use this project with SUSE AI.

## License

See the [LICENSE](LICENSE) notice.
