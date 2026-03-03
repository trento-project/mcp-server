# Trento MCP Server Container Image

## Description

The Trento MCP Server is a [Model Context Protocol](https://modelcontextprotocol.io/introduction) (MCP) implementation that bridges the gap between AI assistants and the [Trento Project](https://www.trento-project.io). Instead of navigating through web interfaces, you can now manage and monitor your SAP systems by simply conversing with your AI assistant in natural language.

Whether you're checking cluster health, reviewing system configurations, or analyzing SAP landscapes, the Trento MCP Server enables you to work more efficiently by bringing Trento's powerful capabilities directly into your AI-powered workflow. It connects to SUSE Linux Enterprise Server (SLES), which provides native agentic AI support through MCPHost integration, and it is also supported by SUSE AI for private, on-premises AI deployments.

[Watch this video](https://www.youtube.com/watch?v=7kDVc3YUR-U) demonstrating how the Trento MCP Server transforms complex SAP monitoring tasks into simple natural language conversations.

## Usage

To run the Trento MCP Server using the container image, use the following command:

```console
docker run -d \
  --name mcp-server-trento \
  -p 5000:5000 \
  -e TRENTO_MCP_TRENTO_URL=https://demo.trento-project.io/ \
  registry.suse.com/trento/mcp-server-trento
```

Refer to the [official SUSE documentation](https://documentation.suse.com/sles-sap/trento/html/SLES-SAP-trento/sec-trento-mcp-integration.html) for detailed instructions on configuring the Trento MCP Server and connecting it to your AI assistant.

Once configured, you can interact with Trento through your AI assistant using natural language:

- **Ask questions conversationally**:
"_Show me all SAP systems in my landscape_"
"_What's the health status of cluster cluster-1?_"
"_List all hosts running HANA databases_"
"_Get details about the checks execution history_"
"_Are there any critical alerts I need to address?_"

- **Get instant insights**:
"_Summarize the overall health of my SAP environment_"
"_Which systems need attention today?_"
"_Show me the latest check results for production systems_"

The AI assistant will use the Trento MCP Server to execute these requests and present the results in a conversational format.

## Licensing

`SPDX-License-Identifier: Apache-2.0`

This project is licensed under the Apache License 2.0. See the [LICENSE](https://github.com/trento-project/mcp-server/blob/main/LICENSE) file for details.
