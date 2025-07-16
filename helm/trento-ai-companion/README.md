<!--
  ~ Copyright 2025 SUSE LLC
  ~ SPDX-License-Identifier: Apache-2.0
-->

# Helm package for trento-ai-companion

<!-- This readme has been created with this tool: https://github.com/bitnami/readme-generator-for-helm
    > node "./readme-generator-for-helm/bin/index.js" -v ./helm/values.yaml -r ./helm/README.md
-->

## TL;DR

```console
helm -n suse-ai upgrade --install trento-for-suse-ai ./helm/trento-ai-companion --values ./values.mcpo.yaml
helm -n suse-ai upgrade --install mcp-auth ./helm/trento-ai-companion --values ./values.auth.yaml
helm -n suse-ai upgrade --install mcp-stream ./helm/trento-ai-companion --values ./values.stream.yaml
```

## Parameters

### Common parameters

| Name                      | Description                                                        | Value           |
| ------------------------- | ------------------------------------------------------------------ | --------------- |
| `kubernetesClusterDomain` | The Kubernetes cluster domain used for internal service DNS names. | `cluster.local` |

### MCPO component

| Name                             | Description                                                          | Value                                                  |
| -------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------ |
| `mcpo.enabled`                   | Enable the MCPO component.                                           | `false`                                                |
| `mcpo.args`                      | Command-line arguments for the MCPO container.                       | `["--port=8000","--config","/app/config/config.json"]` |
| `mcpo.image.repository`          | The container image repository for the MCPO component.               | `ghcr.io/open-webui/mcpo`                              |
| `mcpo.image.tag`                 | The container image tag for the MCPO component.                      | `main`                                                 |
| `mcpo.resources.limits.cpu`      | The CPU limit for the MCPO pod.                                      | `1`                                                    |
| `mcpo.resources.limits.memory`   | The memory limit for the MCPO pod.                                   | `1Gi`                                                  |
| `mcpo.resources.requests.cpu`    | The CPU request for the MCPO pod.                                    | `200m`                                                 |
| `mcpo.resources.requests.memory` | The memory request for the MCPO pod.                                 | `256Mi`                                                |
| `mcpo.ports`                     | Port configuration for the MCPO service.                             | `[]`                                                   |
| `mcpo.replicas`                  | The number of pod replicas for the MCPO deployment.                  | `1`                                                    |
| `mcpo.type`                      | The type of Kubernetes service for MCPO (e.g., ClusterIP, NodePort). | `ClusterIP`                                            |

### MCP Server for Trento component

| Name                                        | Description                                                                                                                              | Value                                                                                                                                                                                             |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mcpServerTrento.ingress.enabled`           | Enable ingress for the mcpServerTrento service.                                                                                          | `true`                                                                                                                                                                                            |
| `mcpServerTrento.ingress.ingressClassName`  | The class of the ingress controller to use.                                                                                              | `traefik`                                                                                                                                                                                         |
| `mcpServerTrento.ingress.tls`               | Enable TLS for the ingress.                                                                                                              | `true`                                                                                                                                                                                            |
| `mcpServerTrento.ingress.hosts`             | Ingress hosts configuration for the mcpServerTrento service.                                                                             | `[]`                                                                                                                                                                                              |
| `mcpServerTrento.args`                      | Command-line arguments for the MCP Server Trento container. Includes settings for port, transport, paths, and Trento connection details. | `["--port=8080","--transport=sse","--oasPath=/app/api/openapi.json","--oauth-enabled=false","--trento-url=https://demo.trento-project.io","--trento-username=demo","--trento-password=demopass"]` |
| `mcpServerTrento.image.repository`          | The container image repository for the MCP Server Trento component.                                                                      | `antgamdia/mcp-server-trento`                                                                                                                                                                     |
| `mcpServerTrento.image.tag`                 | The container image tag for the MCP Server Trento component.                                                                             | `latest`                                                                                                                                                                                          |
| `mcpServerTrento.resources.limits.cpu`      | The CPU limit for the MCP Server Trento pod.                                                                                             | `500m`                                                                                                                                                                                            |
| `mcpServerTrento.resources.limits.memory`   | The memory limit for the MCP Server Trento pod.                                                                                          | `512Mi`                                                                                                                                                                                           |
| `mcpServerTrento.resources.requests.cpu`    | The CPU request for the MCP Server Trento pod.                                                                                           | `100m`                                                                                                                                                                                            |
| `mcpServerTrento.resources.requests.memory` | The memory request for the MCP Server Trento pod.                                                                                        | `128Mi`                                                                                                                                                                                           |
| `mcpServerTrento.ports`                     | Port configuration for the mcpServerTrento service.                                                                                      | `[]`                                                                                                                                                                                              |
| `mcpServerTrento.replicas`                  | The number of pod replicas for the MCP Server Trento deployment.                                                                         | `1`                                                                                                                                                                                               |
| `mcpServerTrento.type`                      | The type of Kubernetes service for MCP Server Trento (e.g., ClusterIP, NodePort).                                                        | `ClusterIP`                                                                                                                                                                                       |
