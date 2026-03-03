User Documentation
1.  [[1 ][What is
    Trento?]](sec-trento-what.html)
2.  [[2
    ][Lifecycle]](sec-trento-lifecycle.html)
3.  [[3
    ][Requirements]](sec-trento-requirements.html)
4.  [[4
    ][Installation]](id-installation.html)
5.  [[5 ][Update]](id-update.html)
6.  [[6
    ][Uninstallation]](id-uninstallation.html)
7.  [[7 ][Prometheus
    integration]](id-prometheus-integration.html)
8.  [[8 ][MCP
    Integration]](sec-trento-mcp-integration.html)
9.  [[9 ][Core
    Features]](id-core-features.html)
10. [[10 ][Compliance
    Features]](id-compliance-features.html)
11. [[11 ][Using Trento
    Web]](sec-trento-use-webconsole.html)
12. [[12 ][Integration with SUSE Multi-Linux
    Manager]](sec-integration-with-SUSE-Manager.html)
13. [[13 ][Operations]](id-operations.html)
14. [[14 ][Reporting an
    Issue]](sec-trento-report-problem.html)
15. [[15 ][Problem
    Analysis]](sec-trento-problemanalysis.html)
16. [[16 ][Compatibility matrix between Trento Server and
    Trento Agents]](sec-trento-compatibility-matrix.html)
17. [[17 ][Highlights of Trento
    versions]](sec-trento-version-history.html)
18. [[18 ][More
    information]](sec-trento-more-information.html)
On this page
# [[8 ][MCP Integration]] [\#](sec-trento-mcp-integration.html# "Permalink") 
[ ]
The Trento MCP Server is an optional component that enables AI-assisted
infrastructure management for your SAP landscape. It exposes Trento
functionality through the Model Context Protocol (MCP), an open standard
that facilitates secure communication between data sources and AI
agents. While the core Trento Server operates independently, the Trento
MCP Server component allows you to integrate Trento into an agentic AI
workflow. This enables the use of Large Language Models (LLMs) to
perform common monitoring and troubleshooting tasks using natural
language, providing a standardized way for AI tools to access real-time
system state and best-practice validations.
## [[8.1 ][Installing Trento MCP Server]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-install "Permalink") 
[ ]
The Trento MCP Server can be deployed in different ways depending on
your infrastructure and requirements.
Supported installation methods:
- [Section 8.1.2, "Kubernetes deployment of Trento MCP
  Server"](sec-trento-mcp-integration.html#sec-trento-mcp-server-k8s "8.1.2. Kubernetes deployment of Trento MCP Server")
- [Section 8.1.3, "systemd
  deployment"](sec-trento-mcp-integration.html#sec-trento-mcp-server-systemd "8.1.3. systemd deployment")
### [[8.1.1 ][Prerequisites Trento MCP Server]] [\#](sec-trento-mcp-integration.html#id-prerequisites-trento-mcp-server "Permalink") 
[ ]
The Trento MCP Server is lightweight and stateless. No persistent
storage is required; allocate space for logs as per your logging policy.
Before installing the Trento MCP Server, both Trento Web and Trento
Wanda components must be running and be accessible for the Trento MCP
Server to function properly.
- There must be network connectivity between the Trento MCP Server and
  Trento Server components.
- Access to the Trento Server URL (important when deployed behind NGINX,
  or any other reverse proxy) must be possible.
### [[8.1.2 ][Kubernetes deployment of Trento MCP Server]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-server-k8s "Permalink") 
[ ]
The subsection uses the following placeholders:
- `TRENTO_SERVER_HOSTNAME`: the host name used by the end user
  to access the console.
- `ADMIN_PASSWORD`: the password of the admin user created
  during the installation process.
  The password must meet the following requirements:
  - minimum length of 8 characters
  - the password must not contain 3 identical numbers or letters in a
    row (for example, 111 or aaa)
  - the password must not contain 4 sequential numbers or letters (for
    example, 1234, abcd, ABCD)
#### [[8.1.2.1 ][Enable the Trento MCP Server]] [\#](sec-trento-mcp-integration.html#id-enable-the-trento-mcp-server "Permalink") 
[ ]
When installing Trento Server following the instructions in
[Section 4.1.1, "Kubernetes
deployment"](id-installation.html#sec-trento-k8s-deployment "4.1.1. Kubernetes deployment"),
the Trento MCP Server is disabled by default. Enable it by passing
`--set trento-mcp-server.enabled=true`:
``` programlisting
helm upgrade --install trento-server oci://registry.suse.com/trento/trento-server \
  --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
  --set trento-web.adminUser.password=ADMIN_PASSWORD \
  --set trento-mcp-server.enabled=true
```
The Trento MCP Server will automatically connect to the Trento Web and
Trento Wanda internal services within the Kubernetes cluster.
#### [[8.1.2.2 ][Verify the Trento MCP Server installation]] [\#](sec-trento-mcp-integration.html#id-verify-the-trento-mcp-server-installation "Permalink") 
[ ]
1.  Check that the Trento MCP Server Pod is running:
    ``` programlisting
    kubectl get pods -l app.kubernetes.io/name=mcp-server
    ```
    Example output:
    ``` programlisting
    NAME                                       READY   STATUS    RESTARTS   AGE
    trento-server-mcp-server-xxxxxxxxxx-xxxxx  1/1     Running   0          2m
    ```
2.  Check the logs:
    ``` programlisting
    kubectl logs -l app.kubernetes.io/name=mcp-server
    ```
3.  Check the Trento MCP Server health endpoints:
    ``` programlisting
    # Expose the health check port from the Pod, as it is not exposed as a Kubernetes Service.
    kubectl port-forward --namespace default \
      $(kubectl get pods --namespace default -l app.kubernetes.io/name=mcp-server -o jsonpath="") \
      8080:8080
    ```
    While the previous command is running, perform the following check:
    ``` programlisting
    # Liveness endpoint:
    curl http://localhost:8080/livez
    ```
    ``` programlisting
    # Readiness endpoint:
    curl http://localhost:8080/readyz
    ```
    Example output:
    ``` programlisting
    # Liveness:
    ,"status":"up"}
    # Readiness:
    ,"wanda-api":,"web-api":}}
    ```
#### [[8.1.2.3 ][Trento MCP Server Helm configuration options]] [\#](sec-trento-mcp-integration.html#id-trento-mcp-server-helm-configuration-options "Permalink") 
[ ]
The Trento MCP Server Helm chart supports various configuration options:
- [Section 8.1.2.3.1, "Customize Ingress
  Path"](sec-trento-mcp-integration.html#mcp-customize-ingress-path "8.1.2.3.1. Customize Ingress Path")
- [Section 8.1.2.3.2, "Adjust Log
  Verbosity"](sec-trento-mcp-integration.html#mcp-adjust-log-verbosity "8.1.2.3.2. Adjust Log Verbosity")
- [Section 8.1.2.3.3, "Adjust Resource
  Limits"](sec-trento-mcp-integration.html#mcp-adjust-resource-limits "8.1.2.3.3. Adjust Resource Limits")
- [Section 8.1.2.3.4, "Disabling Health Check
  Probes"](sec-trento-mcp-integration.html#mcp-disabling-health-check-probes "8.1.2.3.4. Disabling Health Check Probes")
##### [[8.1.2.3.1 ][Customize Ingress Path]] [\#](sec-trento-mcp-integration.html#mcp-customize-ingress-path "Permalink") 
[ ]
By default, ingress is enabled. To customize the ingress configuration
in a basic K3s installation, run the command below:
``` programlisting
helm upgrade --install trento-server oci://registry.suse.com/trento/trento-server \
  --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
  --set trento-web.adminUser.password=ADMIN_PASSWORD \
  --set trento-mcp-server.enabled=true \
  --set trento-mcp-server.ingress.hosts[0].host=TRENTO_SERVER_HOSTNAME \
  --set trento-mcp-server.ingress.hosts[0].paths[0].path=/mcp-server-trento \
  --set trento-mcp-server.ingress.hosts[0].paths[0].pathType=ImplementationSpecific
```
The Trento MCP Server endpoint will be:
[`https://TRENTO_SERVER_HOSTNAME/mcp-server-trento/mcp`](https://TRENTO_SERVER_HOSTNAME/mcp-server-trento/mcp)
##### [[8.1.2.3.2 ][Adjust Log Verbosity]] [\#](sec-trento-mcp-integration.html#mcp-adjust-log-verbosity "Permalink") 
[ ]
The default log level is `info`. Adjust it for debugging:
``` programlisting
helm upgrade --install trento-server oci://registry.suse.com/trento/trento-server \
  --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
  --set trento-web.adminUser.password=ADMIN_PASSWORD \
  --set trento-mcp-server.enabled=true \
  --set trento-mcp-server.mcpServer.verbosity=debug
```
##### [[8.1.2.3.3 ][Adjust Resource Limits]] [\#](sec-trento-mcp-integration.html#mcp-adjust-resource-limits "Permalink") 
[ ]
For production deployments with different resource requirements:
``` programlisting
helm upgrade --install trento-server oci://registry.suse.com/trento/trento-server \
  --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
  --set trento-web.adminUser.password=ADMIN_PASSWORD \
  --set trento-mcp-server.enabled=true \
  --set trento-mcp-server.resources.requests.cpu=100m \
  --set trento-mcp-server.resources.requests.memory=128Mi \
  --set trento-mcp-server.resources.limits.cpu=1000m \
  --set trento-mcp-server.resources.limits.memory=1Gi
```
##### [[8.1.2.3.4 ][Disabling Health Check Probes]] [\#](sec-trento-mcp-integration.html#mcp-disabling-health-check-probes "Permalink") 
[ ]
Health check probes are enabled by default. To disable them if needed,
run the following command:
``` programlisting
helm upgrade --install trento-server oci://registry.suse.com/trento/trento-server \
  --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
  --set trento-web.adminUser.password=ADMIN_PASSWORD \
  --set trento-mcp-server.enabled=true \
  --set trento-mcp-server.livenessProbe.enabled=false \
  --set trento-mcp-server.readinessProbe.enabled=false
```
#### [[8.1.2.4 ][Complete configuration example]] [\#](sec-trento-mcp-integration.html#id-complete-configuration-example "Permalink") 
[ ]
Below is a complete example that configures external access via a custom
ingress path:
``` programlisting
helm upgrade --install trento-server oci://registry.suse.com/trento/trento-server \
  --set global.trentoWeb.origin=https://trento.example.com \
  --set trento-web.adminUser.password=SecurePassword123 \
  --set trento-mcp-server.enabled=true \
  --set trento-mcp-server.mcpServer.trentoURL=https://trento.example.com \
  --set trento-mcp-server.ingress.hosts[0].host=trento.example.com \
  --set trento-mcp-server.ingress.hosts[0].paths[0].path=/mcp-server-trento \
  --set trento-mcp-server.ingress.hosts[0].paths[0].pathType=ImplementationSpecific
```
### [[8.1.3 ][systemd deployment]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-server-systemd "Permalink") 
[ ]
A systemd-based installation of the Trento MCP Server using RPM packages
can be performed manually on the latest supported versions of SUSE Linux
Enterprise Server for SAP applications.
[**Supported versions**]:
- SUSE Linux Enterprise Server for SAP applications 15: SP4--SP7
- SUSE Linux Enterprise Server for SAP applications 16.0
#### [[8.1.3.1 ][Installing Trento MCP Server using RPM packages]] [\#](sec-trento-mcp-integration.html#id-installing-trento-mcp-server-using-rpm-packages "Permalink") 
[ ]
1.  Install the Trento MCP Server package:
    ``` programlisting
    zypper install mcp-server-trento
    ```
#### [[8.1.3.2 ][Configure Trento MCP Server]] [\#](sec-trento-mcp-integration.html#id-configure-trento-mcp-server "Permalink") 
[ ]
1.  Create the Trento MCP Server configuration file
    `/etc/trento/mcp-server-trento` by copying the example:
    ``` programlisting
    cp /etc/trento/mcp-server-trento.example /etc/trento/mcp-server-trento
    ```
2.  Edit the configuration file to point to your Trento Server:
    ``` programlisting
    vim /etc/trento/mcp-server-trento
    ```
    Example configuration:
    ``` programlisting
    AUTODISCOVERY_PATHS=/api/all/openapi,/wanda/api/all/openapi
    ENABLE_HEALTH_CHECK=false
    HEADER_NAME=Authorization
    HEALTH_API_PATH=/api/healthz
    HEALTH_PORT=8080
    # OAS_PATH=https://trento.example.com/api/all/openapi,https://trento.example.com/wanda/api/all/openapi
    PORT=5000
    TAG_FILTER=MCP
    TRANSPORT=streamable
    TRENTO_URL=https://trento.example.com
    VERBOSITY=info
    INSECURE_SKIP_TLS_VERIFY=false
    ```
Configure the Trento MCP Server using either `TRENTO_URL` or
`OAS_PATH`.\
If `OAS_PATH` is left empty, the Trento MCP Server
automatically discovers the APIs from the Trento Server using
`TRENTO_URL`.\
If `OAS_PATH` is set, it takes precedence and
`TRENTO_URL` is ignored.
[**Use `TRENTO_URL` when one or more of the following
conditions apply:**]
- Trento Server is deployed behind a reverse proxy (NGINX, etc.).
- The Trento MCP Server runs on a different host or network than Trento
  Server.
- You want to use external or public URLs.
- You prefer automatic API autodiscovery.
[**Use `OAS_PATH` when one or more of the following conditions
apply:**]
- You want to connect directly to internal services without
  autodiscovery.
- You need to bypass reverse proxy configurations.
##### [[8.1.3.2.1 ][Start the Trento MCP Server service]] [\#](sec-trento-mcp-integration.html#id-start-the-trento-mcp-server-service "Permalink") 
[ ]
Enable and start the Trento MCP Server service:
``` programlisting
systemctl enable --now mcp-server-trento
```
#### [[8.1.3.3 ][Verify the Trento MCP Server service]] [\#](sec-trento-mcp-integration.html#id-verify-the-trento-mcp-server-service "Permalink") 
[ ]
1.  Verify the service is running:
    ``` programlisting
    systemctl status mcp-server-trento
    ```
    Expected output:
    ``` programlisting
    ● mcp-server-trento.service - Trento MCP Server service
         Loaded: loaded (/usr/lib/systemd/system/mcp-server-trento.service; enabled)
         Active: active (running) since ...
    ```
2.  Check the service logs:
    ``` programlisting
    journalctl -u mcp-server-trento -f
    ```
3.  If firewalld is running, allow Trento MCP Server to be accessible
    and add an exception to firewalld:
    ``` programlisting
    firewall-cmd --zone=public --add-port=5000/tcp --permanent
    firewall-cmd --reload
    ```
4.  If you enabled health checks and want to expose them, also allow the
    health check port:
    ``` programlisting
    firewall-cmd --zone=public --add-port=8080/tcp --permanent
    firewall-cmd --reload
    ```
5.  If you enabled health checks, verify the endpoints locally:
    ``` programlisting
    # Note: Replace localhost with the server's IP/hostname if running these commands from a remote machine,
    # and ensure the health port is allowed by your firewall.
    # Liveness endpoint:
    curl http://localhost:8080/livez
    # Example output:
    # ,"status":"up"}
    # Readiness endpoint:
    curl http://localhost:8080/readyz
    # Example output:
    # ,"wanda-api":,"web-api":}}
    ```
## [[8.2 ][Configuring Trento MCP Server]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-config "Permalink") 
[ ]
This section provides an overview of how to configure the Trento MCP
Server depending on the deployment method.
- [Section 8.2.1, "Configuration in a Kubernetes
  deployment"](sec-trento-mcp-integration.html#sec-trento-mcp-kubernetes-config "8.2.1. Configuration in a Kubernetes deployment")
- [Section 8.2.2, "Configuration in an systemd
  deployment"](sec-trento-mcp-integration.html#sec-trento-mcp-systemd-config "8.2.2. Configuration in an systemd deployment")
### [[8.2.1 ][Configuration in a Kubernetes deployment]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-kubernetes-config "Permalink") 
[ ]
#### [[8.2.1.1 ][Configuration Sources]] [\#](sec-trento-mcp-integration.html#id-configuration-sources "Permalink") 
[ ]
The Trento MCP Server supports multiple configuration sources with the
following priority order (highest to lowest):
1.  [**Environment variables**] - Used for containerized
    deployments.
2.  [**Built-in defaults**] - Fallback values.
#### [[8.2.1.2 ][Configuration Overview]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-kubernetes-config-sources "Permalink") 
[ ]
  Environment Variable                              Default Value                                         Description
  ------------------------------------------------- ----------------------------------------------------- --------------------------------------------------------------------------------------------
  `TRENTO_MCP_AUTODISCOVERY_PATHS`        `/api/all/openapi,/wanda/api/all/openapi`   Custom paths for API autodiscovery.
  `TRENTO_MCP_ENABLE_HEALTH_CHECK`        `false`                                     Enable the health check server.
  `TRENTO_MCP_CONFIG`                     (empty)                                               Configuration file path.
  `TRENTO_MCP_HEADER_NAME`                `Authorization`                             Header name used to pass the Trento API key to the Trento MCP Server.
  `TRENTO_MCP_HEALTH_API_PATH`            `/api/healthz`                              API path used for health checks on target servers.
  `TRENTO_MCP_HEALTH_PORT`                `8080`                                      Port where the health check server runs.
  `TRENTO_MCP_INSECURE_SKIP_TLS_VERIFY`   `false`                                     Skip TLS certificate verification when fetching OAS specs from HTTPS.
  `TRENTO_MCP_OAS_PATH`                   `[]`                                        Path(s) to OpenAPI specification file(s). Can be set multiple times.
  `TRENTO_MCP_PORT`                       `5000`                                      Port where the Trento MCP Server runs.
  `TRENTO_MCP_TAG_FILTER`                 `["MCP"]`                                   Only include operations that contain one of these tags.
  `TRENTO_MCP_TRANSPORT`                  `streamable`                                Protocol to use: `streamable` or `sse`.
  `TRENTO_MCP_TRENTO_URL`                 (empty)                                               Target Trento server URL. Required for autodiscovery if OAS path is not set.
  `TRENTO_MCP_VERBOSITY`                  `info`                                      Log level: `debug`, `info`, `warning`, or `error`.
#### [[8.2.1.3 ][Kubernetes Deployment Example]] [\#](sec-trento-mcp-integration.html#id-kubernetes-deployment-example "Permalink") 
[ ]
``` programlisting
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server-trento
spec:
  template:
    spec:
      containers:
      - name: mcp-server-trento
        image: mcp-server-trento:latest
        env:
        - name: TRENTO_MCP_PORT
          value: "5000"
        - name: TRENTO_MCP_HEALTH_PORT
          value: "8080"
        - name: TRENTO_MCP_ENABLE_HEALTH_CHECK
          value: "true"
        - name: TRENTO_MCP_TRENTO_URL
          value: "https://trento.example.com"
        - name: TRENTO_MCP_VERBOSITY
          value: "info"
        ports:
        - containerPort: 5000
          name: mcp
        - containerPort: 8080
          name: health
```
### [[8.2.2 ][Configuration in an systemd deployment]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-systemd-config "Permalink") 
[ ]
#### [[8.2.2.1 ][Configuration Sources]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-systemd-config-sources "Permalink") 
[ ]
The Trento MCP Server supports multiple configuration sources with the
following priority order (highest to lowest):
1.  [**Command-line flags**] - Override config for the
    current process.
2.  [**Configuration file**] - Persistent settings
    configuration.
#### [[8.2.2.2 ][Configuration Overview]] [\#](sec-trento-mcp-integration.html#id-configuration-overview "Permalink") 
[ ]
The `mcp-server-trento` binary accepts several command-line
flags to configure its behavior. The following table lists all available
configuration options, their corresponding flags, configuration
variables, and default values.
  Flag                                         Config Variable                        Default Value                                         Description
  -------------------------------------------- -------------------------------------- ----------------------------------------------------- --------------------------------------------------------------------------------------------
  `--autodiscovery-paths, -A`        `AUTODISCOVERY_PATHS`        `/api/all/openapi,/wanda/api/all/openapi`   Custom paths for API autodiscovery.
  `--config, -c`                     (empty)                                (empty)                                               Configuration file path.
  `--enable-health-check, -d`        `ENABLE_HEALTH_CHECK`        `false`                                     Enable the health check server.
  `--header-name, -H`                `HEADER_NAME`                `Authorization`                             Header name used to pass the Trento API key to the Trento MCP Server.
  `--health-api-path, -a`            `HEALTH_API_PATH`            `/api/healthz`                              API path used for health checks on target servers.
  `--health-port, -z`                `HEALTH_PORT`                `8080`                                      Port where the health check server runs.
  `--insecure-skip-tls-verify, -i`   `INSECURE_SKIP_TLS_VERIFY`   `false`                                     Skip TLS certificate verification when fetching OAS specs from HTTPS.
  `--oas-path, -P`                   `OAS_PATH`                   `[]`                                        Path(s) to OpenAPI specification file(s). Can be set multiple times.
  `--port, -p`                       `PORT`                       `5000`                                      Port where the Trento MCP Server runs.
  `--tag-filter, -f`                 `TAG_FILTER`                 `["MCP"]`                                   Only include operations that contain one of these tags.
  `--transport, -t`                  `TRANSPORT`                  `streamable`                                Protocol to use: `streamable` or `sse`.
  `--trento-url, -u`                 `TRENTO_URL`                 (empty)                                               Target Trento server URL. Required for autodiscovery if OAS path is not set.
  `--verbosity, -v`                  `VERBOSITY`                  `info`                                      Log level: `debug`, `info`, `warning`, or `error`.
#### [[8.2.2.3 ][Configure Trento MCP Server with Command-Line Flags]] [\#](sec-trento-mcp-integration.html#id-configure-trento-mcp-server-with-command-line-flags "Permalink") 
[ ]
Trento MCP Server allows you to override configuration settings using
command-line flags for temporary changes. These overrides are not
persistent and are lost when the process stops or the system is
rebooted. To make configuration changes permanent for the systemd
service, update `/etc/trento/mcp-server-trento` and restart
the service.
Basic usage with custom port, verbosity, and target URL:
``` programlisting
mcp-server-trento --port 9000 --verbosity debug --trento-url https://trento.example.com
```
Using multiple OpenAPI specifications:
``` programlisting
mcp-server-trento --oas-path https://api1.example.com/openapi.json --oas-path https://api2.example.com/openapi.json
```
Autodiscovery with custom paths:
``` programlisting
mcp-server-trento --trento-url https://trento.example.com --autodiscovery-paths /api/v1/openapi,/wanda/api/v1/openapi
```
Enable health checks on a custom port:
``` programlisting
mcp-server-trento --enable-health-check --health-port 8080 --port 5000
```
#### [[8.2.2.4 ][Help and Validation]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-help-validation "Permalink") 
[ ]
You can see all available flags by running:
``` programlisting
mcp-server-trento --help
```
The server will validate the configuration on startup and log any issues
with debug verbosity enabled.
### [[8.2.3 ][Health Check Configuration]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-health-checks "Permalink") 
[ ]
The Trento MCP Server includes built-in health check endpoints for
systemd and Kubernetes integration.
![Note](static/images/icon-note.svg "Note")
Note
Health check functionality is disabled by default and must be explicitly
enabled using the `--enable-health-check` flag or the
`TRENTO_MCP_ENABLE_HEALTH_CHECK` environment variable.
#### [[8.2.3.1 ][Health Check Endpoints]] [\#](sec-trento-mcp-integration.html#id-health-check-endpoints "Permalink") 
[ ]
The health check server provides the following endpoints:
- `/livez` - Liveness probe for Kubernetes pod restart
  decisions.
- `/readyz` - Readiness probe for traffic routing decisions.
The readiness endpoint performs comprehensive health checks, including:
- `mcp-server` - Validates Trento MCP Server connectivity
  using an MCP client.
- `api-server` - Verifies connectivity to the configured
  Trento API server.
#### [[8.2.3.2 ][Enable Health Checks with Helm on a Kubernetes deployment]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-k3s-health-helm "Permalink") 
[ ]
Enable health checks when deploying on Kubernetes with Helm:
``` programlisting
helm upgrade \
  --install trento-server oci://registry.suse.com/trento/trento-server \
  --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
  --set trento-web.adminUser.password=ADMIN_PASSWORD \
  --set trento-mcp-server.enabled=true \
  --set TRENTO_MCP_ENABLE_HEALTH_CHECK=true \
  --set TRENTO_MCP_HEALTH_PORT=8080
```
The health port is internal to the Kubernetes cluster. To reach it from
the host running Kubernetes, forward the Pod port. Replace
`NAMESPACE` with your target namespace (Helm defaults to
`default`).
``` programlisting
kubectl port-forward --namespace NAMESPACE \
  $(kubectl get pods --namespace NAMESPACE -l app.kubernetes.io/name=mcp-server -o jsonpath="") \
  8080:8080 &
```
With the port forward active, test the endpoints in [Testing Health
Endpoints](sec-trento-mcp-integration.html#sec-trento-mcp-health-testing "8.2.3.4. Testing Health Endpoints").
#### [[8.2.3.3 ][Enable Health Checks with the command-line for systemd deployment]] [\#](sec-trento-mcp-integration.html#id-enable-health-checks-with-the-command-line-for-systemd-deployment "Permalink") 
[ ]
``` programlisting
mcp-server-trento --enable-health-check
```
``` programlisting
mcp-server-trento --enable-health-check --health-port 8080
```
#### [[8.2.3.4 ][Testing Health Endpoints]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-health-testing "Permalink") 
[ ]
``` programlisting
# Test liveness endpoint
curl http://localhost:8080/livez
# Test readiness endpoint
curl http://localhost:8080/readyz
# Expected readiness response format:
# ,"api-server":,"api-documentation":}}
# Expected liveness response format:
# 
```
### [[8.2.4 ][Troubleshooting]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-troubleshooting "Permalink") 
[ ]
This section provides solutions for common issues when deploying and
using the Trento MCP Server.
#### [[8.2.4.1 ][Connection Issues]] [\#](sec-trento-mcp-integration.html#id-connection-issues "Permalink") 
[ ]
- [**Trento MCP Server cannot connect to Trento API**]
  - Verify the `TRENTO_URL` or `OAS_PATH`
    configuration points to accessible endpoints
  - Check network connectivity between the Trento MCP Server and Trento
    components
  - Ensure API authentication is properly configured with valid tokens
- [**MCP clients cannot connect to Trento MCP Server**]
  - Verify the Trento MCP Server is running and listening on the correct
    port (default: 5000)
  - Check firewall rules allow access to the Trento MCP Server port
  - Ensure the Trento MCP Server endpoint URL is correctly configured in
    client applications
#### [[8.2.4.2 ][Authentication Issues]] [\#](sec-trento-mcp-integration.html#id-authentication-issues "Permalink") 
[ ]
- [**API token authentication fails**]
  - Verify the Personal Access Token is valid and not expired
  - Ensure the token has the necessary permissions in Trento
  - Check that the `HEADER_NAME` configuration matches between
    server and client
- [**Token not accepted**]
  - Confirm the token was generated from the correct Trento instance
  - Verify the token format and ensure it includes the \"Bearer \"
    prefix if required
#### [[8.2.4.3 ][Configuration Issues]] [\#](sec-trento-mcp-integration.html#id-configuration-issues "Permalink") 
[ ]
- [**OpenAPI specification not found**]
  - Check that `TRENTO_URL` or `OAS_PATH` point to
    valid Trento API endpoints
  - Verify the Trento Web and Trento Wanda services are running and
    accessible
  - Ensure autodiscovery paths are correct if using
    `TRENTO_URL`
- [**Tools not appearing in MCP clients**]
  - Check the `TAG_FILTER` configuration - only operations
    with matching tags are exposed
  - Verify the OpenAPI specifications are accessible and valid
  - Ensure the Trento MCP Server can parse the API documentation
#### [[8.2.4.4 ][Performance Issues]] [\#](sec-trento-mcp-integration.html#id-performance-issues "Permalink") 
[ ]
- [**Slow response times**]
  - Check network latency between Trento MCP Server and Trento
    components
  - Review Trento API performance and database query times
  - Consider enabling debug logging to identify bottlenecks
- [**High resource usage**]
  - Monitor Trento MCP Server memory and CPU usage
  - Check for memory leaks in long-running processes
  - Consider adjusting logging verbosity to reduce I/O overhead
#### [[8.2.4.5 ][Health Check Issues]] [\#](sec-trento-mcp-integration.html#id-health-check-issues "Permalink") 
[ ]
- [**Health checks failing**]
  - Verify health check endpoints are accessible
  - Check that all required services (Trento API, Trento MCP Server) are
    responding
  - Review health check configuration and timeouts
#### [[8.2.4.6 ][Logging and Debugging]] [\#](sec-trento-mcp-integration.html#id-logging-and-debugging "Permalink") 
[ ]
- [**Enable debug logging**]
  - Set `VERBOSITY=debug` to get detailed logs
  - Check Trento MCP Server logs for error messages and connection
    attempts
  - Review Trento component logs for API-related issues
- [**Common log messages**]
  - \"Failed to fetch OpenAPI specification\" - Check API endpoint
    accessibility
  - \"Authentication failed\" - Verify API token configuration
  - \"No tools available\" - Check tag filtering and API documentation
#### [[8.2.4.7 ][Getting Help]] [\#](sec-trento-mcp-integration.html#id-getting-help "Permalink") 
[ ]
If you continue to experience issues:
1.  Check the Trento MCP Server logs for detailed error messages
2.  Verify configuration values:
    a.  For systemd deployments, use
        `mcp-server-trento --help`
    b.  For Kubernetes deployments, run Helm with
        `--render-subchart-notes` to view the rendered Trento
        MCP Server settings
3.  Test API connectivity directly using curl or similar tools
4.  Check the Trento server logs for API authentication and access
    issues
## [[8.3 ][Using the Trento MCP Server]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-how-to-use "Permalink") 
[ ]
The Trento MCP Server provides the interface for AI-assisted
infrastructure operations, enabling agentic assistants to integrate with
Trento. By utilizing the Model Context Protocol, these assistants can
perform monitoring and troubleshooting tasks through natural language.
See [MCPHost on
SLES](sec-trento-mcp-integration.html#sec-trento-mcp-sles "8.3.1. Integrating the Trento MCP Server with MCPHost")
or [Using alternative MCP
clients](sec-trento-mcp-integration.html#sec-trento-mcp-others "8.3.2. Integrating the Trento MCP Server with other clients")
for details.
### [[8.3.1 ][Integrating the Trento MCP Server with MCPHost]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-sles "Permalink") 
[ ]
This guide explains how to connect the Trento MCP Server to SUSE Linux
Enterprise Server 16 using MCPHost, a lightweight CLI tool for the Model
Context Protocol (MCP).
![Important](static/images/icon-important.svg "Important")
Important
Supported only on SUSE Linux Enterprise Server for SAP applications 16.0
#### [[8.3.1.1 ][Prerequisites]] [\#](sec-trento-mcp-integration.html#id-prerequisites "Permalink") 
[ ]
To configure MCPHost, ensure you have the following:
#### [[8.3.1.2 ][Prerequisites]] [\#](sec-trento-mcp-integration.html#id-prerequisites-2 "Permalink") 
[ ]
- An LLM provider and credentials.
  - Public hosted options, such as Google Gemini, OpenAI, etc.
  - Private/on-premises option, such as SUSE AI.
- A running Trento Server installation with the Trento MCP Server
  component enabled.
- A Trento Personal Access Token generated in Trento Web Profile view.
  [![Generate a Personal Access Token in
  Trento](images/generate-pat.png "Generate a Personal Access Token in Trento")](images/generate-pat.png)
  [[Figure 8.1: ][Generate a Personal Access Token in
  Trento
  ]][\#](sec-trento-mcp-integration.html#id-1.9.5.3.5.2.3.2 "Permalink")
  [ ]
#### [[8.3.1.3 ][Install MCPHost]] [\#](sec-trento-mcp-integration.html#id-install-mcphost "Permalink") 
[ ]
To install MCPHost, open a terminal and run the following commands:
``` programlisting
sudo zypper refresh
sudo zypper install mcphost
```
After installation, verify that MCPHost is available and working by
checking its version:
``` programlisting
mcphost --version
```
#### [[8.3.1.4 ][Configure MCPHost]] [\#](sec-trento-mcp-integration.html#id-configure-mcphost "Permalink") 
[ ]
MCPHost reads its configuration from several locations; one common
location is `~/.mcphost.yml`. Create
`~/.mcphost.yml` with the following content:
``` programlisting
mcpServers:
  trento-mcp-server:
    type: "remote"
    url: https://trento.example.com/mcp-server-trento/mcp
    headers:
      - "Authorization: Bearer $"
```
- Replace
  [`https://trento.example.com/mcp-server-trento/mcp`](https://trento.example.com/mcp-server-trento/mcp) with the actual URL where your Trento MCP Server is
  accessible:
  - For Kubernetes deployments with ingress, use the ingress URL (e.g.,
    [`https://trento.example.com/mcp-server-trento/mcp`](https://trento.example.com/mcp-server-trento/mcp)).
  - For local or development setups, use
    [`http://localhost:5000/mcp`](http://localhost:5000/mcp) (adjust the port as needed).
  - The transport type is configured on the Trento MCP Server, if using
    Server-Sent Events (SSE) transport instead of the default streamable
    transport, change the path from `/mcp` to
    `/sse`.
- If you configured a custom header name (using `HEADER_NAME`
  or `--header-name`), update `Authorization`
  accordingly.
![Note](static/images/icon-note.svg "Note")
Note
[**Security best practice:**] Keep secrets out of
configuration files. Store your keys in environment variables instead of
hardcoding them.
Export your keys in the shell before running MCPHost. For example:
``` programlisting
export GOOGLE_API_KEY=<your-google-api-key>
export TRENTO_PAT=<your-trento-personal-access-token>
```
![Tip](static/images/icon-tip.svg "Tip")
Tip
Configure remote LLM models directly in your MCPHost configuration. For
example, to use Google Gemini as your model provider:
``` programlisting
model: "google:gemini-2.5-flash"
provider-url: "https://generativelanguage.googleapis.com/v1beta/openai/"
provider-api-key: "$"
mcpServers:
  mcp-server-trento:
    type: "remote"
    url: https://trento.example.com/mcp-server-trento/mcp
    headers:
      - "Authorization: Bearer $"
```
#### [[8.3.1.5 ][Run MCPHost and use Trento tools]] [\#](sec-trento-mcp-integration.html#id-run-mcphost-and-use-trento-tools "Permalink") 
[ ]
1.  Start MCPHost:
    ``` programlisting
    mcphost
    ```
    ![Tip](static/images/icon-tip.svg "Tip")
    Tip
    If no servers appear on startup, confirm your configuration file
    exists at `~/.mcphost.yml` and that your environment
    variables are exported in the same shell session.
2.  Verify the connection to Trento and basic status:
    ``` programlisting
    /servers
    ```
    [![MCPHost initial
    screen](images/mcphost-initial.png "MCPHost initial screen")](images/mcphost-initial.png)
    [[Figure 8.2: ][MCPHost initial screen with the
    Trento MCP Server connected
    ]][\#](sec-trento-mcp-integration.html#id-1.9.5.3.8.2.2.3 "Permalink")
    [ ]
#### [[8.3.1.6 ][Use MCPHost to interact with Trento Server]] [\#](sec-trento-mcp-integration.html#id-use-mcphost-to-interact-with-trento-server "Permalink") 
[ ]
[[Ask the model to invoke Trento tools using natural language prompts,
such as:
]][\#](sec-trento-mcp-integration.html#id-1.9.5.3.9.2 "Permalink")
[ ]
- \"List all SAP systems managed\".
- \"Show my HANA clusters\".
- \"Are my SAP systems compliant?\"
- \"What is the health status of my SAP landscape?\"
- \"Show me all hosts running SAP applications\".
- \"Are there any critical alerts I need to address?\"
- \"Get details about the latest check execution results\".
- \"Which SAP systems are currently running?\"
Example MCPHost session querying Trento about SAP systems:
[![Example MCPHost session with
Trento](images/example-mcphost.png "Example MCPHost session with Trento")](images/example-mcphost.png)
#### [[8.3.1.7 ][MCPHost Troubleshooting]] [\#](sec-trento-mcp-integration.html#id-mcphost-troubleshooting "Permalink") 
[ ]
If you encounter issues connecting MCPHost to the Trento MCP Server:
- [**Connection errors**]
  - Verify that the Trento MCP Server URL in `~/.mcphost.yml`
    is correct and accessible from your system.
  - Check if the Trento MCP Server is running by reviewing logs from
    your Trento installation.
  - Ensure network connectivity and that any required firewall rules are
    in place.
  - Test basic connectivity:
    `curl -I `[`https://trento.example.com/mcp-server-trento/mcp`](https://trento.example.com/mcp-server-trento/mcp).
- [**Authentication errors**]
  - Verify that your personal access token is valid by testing it
    directly with your Trento Server API.
  - Ensure `TRENTO_PAT` is exported in the same shell session
    before running `mcphost`.
  - Check that the header name matches your server configuration
    (default: `Authorization`).
  - Ensure the token has the necessary permissions in Trento.
- [**LLM provider errors**]
  - Verify that LLM `GOOGLE_API_KEY` (or your provider's API
    key) is exported correctly.
  - Check the `provider-url` and `model`
    configuration in your `~/.mcphost.yml`.
  - Confirm that your API key has sufficient quota and permissions with
    your provider.
- [**General issues**]
  - Check the MCPHost terminal output for detailed error messages during
    startup or operation.
  - Review the Trento MCP Server logs for connection attempts and
    errors.
  - Verify that your configuration file exists at
    `~/.mcphost.yml` and has correct YAML syntax.
### [[8.3.2 ][Integrating the Trento MCP Server with other clients]] [\#](sec-trento-mcp-integration.html#sec-trento-mcp-others "Permalink") 
[ ]
The Trento MCP Server can be integrated with any client application that
supports the Model Context Protocol. This makes it possible to interact
with the Trento API and execute tools defined in the OpenAPI
specification through your preferred AI assistant or development tool.
This guide uses Visual Studio Code with GitHub Copilot as an example,
but the configuration procedures apply to any MCP-compatible client.
#### [[8.3.2.1 ][Prerequisites]] [\#](sec-trento-mcp-integration.html#id-prerequisites-3 "Permalink") 
[ ]
To configure your client, make sure that you have the following:
#### [[8.3.2.2 ][Prerequisites]] [\#](sec-trento-mcp-integration.html#id-prerequisites-4 "Permalink") 
[ ]
- An LLM provider and credentials.
  - Public hosted options, such as Google Gemini, OpenAI, etc.
  - Private/on-premises option, such as SUSE AI.
- A running Trento Server installation with the Trento MCP Server
  component enabled.
- A Trento Personal Access Token generated in Trento Web Profile view.
  [![Generate a Personal Access Token in
  Trento](images/generate-pat.png "Generate a Personal Access Token in Trento")](images/generate-pat.png)
  [[Figure 8.3: ][Generate a Personal Access Token in
  Trento
  ]][\#](sec-trento-mcp-integration.html#id-1.9.5.4.5.2.3.2 "Permalink")
  [ ]
#### [[8.3.2.3 ][Configuring your client]] [\#](sec-trento-mcp-integration.html#id-configuring-your-client "Permalink") 
[ ]
Once you have your Trento Server installation ready with the Trento MCP
Server URL and API token, you can configure the MCP Server client. The
examples below show JSON configuration format used by most MCP Server
clients, including VS Code, Claude Desktop, and others.
##### [[8.3.2.3.1 ][Option 1: Configuration with prompted input]] [\#](sec-trento-mcp-integration.html#id-option-1-configuration-with-prompted-input "Permalink") 
[ ]
This configuration asks for your personal access token when the client
starts, keeping credentials secure and out of configuration files. The
`password: true` setting ensures your personal access token
input is masked when you type it.
![Note](static/images/icon-note.svg "Note")
Note
This option is supported by most clients, including VS Code. Check your
client's documentation if the prompt feature is not available.
``` programlisting

    }
  },
  "inputs": [
    
  ]
}
```
##### [[8.3.2.3.2 ][Option 2: Direct header configuration]] [\#](sec-trento-mcp-integration.html#id-option-2-direct-header-configuration "Permalink") 
[ ]
For clients that don't support prompted input, or for testing purposes,
set your Trento personal access token directly in the configuration
file.
![Warning](static/images/icon-warning.svg "Warning")
Warning
When using this option, ensure your configuration file has appropriate
permissions and is not committed to version control systems.
``` programlisting

    }
  }
}
```
![Note](static/images/icon-note.svg "Note")
Note
Replace
[`https://trento.example.com/mcp-server-trento/mcp`](https://trento.example.com/mcp-server-trento/mcp) with your actual Trento MCP Server endpoint URL from
your installation.
##### [[8.3.2.3.3 ][Client options]] [\#](sec-trento-mcp-integration.html#id-client-options "Permalink") 
[ ]
For detailed guidance on taking advantage of MCP capabilities in
different tools, refer to the following official documentation:
- [Visual Studio Code with GitHub Copilot - MCP Server
  Configuration](https://code.visualstudio.com/docs/copilot/customization/mcp-servers).
- [Claude Desktop - Model Context Protocol
  Integration](https://docs.claude.com/en/docs/mcp).
- [Cursor](https://cursor.com/) - AI-powered code
  editor with MCP support.
- [Google Cloud Gemini Code Assist - Agentic
  Chat](https://cloud.google.com/gemini/docs/codeassist/use-agentic-chat-pair-programmer).
- [Windsurf - Cascade MCP
  Support](https://docs.windsurf.com/windsurf/cascade/mcp).
[[Previous][[Chapter 7 ]Prometheus
integration]](id-prometheus-integration.html)
[[Next][[Chapter 9 ]Core
Features]](id-core-features.html)
On this page
- [[[8.1 ][Installing Trento MCP
  Server]](sec-trento-mcp-integration.html#sec-trento-mcp-install)]
- [[[8.2 ][Configuring Trento MCP
  Server]](sec-trento-mcp-integration.html#sec-trento-mcp-config)]
- [[[8.3 ][Using the Trento MCP
  Server]](sec-trento-mcp-integration.html#sec-trento-mcp-how-to-use)]
Share this page
- [](sec-trento-mcp-integration.html# "E-Mail")
- [](sec-trento-mcp-integration.html# "Print this page")
