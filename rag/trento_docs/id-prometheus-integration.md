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
# [[7 ][Prometheus integration]] [\#](id-prometheus-integration.html# "Permalink") 
[ ]
Prometheus Server is a Trento Server component responsible for
retrieving the memory and CPU utilization metrics collected by the
`node-exporter` in the agent hosts and serving them to the web
component. The web component renders the metrics as dynamic graphical
charts in the details view of the registered hosts.
## [[7.1 ][Requirements]] [\#](id-prometheus-integration.html#id-requirements "Permalink") 
[ ]
The `node-exporter` must be installed and running in the agent
hosts and Prometheus Server must be able to reach the agent hosts at the
IP address and port that the `node-exporter` is bound to.
The IP address and port that Prometheus Server uses to reach the
`node-exporter` can be changed by setting parameter
`node-exporter-target` with value
`<ip_address>:<port>` in the agent configuration file.
If the parameter is not set, Prometheus Server uses the lowest IPv4
address discovered in the host with default port 9100.
## [[7.2 ][Kubernetes deployment]] [\#](id-prometheus-integration.html#id-kubernetes-deployment "Permalink") 
[ ]
When using the Helm chart to deploy Trento Server on a Kubernetes
cluster, an image of Prometheus Server is deployed automatically. No
further actions are required by the user, other than ensuring that it
can reach the `node-exporter` in the agent hosts.
In a Kubernetes cluster with multiple nodes, the user can select on
which node to deploy the Prometheus Server by adding the following flag
to the Helm installation command:
``` programlisting
--set prometheus.server.nodeSelector.LABEL=<value>
```
Where `<value>` is the label assigned to the node where the
user wants Prometheus Server to be deployed.
## [[7.3 ][systemd deployment]] [\#](id-prometheus-integration.html#id-systemd-deployment "Permalink") 
[ ]
In a systemd deployment of Trento Server, you can choose between using
an existing installation of Prometheus Server, installing a dedicated
Prometheus Server instance, or not using Prometheus Server at all.
### [[7.3.1 ][Use an existing installation]] [\#](id-prometheus-integration.html#id-use-an-existing-installation "Permalink") 
[ ]
If you already have an existing Prometheus Server that you want to use
with Trento Server, you must set `CHARTS_ENABLED=true` and
`PROMETHEUS_URL` pointing to the right address and port in the
Trento Web configuration file. You must restart restart the Trento Web
service to enable the changes.
The lowest required Prometheus Server version is 2.28.0.
Use the section Install Prometheus on SUSE Linux Enterprise Server for
SAP applications 16.0 as a reference to adjust the Prometheus Server
configuration.
### [[7.3.2 ][Install Prometheus Server from SUSE Package Hub on SUSE Linux Enterprise Server for SAP applications 15.x]] [\#](id-prometheus-integration.html#id-install-prometheus-server-from-suse-package-hub-on-suse-linux-enterprise-server-for-sap-applications-15-x "Permalink") 
[ ]
SUSE Package Hub packages are tested by SUSE but are not officially
supported as part of the SUSE Linux Enterprise Server for SAP
applications base product. Users should assess the suitability of these
packages based on their own risk tolerance and support needs.
Enable the SUSE Package Hub repository (replace `15.x` with
the version of your operating system, for example 15.7):
``` programlisting
SUSEConnect --product PackageHub/15.x/x86_64
zypper refresh
```
Now proceed with the same steps as in Install Prometheus on SUSE Linux
Enterprise Server for SAP applications 16.0.
### [[7.3.3 ][Install Prometheus on SUSE Linux Enterprise Server for SAP applications 16.0]] [\#](id-prometheus-integration.html#id-install-prometheus-on-suse-linux-enterprise-server-for-sap-applications-16-0 "Permalink") 
[ ]
1.  Create the Prometheus user and group:
    ``` programlisting
    groupadd --system prometheus
    useradd -s /sbin/nologin --system -g prometheus prometheus
    ```
2.  Install Prometheus using Zypper:
    ``` programlisting
    zypper in golang-github-prometheus-prometheus
    ```
3.  Configure Prometheus for Trento by replacing or updating the
    existing configuration at `/etc/prometheus/prometheus.yml`
    with:
    ``` programlisting
    global:
      scrape_interval: 30s
      evaluation_interval: 10s
    scrape_configs:
      - job_name: "http_sd_hosts"
        honor_timestamps: true
        scrape_interval: 30s
        scrape_timeout: 30s
        scheme: http
        follow_redirects: true
        http_sd_configs:
          - follow_redirects: true
            refresh_interval: 1m
            url: http://localhost:4000/api/prometheus/targets
    ```
    Note: the value of the `url` parameter above assumes that
    the Trento Web service is running in the same host as Prometheus
    Server.
4.  Enable and start the Prometheus service:
    ``` programlisting
    systemctl enable --now prometheus
    ```
5.  If firewalld is running, allow Prometheus to be accessible and add
    an exception to firewalld:
    ``` programlisting
    firewall-cmd --zone=public --add-port=9090/tcp --permanent
    firewall-cmd --reload
    ```
6.  Set `CHARTS_ENABLED=true` and
    `PROMETHEUS_URL=http://localhost:9090` in the Trento Web
    configuration file and restart the Trento Web service.
    ``` programlisting
    systemctl restart trento-web
    ```
    Note: the value of the `PROMETHEUS_URL` parameter above
    assumes that the Trento Web service is running in the same host as
    Prometheus Server.
### [[7.3.4 ][Not using Prometheus Server]] [\#](id-prometheus-integration.html#id-not-using-prometheus-server "Permalink") 
[ ]
If you decide not to use Prometheus Server in your Trento installation,
you must disable graphical charts in the UI by setting
`CHARTS_ENABLED=false` in the Trento Web configuration file.
[[Previous][[Chapter 6
]Uninstallation]](id-uninstallation.html)
[[Next][[Chapter 8 ]MCP
Integration]](sec-trento-mcp-integration.html)
On this page
- [[[7.1
  ][Requirements]](id-prometheus-integration.html#id-requirements)]
- [[[7.2 ][Kubernetes
  deployment]](id-prometheus-integration.html#id-kubernetes-deployment)]
- [[[7.3 ][systemd
  deployment]](id-prometheus-integration.html#id-systemd-deployment)]
Share this page
- [](id-prometheus-integration.html# "E-Mail")
- [](id-prometheus-integration.html# "Print this page")
