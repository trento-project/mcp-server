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
# [[3 ][Requirements]] [\#](sec-trento-requirements.html# "Permalink") 
[ ]
This section describes requirements for the Trento Server and its Trento
Agents, as well as the SAP systems and clusters that we want to monitor
in the backend environment.
## [[3.1 ][Trento Server requirements]] [\#](sec-trento-requirements.html#sec-trento-server-requirements "Permalink") 
[ ]
Running all the Trento Server components requires a minimum of 4 GB of
RAM, two CPU cores and 64 GB of storage. When using K3s, such storage
should be provided under `/var/lib/rancher/k3s`.
Trento is based on event-driven technology. Registered events are stored
in a PostgreSQL database with a default retention period of 10 days. For
each host registered with Trento, you need to allocate at least 1.5GB of
space in the PostgreSQL database.
Trento Server supports different deployment scenarios: Kubernetes and
systemd. A Kubernetes-based deployment of Trento Server is cloud-native
and OS-agnostic. It can be performed on the following services:
- RKE2
- a Kubernetes service in a cloud provider
- any other CNCF-certified Kubernetes running on x86_64 architecture
The Helm chart and the container images required for a Kubernetes-based
deployment are available in SUSE public registry.
A production-ready Kubernetes-based deployment of Trento Server requires
Kubernetes knowledge. The Helm chart is intended to be used by customers
without in-house Kubernetes expertise, or as a way to try Trento with a
minimum of effort. However, Helm chart delivers a basic deployment of
the Trento Server with all the components running on a single node of
the cluster.
The packages required for a systemd deployment are available in the
repositories of SUSE Linux Enterprise Server for SAP applications 15
(SP4 or higher) or SUSE Linux Enterprise Server for SAP applications
16.0.
## [[3.2 ][Trento Agent requirements]] [\#](sec-trento-requirements.html#sec-trento-agent-requirements "Permalink") 
[ ]
The resource footprint of the Trento Agent is designed to not impact the
performance of the host it runs on.
The Trento Agent component needs to interact with several low-level
system components that are part of the SUSE Linux Enterprise Server for
SAP applications distribution.
The hosts must have unique machine identifiers (ids) in order to be
registered in Trento. This means that if a host in your environment is
built as a clone of another one, make sure to change the machine's
identifier as part of the cloning process before starting the Trento
Agent on it.
Similarly, the clusters must have unique authkeys in order to be
registered in Trento.
The Trento Agent package is available in the repositories of SUSE Linux
Enterprise Server for SAP applications 15 (SP4 or higher) or SUSE Linux
Enterprise Server for SAP applications 16.0.
## [[3.3 ][Network requirements]] [\#](sec-trento-requirements.html#sec-trento-network-requirements "Permalink") 
[ ]
- Required inbound connectivity:
  - From any Trento Agent host to Trento Server at port TCP/80 (HTTP),
    or TCP/443 (HTTPS) if SSL is enabled.
  - From any Trento Agent host to Trento Server at port TCP/5672
    (Advanced Message Queuing Protocol or AMQP)
  - From the user network to Trento Server at port TCP/80 (HTTP), or
    TCP/443 (HTTPS) if SSL is enabled.
  - If the Trento MCP Server is installed and enabled:
    - For a Kubernetes deployment, from the MCP client to the Trento
      Server ingress at TCP/80 or TCP/443. Internally, the MCP Server
      Pod uses TCP/5000 and TCP/8080 if the health check is enabled.
    - For a systemd deployment, from the user network to Trento MCP
      Server at TCP/5000.
  - Optionally: From the user network to Trento Server at ports
    TCP/4000, TCP/4001 and TCP/8080 (health checks for web, wanda and
    MCP, respectively).
  - From Prometheus server, when it exists, to each Trento Agent host at
    the port used by the Node Exporter.
## [[3.4 ][SAP requirements]] [\#](sec-trento-requirements.html#sec-sap-requirements "Permalink") 
[ ]
An SAP system must run on a HANA database to be discovered by Trento. In
addition, the parameter `dbs/hdb/dbname` must be set in the
DEFAULT profile of the SAP system to the correct database (tenant) name.
The agent must be installed in all the hosts that are part of the SAP
system architecture. Particularly:
- the host where the ASCS instance is running
- the host where the ERS instance, if it exists, is running
- all the hosts where an application server instance is running
- all the database hosts
## [[3.5 ][Cluster requirements]] [\#](sec-trento-requirements.html#sec-trento-cluster-requirements "Permalink") 
[ ]
The initial discovery of a pacemaker cluster requires the DC node to be
online. Once the cluster has been discovered, all nodes can be stopped
and Trento will continue to discover the cluster.
]Lifecycle]](sec-trento-lifecycle.html)
]Installation]](id-installation.html)
On this page
- [[[3.1 ][Trento Server
  requirements]](sec-trento-requirements.html#sec-trento-server-requirements)]
- [[[3.2 ][Trento Agent
  requirements]](sec-trento-requirements.html#sec-trento-agent-requirements)]
- [[[3.3 ][Network
  requirements]](sec-trento-requirements.html#sec-trento-network-requirements)]
- [[[3.4 ][SAP
  requirements]](sec-trento-requirements.html#sec-sap-requirements)]
- [[[3.5 ][Cluster
  requirements]](sec-trento-requirements.html#sec-trento-cluster-requirements)]
Share this page
- [](sec-trento-requirements.html# "E-Mail")
- [](sec-trento-requirements.html# "Print this page")
