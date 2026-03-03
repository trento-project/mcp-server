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
# [[1 ][What is Trento?]] [\#](sec-trento-what.html# "Permalink") 
[ ]
Trento is the official version of the Trento community project. It is a
comprehensive monitoring solution consisting of two main components: the
Trento Server and the Trento Agent. Trento provides the following
functionality and features:
- A user-friendly reactive Web interface for SAP Basis administrators.
- Automated discovery of Pacemaker clusters using SAPHanaSR classic or
  angi as well as different fencing mechanisms, including diskless SBD.
- Automated discovery of SAP systems running on ABAP or JAVA stacks and
  HANA databases.
- Awareness of maintenance situations in a Pacemaker cluster at cluster,
  node, or resource level.
- Configuration validation for SAP HANA Scale-Up
  Performance/Cost-optimized, SAP HANA Scale-out and ASCS/ERS clusters
  deployed on Azure, AWS, GCP or on-premises bare metal platforms,
  including KVM and Nutanix.
- Useful information that offers insights about the execution of
  configuration checks.
- Delivery of configuration checks decoupled from core functionality.
- Email alerting for critical events in the monitored landscape.
- Integration of saptune into the console and specific configuration
  checks at host and cluster levels.
- Information about relevant patches and upgradable packages for
  registered hosts via integration with SUSE Multi-Linux Manager.
- Monitoring of CPU and memory usage at the host level through basic
  integration with Prometheus.
- API-based architecture to facilitate integration with other monitoring
  tools.
- Rotating API key to protect communication from the Trento Agent to the
  Trento Server.
- AI assistance via Model Context Protocol (MCP) integration.
- Housekeeping capabilities.
## [[1.1 ][Trento Architecture]] [\#](sec-trento-what.html#id-trento-architecture "Permalink") 
[ ]
[![trento high level
architecture](images/trento-high-level-architecture.svg "trento high level architecture")](images/trento-high-level-architecture.svg)
[[Figure 1.1: ][Architectural overview
]][\#](sec-trento-what.html#fig-trento-architecture "Permalink")
[ ]
## [[1.2 ][Trento Server]] [\#](sec-trento-what.html#id-trento-server "Permalink") 
[ ]
The Trento Server is an independent, distributed system designed to run
on a Kubernetes cluster or as a regular systemd stack. It provides both
a Web front-end for user interaction and backend APIs for automation and
integration with components such as the Trento MCP Server. Together with
the optional [Trento MCP
Server](https://modelcontextprotocol.io/docs/getting-started/intro), it enables secure, AI-assisted operations by exposing
Trento Server APIs for natural-language interactions with tools like
MCPHost, Copilot, Claude, and SUSE AI.
The Trento Server consists of the following components:
- The Web component that acts as a control plane responsible for
  internal and external communications as well as rendering the UI.
- The orchestration engine named Wanda that orchestrates the execution
  of compliance checks and operations.
- The Trento MCP Server which creates a secure bridge between the
  infrastructure data collected by Trento and your Large Language Model
  (LLM) of choice.
- A PostgreSQL database for data persistence.
- The RabbitMQ message broker for communication between the
  orchestration engine and the agents.
- A Prometheus instance that retrieves the metrics collected by the
  Prometheus node exporter in the registered hosts. This Prometheus
  instance is optional in a systemd deployment.
## [[1.3 ][Trento Agent]] [\#](sec-trento-what.html#id-trento-agent "Permalink") 
[ ]
The [**Trento Agent**] is a single background process
(`trento-agent`) running on each monitored host of the SAP
infrastructure.
Documentation]](index.html)
]Lifecycle]](sec-trento-lifecycle.html)
On this page
- [[[1.1 ][Trento
  Architecture]](sec-trento-what.html#id-trento-architecture)]
- [[[1.2 ][Trento
  Server]](sec-trento-what.html#id-trento-server)]
- [[[1.3 ][Trento
  Agent]](sec-trento-what.html#id-trento-agent)]
Share this page
- [](sec-trento-what.html# "E-Mail")
- [](sec-trento-what.html# "Print this page")
