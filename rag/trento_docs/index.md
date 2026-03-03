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
# User Documentation 
[ ]
Trento is an open cloud native Web console that aims to help SAP Basis
consultants and administrators to check the configuration, monitor and
manage the entire OS stack of their SAP environments, including HA
features.
[Revision History: User
Documentation](rh-article-trento.html)
[Publication Date: ]2026-02-12
- [[[1 ][What is
  Trento?]](sec-trento-what.html)]
  - [[[1.1 ][Trento
    Architecture]](sec-trento-what.html#id-trento-architecture)]
  - [[[1.2 ][Trento
    Server]](sec-trento-what.html#id-trento-server)]
  - [[[1.3 ][Trento
    Agent]](sec-trento-what.html#id-trento-agent)]
- [[[2
  ][Lifecycle]](sec-trento-lifecycle.html)]
- [[[3
  ][Requirements]](sec-trento-requirements.html)]
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
- [[[4
  ][Installation]](id-installation.html)]
  - [[[4.1 ][Installing Trento
    Server]](id-installation.html#sec-trento-installing-trentoserver)]
  - [[[4.2 ][Installing Trento
    Agents]](id-installation.html#sec-trento-installing-trentoagent)]
- [[[5 ][Update]](id-update.html)]
  - [[[5.1 ][Updating Trento
    Server]](id-update.html#sec-trento-updating-trentoserver)]
  - [[[5.2 ][Updating Trento
    Checks]](id-update.html#sec-trento-updating-trento-checks)]
  - [[[5.3 ][Updating a Trento
    Agent]](id-update.html#sec-trento-updating-trentoagent)]
- [[[6
  ][Uninstallation]](id-uninstallation.html)]
  - [[[6.1 ][Uninstalling Trento
    Server]](id-uninstallation.html#sec-trento-uninstall-trentoserver)]
  - [[[6.2 ][Uninstalling a Trento
    Agent]](id-uninstallation.html#sec-trento-uninstall-trentoagent)]
- [[[7 ][Prometheus
  integration]](id-prometheus-integration.html)]
  - [[[7.1
    ][Requirements]](id-prometheus-integration.html#id-requirements)]
  - [[[7.2 ][Kubernetes
    deployment]](id-prometheus-integration.html#id-kubernetes-deployment)]
  - [[[7.3 ][systemd
    deployment]](id-prometheus-integration.html#id-systemd-deployment)]
- [[[8 ][MCP
  Integration]](sec-trento-mcp-integration.html)]
  - [[[8.1 ][Installing Trento MCP
    Server]](sec-trento-mcp-integration.html#sec-trento-mcp-install)]
  - [[[8.2 ][Configuring Trento MCP
    Server]](sec-trento-mcp-integration.html#sec-trento-mcp-config)]
  - [[[8.3 ][Using the Trento MCP
    Server]](sec-trento-mcp-integration.html#sec-trento-mcp-how-to-use)]
- [[[9 ][Core
  Features]](id-core-features.html)]
  - [[[9.1 ][User
    management]](id-core-features.html#sec-trento-user-management)]
  - [[[9.2 ][Single Sign-On
    integration]](id-core-features.html#integrating-single-sign-on)]
  - [[[9.3 ][Activity
    Log]](id-core-features.html#sec-activity-log)]
  - [[[9.4
    ][Housekeeping]](id-core-features.html#sec-housekeeping)]
  - [[[9.5 ][Managing
    tags]](id-core-features.html#sec-trento-manage-tags)]
  - [[[9.6 ][Rotating API
    keys]](id-core-features.html#sec-trento-rotating-apikeys)]
  - [[[9.7 ][Personal access
    tokens]](id-core-features.html#sec-trento-personal-access-tokens)]
- [[[10 ][Compliance
  Features]](id-compliance-features.html)]
  - [[[10.1 ][Performing configuration
    checks]](id-compliance-features.html#sec-trento-checks)]
  - [[[10.2 ][Checks
    Customization]](id-compliance-features.html#checks-customization)]
- [[[11 ][Using Trento
  Web]](sec-trento-use-webconsole.html)]
  - [[[11.1 ][Getting the global health
    state]](sec-trento-use-webconsole.html#sec-trento-health)]
  - [[[11.2 ][Viewing the
    status]](sec-trento-use-webconsole.html#sec-trento-status)]
  - [[[11.3 ][Viewing the status of
    hosts]](sec-trento-use-webconsole.html#sec-trento-status-hosts)]
  - [[[11.4 ][Viewing the Pacemaker cluster
    status]](sec-trento-use-webconsole.html#sec-trento-status-pacemakerclusters)]
  - [[[11.5 ][Viewing the SAP Systems
    status]](sec-trento-use-webconsole.html#sec-trento-status-sapsystems)]
  - [[[11.6 ][Viewing the SAP HANA database
    status]](sec-trento-use-webconsole.html#sec-trento-status-hanadatabases)]
  - [[[11.7 ][Configuring Trento Web
    settings]](sec-trento-use-webconsole.html#sec-trento-settings-webconsole)]
- [[[12 ][Integration with SUSE Multi-Linux
  Manager]](sec-integration-with-SUSE-Manager.html)]
- [[[13
  ][Operations]](id-operations.html)]
  - [[[13.1 ][Host
    operations]](id-operations.html#id-host-operations)]
  - [[[13.2 ][Cluster
    operations]](id-operations.html#id-cluster-operations)]
  - [[[13.3 ][SAP HANA
    operations]](id-operations.html#id-sap-hana-operations)]
  - [[[13.4 ][SAP
    operations]](id-operations.html#id-sap-operations)]
- [[[14 ][Reporting an
  Issue]](sec-trento-report-problem.html)]
- [[[15 ][Problem
  Analysis]](sec-trento-problemanalysis.html)]
  - [[[15.1 ][Trento
    Server]](sec-trento-problemanalysis.html#id-trento-server-2)]
  - [[[15.2 ][Scenario dump
    script]](sec-trento-problemanalysis.html#id-scenario-dump-script)]
  - [[[15.3 ][Pods descriptions and
    logs]](sec-trento-problemanalysis.html#id-pods-descriptions-and-logs)]
- [[[16 ][Compatibility matrix between Trento Server and
  Trento
  Agents]](sec-trento-compatibility-matrix.html)]
- [[[17 ][Highlights of Trento
  versions]](sec-trento-version-history.html)]
- [[[18 ][More
  information]](sec-trento-more-information.html)]
List of Figures
- [[[1.1 ][Architectural
  overview]](sec-trento-what.html#fig-trento-architecture)]
- [[[8.1 ][Generate a Personal Access Token in
  Trento]](sec-trento-mcp-integration.html#id-1.9.5.3.5.2.3.2)]
- [[[8.2 ][MCPHost initial screen with the Trento MCP Server
  connected]](sec-trento-mcp-integration.html#id-1.9.5.3.8.2.2.3)]
- [[[8.3 ][Generate a Personal Access Token in
  Trento]](sec-trento-mcp-integration.html#id-1.9.5.4.5.2.3.2)]
- [[[9.1 ][Clean up button in Hosts
  overview]](id-core-features.html#id-1.10.5.3)]
- [[[9.2 ][Clean up button in Host details
  view]](id-core-features.html#id-1.10.5.4)]
- [[[9.3 ][Clean up button SAP systems
  overview]](id-core-features.html#id-1.10.5.8)]
- [[[9.4 ][Clean up button in SAP system details
  view]](id-core-features.html#id-1.10.5.9)]
- [[[9.5 ][Checks
  catalog]](id-core-features.html#id-1.10.7.5)]
- [[[9.6
  ][Profile]](id-core-features.html#id-1.10.8.4.3)]
- [[[9.7 ][Generate personal access token
  modal]](id-core-features.html#id-1.10.8.4.4.2.2)]
- [[[9.8 ][Generated personal access
  token]](id-core-features.html#id-1.10.8.4.4.3.2)]
- [[[9.9 ][Personal access tokens
  section]](id-core-features.html#id-1.10.8.6.3)]
- [[[9.10 ][Delete personal access token
  modal]](id-core-features.html#id-1.10.8.6.5)]
- [[[10.1 ][Pacemaker cluster
  details]](id-compliance-features.html#id-1.11.2.3.4.2)]
- [[[10.2 ][Pacemaker Cluster Settings---Checks
  Selection]](id-compliance-features.html#fig-pacemaker-clustersettings-checks)]
- [[[10.3 ][Check results for a
  cluster]](id-compliance-features.html#fig-pacemaker-checkresult)]
- [[[10.4 ][Unmet expected result detail
  view]](id-compliance-features.html#fig-non-met-expectation-detail)]
- [[[11.1 ][Dashboard with the global health
  state]](sec-trento-use-webconsole.html#fig-trento-web-home)]
- [[[11.2 ][Hosts
  entry]](sec-trento-use-webconsole.html#fig-trento-status-hosts)]
- [[[11.3 ][saptune Summary
  section]](sec-trento-use-webconsole.html#fig-saptune-summary-section)]
- [[[11.4 ][saptune details
  view]](sec-trento-use-webconsole.html#fig-saptune-details-view)]
- [[[11.5 ][Pacemaker
  clusters]](sec-trento-use-webconsole.html#fig-trento-status-pacemakerclusters)]
- [[[11.6 ][SAP
  Systems]](sec-trento-use-webconsole.html#fig-trento-status-sapsystems)]
- [[[11.7 ][SAP System
  Details]](sec-trento-use-webconsole.html#id-1.12.8.3.3.2.3.2)]
- [[[11.8 ][HANA
  databases]](sec-trento-use-webconsole.html#fig-trento-status-hanadb)]
- [[[11.9 ][HANA Database
  details]](sec-trento-use-webconsole.html#id-1.12.9.3.3.2.3.3)]
- [[[12.1 ][SUSE Multi-Linux Manager
  settings]](sec-integration-with-SUSE-Manager.html#id-1.13.4)]
- [[[12.2 ][Available software updates in the Host Details
  view]](sec-integration-with-SUSE-Manager.html#id-1.13.6)]
- [[[12.3 ][Available Patches
  overview]](sec-integration-with-SUSE-Manager.html#id-1.13.8)]
- [[[12.4 ][Upgradable Packages
  overview]](sec-integration-with-SUSE-Manager.html#id-1.13.10)]
- [[[12.5 ][Advisory Details
  view]](sec-integration-with-SUSE-Manager.html#id-1.13.12)]
List of Tables
- [[[16.1 ][Compatibility matrix between Trento Server and
  Trento
  Agents]](sec-trento-compatibility-matrix.html#id-1.17.2)]
[[Next][[Chapter 1 ]What is
Trento?]](sec-trento-what.html)
Share this page
- [](index.html# "E-Mail")
- [](index.html# "Print this page")
