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
# [[14 ][Reporting an Issue]] [\#](sec-trento-report-problem.html# "Permalink") 
[ ]
SUSE customers with registered SUSE Linux Enterprise Server for SAP
applications   15 (SP4 or higher) or SUSE Linux Enterprise Server for
SAP applications 16.0 distributions can report Trento issues either
directly in the SUSE Customer Center or through the corresponding
vendor, depending on their licensing model. Problems must be reported
under SUSE Linux Enterprise Server for SAP applications 15 and component
trento.
When opening a support case for Trento, provide the relevant deployment
option for Trento Server: Kubernetes, or systemd deployment.
In case of a Kubernetes deployment, provide the output of the Trento
support script as explained in section [Chapter 15, *Problem
Analysis*](sec-trento-problemanalysis.html "Chapter 15. Problem Analysis").
In case of a systemd deployment, provide the output of the Trento
supportconfig plugin, as explained in section [Chapter 15, *Problem
Analysis*](sec-trento-problemanalysis.html "Chapter 15. Problem Analysis").
For issues with a particular Trento Agent, or a component discovered by
a particular Trento Agent, also provide the following:
- status of the Trento Agent
- journal of the Trento Agent
- output of the command `supportconfig` in the Trento Agent
  host. See
  [https://documentation.suse.com/sles/html/SLES-all/cha-adm-support.html#sec-admsupport-cli](https://documentation.suse.com/sles/html/SLES-all/cha-adm-support.html#sec-admsupport-cli) for information on how to run this command from
  command line.
]Operations]](id-operations.html)
Analysis]](sec-trento-problemanalysis.html)
Share this page
- [](sec-trento-report-problem.html# "E-Mail")
- [](sec-trento-report-problem.html# "Print this page")
