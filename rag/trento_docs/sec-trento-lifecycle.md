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
# [[2 ][Lifecycle]] [\#](sec-trento-lifecycle.html# "Permalink") 
[ ]
Trento is part of SUSE Linux Enterprise Server for SAP applications.
Trento's two main components have the following product lifecycles:
[Trento Agent]

    [Delivery mechanism]
RPM package for SUSE Linux Enterprise Server for SAP
        applications 15 SP4 and newer, and SUSE Linux Enterprise Server
        for SAP applications 16.0.
    [Supported runtime]
Supported in SUSE Linux Enterprise Server for SAP applications
        15 SP4 and newer, and SUSE Linux Enterprise Server for SAP
        applications 16.0, on x86_64 and ppc64le architectures.
[Trento Server]

    [Delivery mechanisms]
A set of container images from the SUSE public registry together
        with a Helm chart that facilitates their installation or a set
        of RPM packages for SUSE Linux Enterprise Server for SAP
        applications 15 SP4 and newer, and SUSE Linux Enterprise Server
        for SAP applications 16.0.
    [Kubernetes deployment]
The Trento Server runs on any current Cloud Native Computing
        Foundation (CNCF)-certified Kubernetes distribution based on a
        x86_64 architecture. Depending on your scenario and needs, SUSE
        supports several usage scenarios:
        - If you already use a CNCF-certified Kubernetes cluster, you
          can run the Trento Server in it.
        - If you don't have a Kubernetes cluster, and need enterprise
          support, SUSE recommends SUSE Rancher Prime Kubernetes Engine
          (RKE) (RKE) version 2.
        - If you do not have a Kubernetes enterprise solution but you
          want to try Trento, SUSE Rancher's K3s provides you with an
          easy way to get started. But keep in mind that K3s default
          installation process deploys a single node Kubernetes cluster,
          which is not a recommended setup for a stable Trento
          production instance.
    [systemd deployments]
Supported in SUSE Linux Enterprise Server for SAP applications
        15 SP4 and newer, and SUSE Linux Enterprise Server for SAP
        applications 16.0 on x86_64 and ppc64le architectures.
[[Previous][[Chapter 1 ]What is
Trento?]](sec-trento-what.html)
[[Next][[Chapter 3
]Requirements]](sec-trento-requirements.html)
Share this page
- [](sec-trento-lifecycle.html# "E-Mail")
- [](sec-trento-lifecycle.html# "Print this page")
