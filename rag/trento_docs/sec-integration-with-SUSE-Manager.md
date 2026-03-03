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
# [[12 ][Integration with SUSE Multi-Linux Manager]] [\#](sec-integration-with-SUSE-Manager.html# "Permalink") 
[ ]
Trento can be inegrated with SUSE Multi-Linux Manager to provide the SAP
administrator with information about relevant patches and upgradable
packages for any host that is registered with both applications.
The user must enter the connection settings for SUSE Multi-Linux Manager
in the Settings view:
[![trento-suse-manager-settings](images/trento-suse-manager-settings.png "trento-suse-manager-settings")](images/trento-suse-manager-settings.png)
[[Figure 12.1: ][SUSE Multi-Linux Manager settings
]][\#](sec-integration-with-SUSE-Manager.html#id-1.13.4 "Permalink")
[ ]
When the SUSE Multi-Linux Manager settings are configured, the SAP Basis
administrator can test the connection by clicking the Test button. If
the connection is successful, the [**Host Details**] view of
each host managed by SUSE Multi-Linux Manager displays a summary of
available patches and upgradable packages:
[![trento-summary-of-available-software-updates](images/trento-summary-of-available-software-updates.png "trento-summary-of-available-software-updates")](images/trento-summary-of-available-software-updates.png)
[[Figure 12.2: ][Available software updates in the Host
Details view
]][\#](sec-integration-with-SUSE-Manager.html#id-1.13.6 "Permalink")
[ ]
Click [**Relevant Patches**] to view a list of patches
available for the host:
[![trento-available-patches-overview](images/trento-available-patches-overview.png "trento-available-patches-overview")](images/trento-available-patches-overview.png)
[[Figure 12.3: ][Available Patches overview
]][\#](sec-integration-with-SUSE-Manager.html#id-1.13.8 "Permalink")
[ ]
Click [**Upgradable Packages**] to view a list of packages
that can be upgraded on that particular host:
[![trento-upgradable-packages-overview](images/trento-upgradable-packages-overview.png "trento-upgradable-packages-overview")](images/trento-upgradable-packages-overview.png)
[[Figure 12.4: ][Upgradable Packages overview
]][\#](sec-integration-with-SUSE-Manager.html#id-1.13.10 "Permalink")
[ ]
Click an advisory or patch link to access the corresponding details view
with relevant information, such us whether it requires a reboot or not,
associated vulnerabilities, or a list of affected hosts:
[![trento-advisory-details-view](images/trento-advisory-details-view.png "trento-advisory-details-view")](images/trento-advisory-details-view.png)
[[Figure 12.5: ][Advisory Details view
]][\#](sec-integration-with-SUSE-Manager.html#id-1.13.12 "Permalink")
[ ]
There are three types of patches or advisories: security advisories, bug
fixes and feature enhancements. Security advisories are considered
critical. If an advisory is available, the health of the host is set to
critical. If there are available patches but none of them is a security
one, the health of the host switches to warning. When a host cannot be
found in SUSE Multi-Linux Manager, or there is a problem retrieving the
data for it, its health is set to unknown.
You can clear the SUSE Multi-Linux Manager settings from the Settings
view at any time. When you do this, all information about available
software updates disappears from the console, and the status of the
hosts is adjusted accordingly.
[[Previous][[Chapter 11 ]Using
Trento
Web]](sec-trento-use-webconsole.html)
[[Next][[Chapter 13
]Operations]](id-operations.html)
Share this page
- [](sec-integration-with-SUSE-Manager.html# "E-Mail")
- [](sec-integration-with-SUSE-Manager.html# "Print this page")
