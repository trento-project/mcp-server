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
# [[6 ][Uninstallation]] [\#](id-uninstallation.html# "Permalink") 
[ ]
## [[6.1 ][Uninstalling Trento Server]] [\#](id-uninstallation.html#sec-trento-uninstall-trentoserver "Permalink") 
[ ]
The procedure to uninstall the Trento Server depends on the deployment
type: Kubernetes or systemd. The section covers Kubernetes deployments.
If Trento Server was deployed manually, you need to uninstall it
manually. If Trento Server was deployed using the Helm chart, you can
also use Helm to uninstall it as follows:
``` programlisting
helm uninstall trento-server
```
## [[6.2 ][Uninstalling a Trento Agent]] [\#](id-uninstallation.html#sec-trento-uninstall-trentoagent "Permalink") 
[ ]
To uninstall a Trento Agent, perform the following steps:
- Log in to the Trento Agent host.
- Stop the Trento Agent:
  ``` programlisting
  > sudo systemctl stop trento-agent
  ```
- Remove the package:
  ``` programlisting
  > sudo zypper remove trento-agent
  ```
[[Previous][[Chapter 5
]Update]](id-update.html)
[[Next][[Chapter 7 ]Prometheus
integration]](id-prometheus-integration.html)
On this page
- [[[6.1 ][Uninstalling Trento
  Server]](id-uninstallation.html#sec-trento-uninstall-trentoserver)]
- [[[6.2 ][Uninstalling a Trento
  Agent]](id-uninstallation.html#sec-trento-uninstall-trentoagent)]
Share this page
- [](id-uninstallation.html# "E-Mail")
- [](id-uninstallation.html# "Print this page")
