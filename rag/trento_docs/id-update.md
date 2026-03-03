User Documentation
1.  [[1 ][What is
    Trento?]](sec-trento-what.html)
2.  [[2
    ][Lifecycle]](sec-trento-lifecycle.html)
3.  [[3
    ][Requirements]](sec-trento-requirements.html)
4.  [[4
    ][Installation]](id-installation.html)
5.  [[5
    ][Update]](id-update.html)
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
# [[5 ][Update]] [\#](id-update.html# "Permalink") 
[ ]
## [[5.1 ][Updating Trento Server]] [\#](id-update.html#sec-trento-updating-trentoserver "Permalink") 
[ ]
The procedure to update Trento Server depends on the chosen deployment
option: Kubernetes or systemd.
Consider the following when performing an update:
- Before updating Trento Server, ensure that all the Trento Agents in
  the environment are supported by the target version. For more
  information, see section [Chapter 16, *Compatibility matrix between
  Trento Server and Trento
  Agents*](sec-trento-compatibility-matrix.html "Chapter 16. Compatibility matrix between Trento Server and Trento Agents").
- When updating Trento to version 2.4 or higher, the admin password may
  need to be adjusted to follow the rules described in the User
  Management section.
In a Kubernetes deployment, you can use Helm to update Trento Server:
``` programlisting
helm upgrade \
   --install trento-server oci://registry.suse.com/trento/trento-server \
   --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
   --set trento-web.adminUser.password=ADMIN_PASSWORD
```
If you have configured options like email alerting, the Helm command
must be adjusted accordingly. In this case, consider the following:
- Remember to set the helm experimental flag if you are using a version
  of Helm lower than 3.8.0.
- When updating Trento to version 2.0.0 or higher, an additional flag
  must be set in the Helm command:
  ``` programlisting
  helm upgrade \
     --install trento-server oci://registry.suse.com/trento/trento-server \
     --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
     --set trento-web.adminUser.password=ADMIN_PASSWORD \
     --set rabbitmq.auth.erlangCookie=$(openssl rand -hex 16)
  ```
- When updating Trento to version 2.3 or higher, a new API key is
  generated and the configuration of all registered Trento Agents must
  be updated accordingly.
In a system deployment, you can use zypper to update Trento Server:
``` programlisting
 zypper refresh
 zypper update trento-web
 zypper update trento-wanda
 systemctl restart trento-web
 systemctl restart trento-wanda
```
## [[5.2 ][Updating Trento Checks]] [\#](id-update.html#sec-trento-updating-trento-checks "Permalink") 
[ ]
Configuration checks are an integral part of the checks engine, but they
are delivered separately. This allows customers to update the checks
catalog in their setup whenever updates to existing checks and new
checks are released, without waiting for a new version release cycle.
The procedure of updating the configuration checks depends on the Trento
Server deployment type: Kubernetes or systemd.
In a Kubernetes deployment, checks are delivered as a container image,
and you can use Helm with the following options to pull the latest
image:
``` literallayout
  helm ... \
 --set trento-wanda.checks.image.tag=latest \
 --set trento-wanda.checks.image.repository=registry.suse.com/trento/trento-checks  \
 --set trento-wanda.checks.image.pullPolicy=Always \
 ...
```
In a systemd deployment, checks are delivered as an RPM package, and you
can use Zypper to update your checks catalog:
``` programlisting
> sudo zypper ref
> sudo zypper update trento-checks
```
## [[5.3 ][Updating a Trento Agent]] [\#](id-update.html#sec-trento-updating-trentoagent "Permalink") 
[ ]
To update the Trento Agent, follow the procedure below:
1.  Log in to the Trento Agent host.
2.  Stop the Trento Agent:
    ``` programlisting
    > sudo systemctl stop trento-agent
    ```
3.  Install the new package:
    ``` programlisting
    > sudo zypper ref
    > sudo zypper install trento-agent
    ```
4.  Copy the file `/etc/trento/agent.yaml.rpmsave` to
    `/etc/trento/agent.yaml`. Make sure that entries
    `facts-service-url`, `server-url`, and
    `api-key` in `/etc/trento/agent.yaml` are
    correct.
5.  Start the Trento Agent:
    ``` programlisting
    > sudo systemctl start trento-agent
    ```
6.  Check the status of the Trento Agent:
    ``` programlisting
    sudo systemctl status trento-agent
    ● trento-agent.service - Trento Agent service
       Loaded: loaded (/usr/lib/systemd/system/trento-agent.service; enabled; vendor preset: disabled)
       Active: active (running) since Wed 2021-11-24 17:37:46 UTC; 4s ago
     Main PID: 22055 (trento)
        Tasks: 10
       CGroup: /system.slice/trento-agent.service
               ├─22055 /usr/bin/trento agent start --consul-config-dir=/srv/consul/consul.d
               └─22220 /usr/bin/ruby.ruby2.5 /usr/sbin/SUSEConnect -s
    [...]
    ```
7.  Check the version in the Hosts overview of the Trento UI (URL
    `http://TRENTO_SERVER_HOSTNAME`).
8.  Repeat this procedure in all Trento Agent hosts.
[[Previous][[Chapter 4
]Installation]](id-installation.html)
[[Next][[Chapter 6
]Uninstallation]](id-uninstallation.html)
On this page
- [[[5.1 ][Updating Trento
  Server]](id-update.html#sec-trento-updating-trentoserver)]
- [[[5.2 ][Updating Trento
  Checks]](id-update.html#sec-trento-updating-trento-checks)]
- [[[5.3 ][Updating a Trento
  Agent]](id-update.html#sec-trento-updating-trentoagent)]
Share this page
- [](id-update.html# "E-Mail")
- [](id-update.html# "Print this page")
