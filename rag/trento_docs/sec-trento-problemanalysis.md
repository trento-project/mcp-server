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
# [[15 ][Problem Analysis]] [\#](sec-trento-problemanalysis.html# "Permalink") 
[ ]
## [[15.1 ][Trento Server]] [\#](sec-trento-problemanalysis.html#id-trento-server-2 "Permalink") 
[ ]
There are two tools you can use to collect information and data that can
be useful when troubleshooting and analyzing issues with Trento Server.
### [[15.1.1 ][Trento support plugin]] [\#](sec-trento-problemanalysis.html#id-trento-support-plugin "Permalink") 
[ ]
The Trento support plugin consists of the `trento-support.sh`
script and the support plugin itself. The tool automates the collection
of logs and relevant runtime information on the server side. It can be
used in two different scenarios:
- A deployment on K3s
- A systemd deployment
### [[15.1.2 ][Using the Trento support plugin with a K3s deployment]] [\#](sec-trento-problemanalysis.html#id-using-the-trento-support-plugin-with-a-k3s-deployment "Permalink") 
[ ]
Using the plugin with a K3s deployment requires a SUSE Linux Enterprise
Server for SAP applications 15 SP3 or higher host with the following
setup:
- Packages `jq` and `yq` are installed
- Helm is installed
- `kubectl` is installed and connected to the Kubernetes
  cluster where Trento Server is running
To use the plugin, proceed as follows:
1.  Install the Trento support plugin:
    ``` screen
    # zypper ref
    # zypper install supportutils-plugin-trento
    ```
2.  Run the `trento-support.sh` script:
    ``` screen
    # trento-support --output file-tgz --collect all
    ```
3.  Send the generated archive file to support for analysis.
The script accepts the following options:
- `-o`, `--output` Output type (`stdout`,
  `file`, `file-tgz`)
- `-c`, `--collect` Collection options
  (`configuration`, `base`, `kubernetes`,
  `all`)
- `-r`, `--release-name` Release name to use for the
  chart installation. Default is `trento-server`
- `-n`, `--namespace` Kubernetes namespace used when
  installing the chart.Default is `default`
- `--help` Shows help messages
### [[15.1.3 ][Using the Trento support plugin with a systemd deployment]] [\#](sec-trento-problemanalysis.html#id-using-the-trento-support-plugin-with-a-systemd-deployment "Permalink") 
[ ]
To use the plugin in this scenario, proceed as follows:
1.  Install the Trento support plugin:
    ``` screen
    # zypper ref
    # zypper install supportutils-plugin-trento
    ```
2.  Execute supportconfig as described in
    [https://documentation.suse.com/smart/systems-management/html/supportconfig/index.html](https://documentation.suse.com/smart/systems-management/html/supportconfig/index.html). The `supportconfig` tool will call the
    Trento support plugin.
3.  Send the generated output to support for analysis.
## [[15.2 ][Scenario dump script]] [\#](sec-trento-problemanalysis.html#id-scenario-dump-script "Permalink") 
[ ]
A scenario dump is a dump of the Trento database. It helps the Trento
team to recreate the scenario to test it.
A script is available in the Trento upstream project. The script helps
generate a scenario dump when the server is running on a Kubernetes
cluster. Using this script requires a host with the following setup:
- `kubectl` is installed and connected to the Kubernetes
  cluster where Trento Server is running.
To generate the dump, proceed as follows:
1.  Download the latest version of the dump script:
    ``` screen
    > wget https://raw.githubusercontent.com/trento-project/web/main/hack/dump_scenario_from_k8.sh
    ```
2.  Make the script executable:
    ``` screen
    > chmod +x dump_scenario_from_k8.sh
    ```
3.  Make sure that `kubectl` is connected to the Kubernetes
    cluster where Trento Server is running and run the script:
    ``` screen
    > ./dump_scenario_from_k8.sh -n SCENARIO_NAME -p PATH
    ```
4.  Go to `PATH/scenarios/SCENARIO_NAME`, package all the
    generated JSON files, and send the package to support for analysis.
## [[15.3 ][Pods descriptions and logs]] [\#](sec-trento-problemanalysis.html#id-pods-descriptions-and-logs "Permalink") 
[ ]
In case of a deployment on K3s, the descriptions and logs of the Trento
Server pods can be useful for analysis and troubleshooting purposes (in
addition to the output of the trento-support.sh script and the dump
scenario script). These descriptions and logs can be obtained with the
`kubectl` command. For this to work, you need a host with
`kubectl` is installed and connected to the K3s cluster
running Trento Server.
1.  List the pods running in Kubernetes cluster and their statuses. Run
    the command below to view Trento Server pods:
    ``` screen
    > kubectl get pods
    NAME                                               READY   STATUS    RESTARTS   AGE
    trento-server-postgresql-0                         1/1     Running   0          87m
    trento-server-prometheus-server-7b5c9474bc-wmv8s   2/2     Running   0          87m
    trento-server-rabbitmq-0                           1/1     Running   0          87m
    trento-server-wanda-67ffbb79dc-7t6xw               1/1     Running   0          87m
    trento-server-web-7df8f65794-vdbhs                 1/1     Running   0          87m
    ```
2.  Retrieve the description of a pod as follows:
    ``` screen
    > kubectl describe pod POD_NAME
    ```
3.  Retrieve the log of a pod as follows:
    ``` screen
    > kubectl logs POD_NAME
    ```
4.  Monitor the log of a pod as follows:
    ``` screen
    > kubectl logs POD_NAME --follow
    ```
an
Issue]](sec-trento-report-problem.html)
matrix between Trento Server and Trento
Agents]](sec-trento-compatibility-matrix.html)
On this page
- [[[15.1 ][Trento
  Server]](sec-trento-problemanalysis.html#id-trento-server-2)]
- [[[15.2 ][Scenario dump
  script]](sec-trento-problemanalysis.html#id-scenario-dump-script)]
- [[[15.3 ][Pods descriptions and
  logs]](sec-trento-problemanalysis.html#id-pods-descriptions-and-logs)]
Share this page
- [](sec-trento-problemanalysis.html# "E-Mail")
- [](sec-trento-problemanalysis.html# "Print this page")
