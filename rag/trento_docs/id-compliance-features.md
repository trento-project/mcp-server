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
# [[10 ][Compliance Features]] [\#](id-compliance-features.html# "Permalink") 
[ ]
## [[10.1 ][Performing configuration checks]] [\#](id-compliance-features.html#sec-trento-checks "Permalink") 
[ ]
Trento provides configuration checks that ensure your infrastructure
setup adheres to our or other vendor's Best Practices, and it does not
diverge with time. Configuration checks are available for HANA clusters,
ASCS/ERS clusters and hosts. The following procedure is specific to a
HANA cluster. The procedure for an ASCS/ERS cluster or a host would be
exactly the same, except it starts from the corresponding
[**Details**] view.
1.  Log in to Trento
2.  In the left panel, click [**Cluster**].
3.  In the list, search for a SAP HANA cluster.
4.  Click the desired cluster name in the [**Name**] column.
    The [**Details**] view opens.
    [![trento-web-pacemaker-cluster-details-view](images/trento-web-pacemaker-cluster-details-view.png "trento-web-pacemaker-cluster-details-view")](images/trento-web-pacemaker-cluster-details-view.png)
    [[Figure 10.1: ][Pacemaker cluster details
    ]][\#](id-compliance-features.html#id-1.11.2.3.4.2 "Permalink")
    [ ]
5.  []Click the [**Settings**] button to change the
    cluster settings of the respective cluster. For checks to be
    executed, a checks selection must be made. Select the checks to be
    executed and click [**Select Checks for Execution**].
    [![trento-web-pacemaker-clustersettings-checks](images/trento-web-pacemaker-clustersettings-checks.png "trento-web-pacemaker-clustersettings-checks")](images/trento-web-pacemaker-clustersettings-checks.png)
    [[Figure 10.2: ][Pacemaker Cluster Settings---Checks
    Selection
    ]][\#](id-compliance-features.html#fig-pacemaker-clustersettings-checks "Permalink")
    [ ]
6.  You can then either wait for Trento to execute the selected checks
    or trigger an execution immediately by clicking the button in the
    [**Checks Selection**] tab.
7.  Investigate the result in the [**Checks Results**] view.
    Each row in the view displays a check ID, a short description of the
    check and the check execution result. Click on a row to open a
    section that provides information about the execution on each node
    of the cluster.
    [![trento-web-checkresult](images/trento-web-checkresult.png "trento-web-checkresult")](images/trento-web-checkresult.png)
    [[Figure 10.3: ][Check results for a cluster
    ]][\#](id-compliance-features.html#fig-pacemaker-checkresult "Permalink")
    [ ]
    The result of a check execution can be passing, warning, critical:
    - *Passing* means that the checked configuration meets the
      recommendation.
    - *Warning* means that the recommendation is not met but the
      configuration is not critical for the proper running of the
      cluster.
    - *Critical* means that either the execution itself failed (for
      example, a timeout) or the recommendation is not met and is
      critical for the well-being of the cluster.
      Use the filter to narrow the list to specific results (for
      example, critical).
8.  Click a check's link to open a modal box with the check description.
    This displays an abstract and a possible solution to the problem.
    The [**References**] section contains links to the
    documentation from the different vendors for more context when
    necessary. Close the modal box by pressing the [**Esc**]
    key or click outside of the box.
    For each unmet expected result, there is a detailed view with
    information about it: what facts were gathered, what values were
    expected, and what was the result of the evaluation. This helps to
    understand why a certain configuration check is failing:
    [![trento-web-nonmetexpectation](images/trento-web-nonmetexpectation.png "trento-web-nonmetexpectation")](images/trento-web-nonmetexpectation.png)
    [[Figure 10.4: ][Unmet expected result detail view
    ]][\#](id-compliance-features.html#fig-non-met-expectation-detail "Permalink")
    [ ]
When checks for a given cluster have been selected, Trento executes them
automatically every five minutes, updating the results. A spinning check
execution result icon means that an execution is running.
## [[10.2 ][Checks Customization]] [\#](id-compliance-features.html#checks-customization "Permalink") 
[ ]
### [[10.2.1 ][Overview of checks Customization]] [\#](id-compliance-features.html#id-overview-of-checks-customization "Permalink") 
[ ]
Trento makes it possible to adjust expected check values to match
target-specific requirements. This can be done directly through the
Trento Web console without modifying the original check or impacting
other targets.
The Trento web console receives a check catalog from Wanda. In the check
selection view of a specific target, you can see all available check
categories. Click on a category to expand the list of checks associated
with it. If you have the [**required permissions**], a
settings icon appears to the right of a customizable check. Click on the
settings icon to open a modal window where you can adjust check values.
The check customization modal includes the following elements:
- Selected Check ID.
- Check description.
- Warning message that neither Trento nor SUSE can be held responsible
  for system malfunctions caused by deviations in the target
  configuration from best practices.
- A list of all customizable check values. Each value includes a value
  name with the original default check value and an input field with the
  current customized or default value.
- The current target-specific provider.
- [**Save**], [**Reset**] and
  [**Close**] buttons at the bottom.
The [**Save**] button is disabled by default. The button is
enabled when the user checks the warning and modifies a value. The
custom values are stored in the Wanda's database, so they persist across
system reboots.
The [**Reset**] button is enabled only when the check has
been customized. Use the button to reverse the changes.
A [**Modified Pill**] indicator next to the check ID
indicates that the values have been customized. A [**Reset**]
icon next to the [**Settings**] icon can be used to revert to
default values.
### [[10.2.2 ][Target-specific check customization]] [\#](id-compliance-features.html#id-target-specific-check-customization "Permalink") 
[ ]
A check is always executed on a target, which can be a host or a
cluster. Users can customize check values specific to the target
environment to ensure optimal system performance. Customizations are
target-specific, and they do not affect other targets or the original
default check values.
### [[10.2.3 ][Required permissions]] [\#](id-compliance-features.html#id-required-permissions "Permalink") 
[ ]
Only admin users and users with the `all:checks_customization`
permission can customize checks. The customization button in the Trento
Web console is not shown for users without this permission. If a check
has been modified, the modified Pill is shown for all users.
### [[10.2.4 ][Customizable checks]] [\#](id-compliance-features.html#id-customizable-checks "Permalink") 
[ ]
All checks with the following value types are customizable:
- String
- Number
- Boolean
User input is validated to ensure that the input value matches the
expected type before allowing to save the custom values in Wanda's
database. If the input type is incorrect or mixed, the customization
fails, triggering a toast notification, that checks customization failed
and a warning message in the modal itself.
### [[10.2.5 ][Check customization persistence]] [\#](id-compliance-features.html#id-check-customization-persistence "Permalink") 
[ ]
Customized check values are persistently stored in Wanda's database.
This ensures that any modifications made by users are consistently
applied across subsequent executions. Additionally, customized values
remain in effect even after system restarts or updates, ensuring
continuous adherence to target-specific configurations.
[[Previous][[Chapter 9 ]Core
Features]](id-core-features.html)
[[Next][[Chapter 11 ]Using Trento
Web]](sec-trento-use-webconsole.html)
On this page
- [[[10.1 ][Performing configuration
  checks]](id-compliance-features.html#sec-trento-checks)]
- [[[10.2 ][Checks
  Customization]](id-compliance-features.html#checks-customization)]
Share this page
- [](id-compliance-features.html# "E-Mail")
- [](id-compliance-features.html# "Print this page")
