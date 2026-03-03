Configuring Node Fencing in a High Availability Cluster
On this page
[[[SUSE Linux Enterprise High
Availability]]] 16.0
# Configuring Node Fencing in a High Availability Cluster 
[Publication Date: ]12 Feb 2026
[WHAT?]
Node fencing protects the cluster from data corruption by resetting
    failed nodes.
[WHY?]
To be supported, all SUSE Linux Enterprise High Availability
    clusters *must* have node fencing configured.
[EFFORT]
Adding physical fencing devices takes approximately 5-10 minutes,
    depending on the complexity of the cluster.
[GOAL]
Configure a High Availability cluster to use a physical node fencing
    device. Physical fencing devices can only be added after the cluster
    is already installed and running, not during the initial cluster
    setup.
[REQUIREMENTS]
    - An existing SUSE Linux Enterprise High Availability cluster
    - A physical fencing device, such as a power switch or network
      switch
To use SBD as the node fencing mechanism instead of a physical device,
see one of the following articles:
- [*Configuring Disk-Based SBD in an Existing High Availability
  Cluster*](../HA-sbd-configuring-diskbased/index.html)
- [*Configuring Diskless SBD in an Existing High Availability
  Cluster*](../HA-sbd-configuring-diskless/index.html)
[Revision History: Configuring Node Fencing in a High Availability
Cluster](rh-ha-fencing-configuring.html)
## [[1 ][What is node fencing?]] [\#](index.html#ha-fencing-what-is "Permalink") 
[ ]
In a *split-brain scenario*, cluster nodes are divided into two or more
groups (or *partitions*) that do not know about each other. This might
be because of a hardware or software failure, or a failed network
connection, for example. A split-brain scenario can be resolved by
*fencing* (resetting or powering off) one or more of the nodes. Node
fencing prevents a failed node from accessing shared resources and
prevents cluster resources from running on a node with an uncertain
status. This helps protect the cluster from data corruption.
To be supported, all SUSE Linux Enterprise High Availability clusters
*must* have at least one node fencing device configured. For critical
workloads, we recommend using two or three fencing devices. A fencing
device can be either a physical device (a power switch) or a software
mechanism (SBD in combination with a watchdog).
### [[1.1 ][Components]] [\#](index.html#ha-fencing-what-is-components "Permalink") 
[ ]
[pacemaker-fenced]
The `pacemaker-fenced` daemon runs on every node in the
    High Availability cluster. It accepts fencing requests from
    `pacemaker-controld`. It can also check the status of
    the fencing device.
[Fence agent]
Each type of fencing device can be controlled by a specific *fence
    agent*, a `stonith`-class resource agent that acts as an
    interface between the cluster and the fencing device. Starting or
    stopping a fencing resource means registering or deregistering the
    fencing device with the `pacemaker-fenced` daemon and
    does not perform any operation on the device itself. Monitoring a
    fencing resource means logging in to the device to verify that it
    works.
[Fencing device]
The fencing device is the actual physical device that resets or
    powers off a node when requested by the cluster via the fence agent.
    The device you use depends on your budget and hardware.
### [[1.2 ][Fencing devices]] [\#](index.html#ha-fencing-what-is-device-types "Permalink") 
[ ]
[Physical devices]
    - *Power Distribution Units (PDU)* are devices with multiple power
      outlets that can provide remote load monitoring and power
      recycling.
    - *Uninterruptible Power Supplies (UPS)* provide emergency power to
      connected equipment in the event of a power failure.
    - *Blade power control devices* can be used for fencing if the
      cluster nodes are running on a set of blades. This device must be
      capable of managing single-blade computers.
    - *Lights-out devices* are network-connected devices that allow
      remote management and monitoring of servers.
[Software mechanisms]
    - *Disk-based SBD* fences nodes by exchanging messages via shared
      block storage. It works together with a watchdog on each node to
      ensure that misbehaving nodes are really stopped.
    - *Diskless SBD* fences nodes by using only the watchdog, without a
      shared storage device. Unlike other node fencing mechanisms,
      diskless SBD does not need a fence agent.
    - The *fence_kdump* agent checks if a node is performing a kernel
      dump (`kdump`). If a `kdump` is in
      progress, the cluster acts as if the node was fenced, because the
      node will reboot after the `kdump` is complete. If a
      `kdump` is not in progress, the next fencing device
      fences the node. This fence agent must be used together with a
      physical fencing device. It cannot be used with SBD.
### [[1.3 ][For more information]] [\#](index.html#ha-fencing-what-is-more-info "Permalink") 
[ ]
For more information, see
[https://clusterlabs.org/projects/pacemaker/doc/3.0/Pacemaker_Explained/html/fencing.html](https://clusterlabs.org/projects/pacemaker/doc/3.0/Pacemaker_Explained/html/fencing.html).
For a full list of available fence agents, run the
`crm ra list stonith` command.
For details about a specific fence agent, run the
`crm ra info stonith:fence_`*`AGENT`* command.
## [[2 ][Creating fencing resources for a physical device]] [\#](index.html#ha-fencing-creating-resources-for-physical-device "Permalink") 
[ ]
Each type of fencing device can be controlled by a specific *fence
agent*, a `stonith`-class resource agent that acts as an
interface between the cluster and the fencing device. Starting or
stopping a fencing resource means registering or deregistering the
fencing device with the `pacemaker-fenced` daemon and does
not perform any operation on the device itself. Monitoring a fencing
resource means logging in to the device to verify that it works.
When a node needs to be fenced, the fencing action is usually performed
by a different node in the cluster. Therefore, in this procedure you
will create multiple fencing resources, each targeting a specific node.
Each fencing resource can run on any node in the cluster except for the
node it targets.
[[Requirements
]][\#](index.html#id-1.3.3 "Permalink")
[ ]
- An existing High Availability cluster is already running.
- All cluster nodes can access a physical fencing device.
Perform this procedure on only one node in the cluster:
1. Log in either as the `root` user or as a user with
    `sudo` privileges.
2. Show the list of available fence agents:
    ``` screen
    > sudo crm ra list stonith
    ```
3. Show the list of required and optional parameters for your device,
    and make a note of the parameters you need for your specific setup:
    ``` screen
    > sudo crm ra info stonith:fence_AGENT
    ```
4. Start the `crm` interactive shell:
    ``` screen
    > sudo crm configure
    ```
    This mode lets you make multiple configuration changes before
    committing all the changes at once.
5. Create a fencing resource for every node in the cluster. Specify
    your device type, the parameters for that device type, and a monitor
    operation:
    ``` screen
    crm(live)configure# primitive RESOURCE-NAME stonith:fence_AGENT \
      params KEY=VALUE KEY=VALUE KEY=VALUE [...] \
      op monitor interval=INTEGER timeout=INTEGER
    ```
    [[Example 1: ][Fencing resources for two nodes with
    an IBM RSA device
    ]][\#](index.html#ha-fencing-creating-resources-for-physical-device-primitives "Permalink")
    [ ]
    This example shows a basic resource configuration for an IBM RSA
    lights-out device on two nodes, `alice` and
    `bob`:
    ``` screen
    crm(live)configure# primitive fence-rsa-alice stonith:fence_rsa \
      params pcmk_host_list=alice \1
      ip=192.168.1.101 username=root password=secret \2
      op monitor interval=30m timeout=120s3
    crm(live)configure# primitive fence-rsa-bob stonith:external/fence_rsa \
      params pcmk_host_list=bob \
      ip=192.168.1.102 username=root password=secret \
      op monitor interval=30m timeout=120s
    ```
    +:-------------------------------------------------+:----------------------------------+
    | [[1]](index.html#co-ha-fence-node)     | Use `pcmk_host_list` to |
    |                                                  | specify the node for this         |
    |                                                  | resource to target. In this       |
    |                                                  | example, the resource             |
    |                                                  | `fence-rsa-alice`       |
    |                                                  | fences the node                   |
    |                                                  | `alice`.             |
    +--------------------------------------------------+-----------------------------------+
    | [[2]](index.html#co-ha-fence-login)    | Provide login details for the     |
    |                                                  | fencing device. The required      |
    |                                                  | parameters depend on the specific |
    |                                                  | device.                           |
    |                                                  |                                   |
    |                                                  | If you use the                    |
    |                                                  | `password` parameter,   |
    |                                                  | the password is obscured in the   |
    |                                                  | output of                         |
    |                                                  | `crm configure show`,   |
    |                                                  | but is stored as plain text in    |
    |                                                  | the CIB and the command history.  |
    |                                                  | Alternatively, you can use a      |
    |                                                  | different parameter, such as      |
    |                                                  | `identity_file`.        |
    +--------------------------------------------------+-----------------------------------+
    | [[3]](index.html#co-ha-fence-monitorr) | Include a monitor operation to    |
    |                                                  | check the status of the device.   |
    |                                                  | Ideally, fencing devices are not  |
    |                                                  | needed very often and are         |
    |                                                  | unlikely to fail during a fencing |
    |                                                  | operation. Therefore, a           |
    |                                                  | monitoring interval of 30 minutes |
    |                                                  | or more should be sufficient for  |
    |                                                  | most devices.                     |
    +--------------------------------------------------+-----------------------------------+
6. Add location constraints so that each fencing resource *cannot* run
    on the node it targets:
    ``` screen
    crm(live)configure# location CONSTRAINT-NAME RESOURCE-NAME -inf: NODE-NAME
    ```
    [[Example 2: ][Location constraints for IBM RSA
    resources on two nodes
    ]][\#](index.html#ha-fencing-creating-resources-for-physical-device-constraints "Permalink")
    [ ]
    This example shows location constraints for two nodes,
    `alice` and `bob`:
    ``` screen
    crm(live)configure# location loc-rsa-alice fence-rsa-alice -inf: alice
    crm(live)configure# location loc-rsa-bob fence-rsa-bob -inf: bob
    ```
    The resource `fence-rsa-alice` must *not* run on
    `alice`, and the resource `fence-rsa-bob`
    must *not* run on `bob`. In a two-node cluster, this
    means `fence-rsa-alice` always runs on `bob`.
    In a cluster with more nodes, this means `fence-rsa-alice`
    can run on *any* node except `alice`.
7. Enable node fencing for the whole cluster:
    ``` screen
    crm(live)configure# property stonith-enabled=true
    ```
8. Add a fencing timeout to define how long to wait for the fencing
    action to finish:
    ``` screen
    crm(live)configure# property stonith-timeout=60
    ```
    The default is `60` seconds, but you might need to change
    it for your specific setup and infrastructure.
9. Review the updated cluster configuration:
    ``` screen
    crm(live)configure# show
    ```
10. Commit the changes:
    ``` screen
    crm(live)configure# commit
    ```
11. Exit the `crm` interactive shell:
    ``` screen
    crm(live)configure# quit
    ```
12. Check the status of the cluster to make sure the fencing resources
    can start:
    ``` screen
    > sudo crm status
    ```
If the fencing resources have the status `Stopped`, the nodes
might have failed to connect to the fencing device. You can check the
connection with the command-line tool for your specific fence agent. For
more information, run the `man fence_`*`AGENT`*
command.
[[Example 3: ][Testing a node\'s connection to an IBM RSA
device
]][\#](index.html#ha-fencing-creating-resources-for-physical-device-troubleshooting "Permalink")
[ ]
This command uses the example details from the previous procedure to
check the status of node `bob`. Adjust this command for
your specific configuration and device.
``` screen
alice> sudo fence_rsa -a 192.168.1.102 -l root -p secret -n bob -o status
```
If the connection is successful, the output shows
`Status: ON`. If the connection is not successful, the output
shows an error message that explains the issue.
## [[3 ][Preventing node fencing during a kernel dump]] [\#](index.html#ha-fencing-preventing-during-kernel-dump "Permalink") 
[ ]
Use this procedure if the nodes have `kdump` configured. If
not, you can skip this procedure.
The *fence_kdump* agent checks if a node is performing a kernel dump
(`kdump`). If a `kdump` is in progress, the
cluster acts as if the node was fenced, because the node will reboot
after the `kdump` is complete. If a `kdump` is
not in progress, the next fencing device fences the node. This fence
agent must be used together with a physical fencing device. It cannot be
used with SBD.
[[Requirements
]][\#](index.html#id-1.4.3 "Permalink")
[ ]
- The cluster uses a physical node fencing device.
- Cluster resources for the fencing device are already configured.
- `kdump` is installed and configured on all nodes.
Perform this procedure on only one node in the cluster:
1. Log in either as the `root` user or as a user with
    `sudo` privileges.
2. Create a `fence_kdump` resource that can check all the
    nodes in the cluster. For example:
    ``` screen
    > sudo crm configure primitive RESOURCE-NAME stonith:fence_kdump \
      params pcmk_host_list="NODE-LIST" timeout=INTEGER
    ```
    The resource is registered with the `pacemaker-fenced`
    daemon on all the specified nodes. You do not need to clone this
    resource.
    For more information, run the
    `crm ra info stonith:fence_kdump` command.
    [[Example 4: ][`fence_kdump` resource for
    two nodes
    ]][\#](index.html#ha-fencing-preventing-during-kernel-dump-primitives "Permalink")
    [ ]
    This example shows a basic resource configuration for two nodes,
    `alice` and `bob`:
    ``` screen
    > sudo crm configure primitive check-kdump stonith:fence_kdump \
      params pcmk_host_list="alice,bob"1 timeout=602
    ```
      -------------------------------------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
      [[1]](index.html#co-ha-fence-kdump-nodename)   A comma-separated list of the cluster nodes. When a node needs to be fenced, this resource listens for a message from `fence_kdump_send` on that node. If a message is received, the node is considered fenced. If no message is received, the physical fencing device must fence the node.
      [[2]](index.html#co-ha-fence-kdump-timeout)    How long to wait for a message from a node. The default is `60` seconds.
      -------------------------------------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
3. Check that the `fence_kdump` resource appears on all
    nodes:
    ``` screen
    > sudo crm cluster run "sudo stonith_admin -L"
    ```
    You should see output similar to this:
    ``` screen
    INFO: [alice]
    check-kdump
    fence-rsa-bob
    2 fence devices found
    INFO: [bob]
    check-kdump
    fence-rsa-alice
    2 fence devices found
    ```
4. Specify the order of the fencing devices. This tells the cluster to
    check if a `kdump` is in progress *before* deciding
    whether to call the physical fencing device. Include all the nodes
    in one command:
    ``` screen
    > sudo crm configure fencing_topology \
      NODE-NAME: KDUMP-RESOURCE FENCING-RESOURCE \
      NODE-NAME: KDUMP-RESOURCE FENCING-RESOURCE \
      [...]
    ```
    For more information, run the
    `crm configure help fencing_topology` command.
    [[Example 5: ][Fencing topology for two nodes
    ]][\#](index.html#ha-fencing-preventing-during-kernel-dump-topology "Permalink")
    [ ]
    This example shows the order of the fencing devices for two nodes,
    `alice` and `bob`:
    ``` screen
    > sudo crm configure fencing_topology \
      alice: check-kdump fence-rsa-alice \
      bob: check-kdump fence-rsa-bob
    ```
    Both nodes have `kdump` and a physical IBM RSA device
    configured. If `alice` needs to be fenced, the cluster
    first calls the resource `check-kdump` to check whether
    `alice` is performing a `kdump`. If not,
    the cluster calls the resource `fence-rsa-alice` to fence
    `alice`.
5. You might need to increase the fencing timeout so the fencing action
    has time to finish:
    ``` screen
    > sudo crm configure property stonith-timeout=INTEGER
    ```
    The appropriate value depends on your specific setup and
    infrastructure.
6. Open the firewall port for `kdump` messages on all nodes:
    ``` screen
    > sudo crm cluster run "sudo firewall-cmd --add-port=7410/udp --permanent"
    > sudo crm cluster run "sudo firewall-cmd --reload"
    ```
7. Configure `fence_kdump_send` to send a message to all
    nodes when the `kdump` process is finished. In the file
    `/etc/sysconfig/kdump`, edit the
    `KDUMP_POSTSCRIPT` line:
    ``` screen
    KDUMP_POSTSCRIPT="/usr/lib/fence_kdump_send -c 51 -i 102 -p 74103 NODE-LIST"4
    ```
      ---------------------------------------------------------- -----------------------------------------------------------------------------------------------------------------------------------------------------------
      [[1]](index.html#co-fence-kdump-send-count)      Use `--count` (or `-c`) to specify how many messages to send. We recommend sending multiple messages in case the first message fails.
      [[2]](index.html#co-fence-kdump-send-interval)   Use `--interval` (or `-i`) to specify the interval between messages. The default is `10` seconds.
      [[3]](index.html#co-fence-kdump-send-port)       Use `--port` (or `-p`) to specify the firewall port for `kdump` messages.
      [[4]](index.html#co-fence-kdump-send-nodes)      Replace *NODE-LIST* with a space-separated list of all the cluster nodes.
      ---------------------------------------------------------- -----------------------------------------------------------------------------------------------------------------------------------------------------------
8. Copy the `kdump``/etc/sysconfig/kdump` file
    to the rest of the nodes:
    ``` screen
    > sudo crm cluster copy /etc/sysconfig/kdump
    ```
9. Regenerate the `kdump` `initrd` on all
    nodes:
    ``` screen
    > sudo crm cluster run "sudo mkdumprd"
    ```
## [[4 ][Testing node fencing]] [\#](index.html#ha-testing-cluster-failures "Permalink") 
[ ]
The `crm cluster crash_test` command simulates cluster
failures and reports the results. To test node fencing, you can run one
or both of the tests `--fence-node` and
`--split-brain-iptables`.
The command supports the following checks:
[`--fence-node`*`NODE`*]
Fences a specific node passed from the command line.
[`--kill-sbd`/`--kill-corosync`/ `--kill-pacemakerd`]
Kills the daemons for SBD, Corosync, or Pacemaker. After running one
    of these tests, you can find a report in the directory
    `/var/lib/crmsh/crash_test/`. The report includes a test
    case description, action logging, and an explanation of possible
    results.
[`--split-brain-iptables`]
Simulates a split-brain scenario by blocking the Corosync port, and
    checks whether one node can be fenced as expected. You must install
    [iptables] before you can run this test.
For more information, run the `crm cluster crash_test --help`
command.
This example uses nodes called `alice` and
`bob`, and tests fencing `bob`. To watch
`bob` change status during the test, you can log in to Hawk
and navigate to [Status] › [Nodes], or run
`crm status` from another node.
[[Example 6: ][Manually triggering node fencing
]][\#](index.html#id-1.5.6 "Permalink")
[ ]
``` screen
admin@alice> sudo crm cluster crash_test --fence-node bob
==============================================
Testcase:          Fence node bob
Fence action:      reboot
Fence timeout:     95
!!! WARNING WARNING WARNING !!!
THIS CASE MAY LEAD TO NODE BE FENCED.
TYPE Yes TO CONTINUE, OTHER INPUTS WILL CANCEL THIS CASE [Yes/No](No): Yes
INFO: Trying to fence node "bob"
INFO: Waiting 95s for node "bob" reboot...
INFO: Node "bob" will be fenced by "alice"!
INFO: Node "bob" was fenced by "alice" at DATE TIME
```
## [[5 ][Legal Notice]] [\#](index.html#legal-disclaimer "Permalink") 
[ ]
Copyright© 2006--2026 SUSE LLC and contributors. All rights reserved.
Permission is granted to copy, distribute and/or modify this document
under the terms of the GNU Free Documentation License, Version 1.2 or
(at your option) version 1.3; with the Invariant Section being this
copyright notice and license. A copy of the license version 1.2 is
included in the section entitled ["[GNU Free Documentation
License]"].
For SUSE trademarks, see
[https://www.suse.com/company/legal/](https://www.suse.com/company/legal/). All other third-party trademarks are the property of
their respective owners. Trademark symbols (®, ™ etc.) denote trademarks
of SUSE and its affiliates. Asterisks (\*) denote third-party
trademarks.
All information found in this book has been compiled with utmost
attention to detail. However, this does not guarantee complete accuracy.
Neither SUSE LLC, its affiliates, the authors, nor the translators shall
be held liable for possible errors or the consequences thereof.
[[Next][[Appendix A ]GNU Free
Documentation
License]](doc-gfdl-license.html)
On this page
- [[[1 ][What is node
  fencing?]](index.html#ha-fencing-what-is)]
- [[[2 ][Creating fencing resources for a physical
  device]](index.html#ha-fencing-creating-resources-for-physical-device)]
- [[[3 ][Preventing node fencing during a kernel
  dump]](index.html#ha-fencing-preventing-during-kernel-dump)]
- [[[4 ][Testing node
  fencing]](index.html#ha-testing-cluster-failures)]
- [[[5 ][Legal
  Notice]](index.html#legal-disclaimer)]
- [[[A ][GNU Free Documentation
  License]](doc-gfdl-license.html)]
- [[[HA glossary]](ha-glossary.html)]
Share this page
- [](index.html# "E-Mail")
- [](index.html# "Print this page")
