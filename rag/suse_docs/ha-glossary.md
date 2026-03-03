Configuring Node Fencing in a High Availability Cluster
1.  [[1 ][What is node
    fencing?]](index.html#ha-fencing-what-is)
2.  [[2 ][Creating fencing resources for a physical
    device]](index.html#ha-fencing-creating-resources-for-physical-device)
3.  [[3 ][Preventing node fencing during a kernel
    dump]](index.html#ha-fencing-preventing-during-kernel-dump)
4.  [[4 ][Testing node
    fencing]](index.html#ha-testing-cluster-failures)
5.  [[5 ][Legal
    Notice]](index.html#legal-disclaimer)
6.  [[A ][GNU Free Documentation
    License]](doc-gfdl-license.html)
7.  [[ ][HA
    glossary]](ha-glossary.html)
On this page
Applies to [[[SUSE Linux Enterprise High
Availability]]] 16.0
## [[ ][HA glossary]] [\#](ha-glossary.html# "Permalink") 
[ ]
[active/active, active/passive] [\#](ha-glossary.html#id-1.8.2 "Permalink")
How resources run on the nodes. Active/passive means that resources
    only run on the active node, but can move to the passive node if the
    active node fails. Active/active means that all nodes are active at
    once, and resources can run on (and move to) any node in the
    cluster.
[arbitrator] [\#](ha-glossary.html#gloss-arbitrator "Permalink")
An *arbitrator* is a machine running outside the cluster to provide
    an additional instance for cluster calculations. For example,
    [QNetd](ha-glossary.html#gloss-qnetd "QNetd") provides a vote
    to help [QDevice](ha-glossary.html#gloss-qdevice "QDevice")
    participate in
    [quorum](ha-glossary.html#gloss-quorum "quorum") decisions.
[CIB (cluster information base)] [\#](ha-glossary.html#id-1.8.4 "Permalink")
An XML representation of the whole cluster configuration and status
    (cluster options, nodes, resources, constraints and the
    relationships to each other). The CIB manager
    (`pacemaker-based`) keeps the CIB synchronized across
    the cluster and handles requests to modify it.
[clone] [\#](ha-glossary.html#gloss-clone "Permalink")
A *clone* is an identical copy of an existing node, used to make
    deploying multiple nodes simpler.
    In the context of a cluster
    [resource](ha-glossary.html#gloss-resource "resource"), a
    clone is a resource that can be active on multiple nodes. Any
    resource can be cloned if its resource agent supports it.
[cluster] [\#](ha-glossary.html#id-1.8.6 "Permalink")
A *high-availability* cluster is a group of servers (physical or
    virtual) designed primarily to secure the highest possible
    availability of data, applications and services. Not to be confused
    with a *high-performance* cluster, which shares the application load
    to achieve faster results.
[Cluster logical volume manager (Cluster LVM)] [\#](ha-glossary.html#id-1.8.7 "Permalink")
The term *Cluster LVM* indicates that LVM is being used in a cluster
    environment. This requires configuration adjustments to protect the
    LVM metadata on shared storage.
[cluster partition] [\#](ha-glossary.html#gloss-clus-part "Permalink")
A cluster partition occurs when communication fails between one or
    more nodes and the rest of the cluster. The nodes are split into
    partitions but are still active. They can only communicate with
    nodes in the same partition and are unaware of the separated nodes.
    This is known as a [split
    brain](ha-glossary.html#gloss-splitbrain "split brain")
    scenario.
[cluster stack] [\#](ha-glossary.html#id-1.8.9 "Permalink")
The ensemble of software technologies and components that make up a
    cluster.
[colocation constraint] [\#](ha-glossary.html#gloss-col-con "Permalink")
A type of [resource
    constraint](ha-glossary.html#gloss-resource-con "resource constraint")
    that specifies which resources can or cannot run together on a node.
[concurrency violation] [\#](ha-glossary.html#id-1.8.11 "Permalink")
A resource that should be running on only one node in the cluster is
    running on several nodes.
[Corosync] [\#](ha-glossary.html#gloss-corosync "Permalink")
Corosync provides reliable messaging, membership and quorum
    information about the cluster. This is handled by the Corosync
    Cluster Engine, a group communication system.
[CRM (cluster resource manager)] [\#](ha-glossary.html#gloss-crm "Permalink")
The management entity responsible for coordinating all non-local
    interactions in a High Availability cluster. SUSE Linux Enterprise
    High Availability uses
    [Pacemaker](ha-glossary.html#gloss-pacemaker "Pacemaker") as
    the CRM. It interacts with several components: local executors on
    its own node and on the other nodes, non-local CRMs, administrative
    commands, the fencing functionality, and the membership layer.
[`crmsh` (CRM Shell)] [\#](ha-glossary.html#id-1.8.14 "Permalink")
The command-line utility *`crmsh`* manages the cluster,
    nodes and resources.
[Csync2] [\#](ha-glossary.html#id-1.8.15 "Permalink")
A synchronization tool for replicating configuration files across
    all nodes in the cluster.
[DC (designated coordinator)] [\#](ha-glossary.html#gloss-dc "Permalink")
The `pacemaker-controld` daemon is the cluster
    controller, which coordinates all actions. This daemon has an
    instance on each cluster node, but only one instance is elected to
    act as the DC. The DC is elected when the cluster services start, or
    if the current DC fails or leaves the cluster. The DC decides
    whether a cluster-wide change must be performed, such as fencing a
    node or moving resources.
[disaster] [\#](ha-glossary.html#id-1.8.17 "Permalink")
An unexpected interruption of critical infrastructure caused by
    nature, humans, hardware failure, or software bugs.
[disaster recovery] [\#](ha-glossary.html#gloss-dis-rec "Permalink")
The process by which a function is restored to the normal, steady
    state after a disaster.
[Disaster Recovery Plan] [\#](ha-glossary.html#id-1.8.19 "Permalink")
A strategy to recover from a disaster with the minimum impact on IT
    infrastructure.
[DLM (Distributed Lock Manager)] [\#](ha-glossary.html#id-1.8.20 "Permalink")
DLM coordinates accesses to shared resources in a cluster, for
    example, managing file locking in clustered file systems to increase
    performance and availability.
[DRBD] [\#](ha-glossary.html#gloss-drbd "Permalink")
[DRBD]® is a block device designed for building High
    Availability clusters. It replicates data on a primary device to
    secondary devices in a way that ensures all copies of the data
    remain identical.
[existing cluster] [\#](ha-glossary.html#id-1.8.22 "Permalink")
The term *existing cluster* is used to refer to any cluster that
    consists of at least one node. An existing cluster has a basic
    [Corosync](ha-glossary.html#gloss-corosync "Corosync")
    configuration that defines the communication channels, but does not
    necessarily have resource configuration yet.
[failover] [\#](ha-glossary.html#glo-failover "Permalink")
Occurs when a resource or node fails on one machine and the affected
    resources move to another node.
[failover domain] [\#](ha-glossary.html#id-1.8.24 "Permalink")
A named subset of cluster nodes that are eligible to run a resource
    if a node fails.
[fencing] [\#](ha-glossary.html#gloss-fencing "Permalink")
Prevents access to a shared resource by isolated or failing cluster
    members. There are two classes of fencing: *resource-level* fencing
    and *node-level* fencing. Resource-level fencing ensures exclusive
    access to a resource. Node-level fencing prevents a failed node from
    accessing shared resources and prevents resources from running on a
    node with an uncertain status. This is usually done by resetting or
    powering off the node.
[GFS2] [\#](ha-glossary.html#id-1.8.26 "Permalink")
Global File System 2 (GFS2) is a shared disk file system for Linux
    computer clusters. GFS2 allows all nodes to have direct concurrent
    access to the same shared block storage. GFS2 has no disconnected
    operating mode, and no client or server roles. All nodes in a GFS2
    cluster function as peers. GFS2 supports up to 32 cluster nodes.
    Using GFS2 in a cluster requires hardware to allow access to the
    shared storage, and a lock manager to control access to the storage.
[group] [\#](ha-glossary.html#id-1.8.27 "Permalink")
Resource groups contain multiple resources that need to be located
    together, started sequentially and stopped in the reverse order.
[Hawk (HA Web Konsole)] [\#](ha-glossary.html#id-1.8.28 "Permalink")
A user-friendly Web-based interface for monitoring and administering
    a High Availability cluster from Linux or non-Linux machines. Hawk
    can be accessed from any machine that can connect to the cluster
    nodes, using a graphical Web browser.
[heuristics] [\#](ha-glossary.html#gloss-heuristics "Permalink")
[QDevice](ha-glossary.html#gloss-qdevice "QDevice") supports
    using a set of commands (*heuristics*) that run locally on start-up
    of cluster services, cluster membership change, successful
    connection to the
    [QNetd](ha-glossary.html#gloss-qnetd "QNetd") server, or
    optionally at regular times. The result is used in calculations to
    determine which partition should have
    [quorum](ha-glossary.html#gloss-quorum "quorum").
[knet (kronosnet)] [\#](ha-glossary.html#id-1.8.30 "Permalink")
A network abstraction layer supporting redundancy, security, fault
    tolerance, and fast fail-over of network links. In SUSE Linux
    Enterprise High Availability 16, *knet* is the default transport
    protocol for the
    [Corosync](ha-glossary.html#gloss-corosync "Corosync")
    communication channels.
[local cluster] [\#](ha-glossary.html#id-1.8.31 "Permalink")
A single cluster in one location (for example, all nodes are located
    in one data center). Network latency is minimal. Storage is
    typically accessed synchronously by all nodes.
[local executor] [\#](ha-glossary.html#id-1.8.32 "Permalink")
The local executor is located between
    [Pacemaker](ha-glossary.html#gloss-pacemaker "Pacemaker") and
    the resources on each node. Through the
    `pacemaker-execd` daemon, Pacemaker can start, stop and
    monitor resources.
[location] [\#](ha-glossary.html#id-1.8.33 "Permalink")
In the context of a whole cluster, *location* can refer to the
    physical location of nodes (for example, all nodes might be located
    in the same data center). In the context of a [location
    constraint](ha-glossary.html#gloss-loc-con "location constraint"),
    *location* refers to the nodes on which a resource can or cannot
    run.
[location constraint] [\#](ha-glossary.html#gloss-loc-con "Permalink")
A type of [resource
    constraint](ha-glossary.html#gloss-resource-con "resource constraint")
    that defines the nodes on which a resource can or cannot run.
[meta attributes (resource options)] [\#](ha-glossary.html#id-1.8.35 "Permalink")
Parameters that tell the [CRM (cluster resource
    manager)](ha-glossary.html#gloss-crm "CRM (cluster resource manager)")
    how to treat a specific
    [resource](ha-glossary.html#gloss-resource "resource"). For
    example, you might define a resource\'s priority or target role.
[metro cluster] [\#](ha-glossary.html#id-1.8.36 "Permalink")
A single cluster that can stretch over multiple buildings or data
    centers, with all sites connected by Fibre Channel. Network latency
    is usually low. Storage is frequently replicated using mirroring or
    synchronous replication.
[network device bonding] [\#](ha-glossary.html#id-1.8.37 "Permalink")
Network device bonding combines two or more network interfaces into
    a single bonded device to increase bandwidth and/or provide
    redundancy. When using
    [Corosync](ha-glossary.html#gloss-corosync "Corosync"), the
    bonded device is not managed by the cluster software. Therefore, the
    bonded device must be configured on every cluster node that might
    need to access it.
[node] [\#](ha-glossary.html#id-1.8.38 "Permalink")
Any server (physical or virtual) that is a member of a cluster.
[order constraint] [\#](ha-glossary.html#gloss-ord-con "Permalink")
A type of [resource
    constraint](ha-glossary.html#gloss-resource-con "resource constraint")
    that defines the sequence of actions.
[Pacemaker] [\#](ha-glossary.html#gloss-pacemaker "Permalink")
Pacemaker is the [CRM (cluster resource
    manager)](ha-glossary.html#gloss-crm "CRM (cluster resource manager)")
    in SUSE Linux Enterprise High Availability, or the
    ["[brain]"] that reacts to events occurring in the
    cluster. Events might be nodes that join or leave the cluster,
    failure of resources, or scheduled activities such as maintenance,
    for example. The `pacemakerd` daemon launches and
    monitors all other related daemons.
[parameters (instance attributes)] [\#](ha-glossary.html#id-1.8.41 "Permalink")
Parameters determine which instance of a service the
    [resource](ha-glossary.html#gloss-resource "resource")
    controls.
[primitive] [\#](ha-glossary.html#id-1.8.43 "Permalink")
A primitive resource is the most basic type of cluster resource.
[promotable clone] [\#](ha-glossary.html#gloss-prom-clone "Permalink")
Promotable clones are a special type of
    [clone](ha-glossary.html#gloss-clone "clone") resource that
    can be promoted. Active instances of these resources are divided
    into two states: promoted and unpromoted (also known as ["[active
    and passive]"] or ["[primary and
    secondary]"]).
[QDevice] [\#](ha-glossary.html#gloss-qdevice "Permalink")
QDevice and [QNetd](ha-glossary.html#gloss-qnetd "QNetd")
    participate in
    [quorum](ha-glossary.html#gloss-quorum "quorum") decisions.
    The `corosync-qdevice` daemon runs on each cluster node
    and communicates with QNetd to provide a configurable number of
    votes, allowing a cluster to sustain more node failures than the
    standard quorum rules allow.
[QNetd] [\#](ha-glossary.html#gloss-qnetd "Permalink")
QNetd is an
    [arbitrator](ha-glossary.html#gloss-arbitrator "arbitrator")
    that runs outside the cluster. The `corosync-qnetd`
    daemon provides a vote to the `corosync-qdevice` daemon
    on each node to help it participate in quorum decisions.
[quorum] [\#](ha-glossary.html#gloss-quorum "Permalink")
A [cluster
    partition](ha-glossary.html#gloss-clus-part "cluster partition")
    is defined to have quorum (be *quorate*) if it has the majority of
    nodes (or ["[votes]"]). Quorum distinguishes exactly
    one partition. This is part of the algorithm to prevent several
    disconnected partitions or nodes (["[split brain]"])
    from proceeding and causing data and service corruption. Quorum is a
    prerequisite for fencing, which then ensures that quorum is unique.
[RA (resource agent)] [\#](ha-glossary.html#id-1.8.48 "Permalink")
A script acting as a proxy to manage a
    [resource](ha-glossary.html#gloss-resource "resource") (for
    example, to start, stop or monitor a resource). SUSE Linux
    Enterprise High Availability supports different kinds of resource
    agents.
[ReaR (Relax and Recover)] [\#](ha-glossary.html#id-1.8.49 "Permalink")
An administrator tool set for creating [disaster
    recovery](ha-glossary.html#gloss-dis-rec "disaster recovery")
    images.
[resource] [\#](ha-glossary.html#gloss-resource "Permalink")
Any type of service or application that is known to
    [Pacemaker](ha-glossary.html#gloss-pacemaker "Pacemaker"),
    for example, an IP address, a file system, or a database. The term
    *resource* is also used for
    [DRBD](ha-glossary.html#gloss-drbd "DRBD"), where it names a
    set of block devices that use a common connection for replication.
[resource constraint] [\#](ha-glossary.html#gloss-resource-con "Permalink")
Resource constraints specify which cluster nodes resources can run
    on, what order resources load in, and what other resources a
    specific resource is dependent on.
    See also [colocation
    constraint](ha-glossary.html#gloss-col-con "colocation constraint"),
    [location
    constraint](ha-glossary.html#gloss-loc-con "location constraint")
    and [order
    constraint](ha-glossary.html#gloss-ord-con "order constraint").
[resource set] [\#](ha-glossary.html#id-1.8.52 "Permalink")
As an alternative format for defining location, colocation or order
    constraints, you can use *resource sets*, where primitives are
    grouped together in one set. When creating a constraint, you can
    specify multiple resources for the constraint to apply to.
[resource template] [\#](ha-glossary.html#id-1.8.53 "Permalink")
To help create many resources with similar configurations, you can
    define a resource template. After being defined, it can be
    referenced in primitives or in certain types of constraints. If a
    template is referenced in a primitive, the primitive inherits all
    operations, instance attributes (parameters), meta attributes and
    utilization attributes defined in the template.
[SBD (STONITH Block Device)] [\#](ha-glossary.html#gloss-sbd "Permalink")
SBD provides a node
    [fencing](ha-glossary.html#gloss-fencing "fencing") mechanism
    through the exchange of messages via shared block storage.
    Alternatively, it can be used in diskless mode. In either case, it
    needs a hardware or software
    [watchdog](ha-glossary.html#gloss-watchdog "watchdog") on
    each node to ensure that misbehaving nodes are really stopped.
[scheduler] [\#](ha-glossary.html#id-1.8.42 "Permalink")
The scheduler is implemented as `pacemaker-schedulerd`.
    When a cluster transition is needed,
    `pacemaker-schedulerd` calculates the expected next
    state of the cluster and determines what actions need to be
    scheduled to achieve the next state.
[split brain] [\#](ha-glossary.html#gloss-splitbrain "Permalink")
A scenario in which the cluster nodes are divided into two or more
    groups that do not know about each other (either through a software
    or hardware failure).
    [STONITH](ha-glossary.html#gloss-stonith "STONITH") prevents
    a split-brain scenario from badly affecting the entire cluster. Also
    known as a *partitioned cluster* scenario.
    The term *split brain* is also used in
    [DRBD](ha-glossary.html#gloss-drbd "DRBD") but means that the
    nodes contain different data.
[SPOF (single point of failure)] [\#](ha-glossary.html#id-1.8.56 "Permalink")
Any component of a cluster that, if it fails, triggers the failure
    of the entire cluster.
[STONITH] [\#](ha-glossary.html#gloss-stonith "Permalink")
Another term for the
    [fencing](ha-glossary.html#gloss-fencing "fencing") mechanism
    that shuts down a misbehaving node to prevent it from causing
    trouble in a cluster. In a
    [Pacemaker](ha-glossary.html#gloss-pacemaker "Pacemaker")
    cluster, node fencing is managed by the fencing subsystem
    `pacemaker-fenced`.
[switchover] [\#](ha-glossary.html#id-1.8.58 "Permalink")
The planned moving of resources to other nodes in a cluster. See
    also [failover](ha-glossary.html#glo-failover "failover").
[utilization] [\#](ha-glossary.html#id-1.8.59 "Permalink")
Tells the CRM what capacity a certain
    [resource](ha-glossary.html#gloss-resource "resource")
    requires from a node.
[watchdog] [\#](ha-glossary.html#gloss-watchdog "Permalink")
[SBD (STONITH Block
    Device)](ha-glossary.html#gloss-sbd "SBD (STONITH Block Device)")
    needs a watchdog on each node to ensure that misbehaving nodes are
    really stopped. SBD ["[feeds]"] the watchdog by
    regularly writing a service pulse to it. If SBD stops feeding the
    watchdog, the hardware enforces a system restart. This protects
    against failures of the SBD process itself, such as becoming stuck
    on an I/O error.
[[Previous][[Appendix A ]GNU Free
Documentation
License]](doc-gfdl-license.html)
Share this page
- [](ha-glossary.html# "E-Mail")
- [](ha-glossary.html# "Print this page")
