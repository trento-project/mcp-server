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
# [[4 ][Installation]] [\#](id-installation.html# "Permalink") 
[ ]
## [[4.1 ][Installing Trento Server]] [\#](id-installation.html#sec-trento-installing-trentoserver "Permalink") 
[ ]
Trento Server can be deployed in different ways depending on your
infrastructure and requirements.
Supported deployment methods:
- [Section 4.1.1, "Kubernetes
  deployment"](id-installation.html#sec-trento-k8s-deployment "4.1.1. Kubernetes deployment")
- [Section 4.1.2, "systemd
  deployment"](id-installation.html#sec-systemd-deployment "4.1.2. systemd deployment")
### [[4.1.1 ][Kubernetes deployment]] [\#](id-installation.html#sec-trento-k8s-deployment "Permalink") 
[ ]
The subsection uses the following placeholders:
- `TRENTO_SERVER_HOSTNAME`: the host name used by the end user
  to access the console.
- `ADMIN_PASSWORD`: the password of the admin user created
  during the installation process.
  The password must meet the following requirements:
  - minimum length of 8 characters
  - the password must not contain 3 identical numbers or letters in a
    row (for example, 111 or aaa)
  - the password must not contain 4 sequential numbers or letters (for
    example, 1234, abcd, ABCD)
![Important](static/images/icon-important.svg "Important")
Important
By default, the provided Helm chart uses
[Traefik](https://github.com/traefik/traefik) as
ingress class\
Main usages are related to:
- path rewriting
- endpoint protection
Search for Traefik [specific usage scenarios on
GitHub](https://github.com/search?q=repo%3Atrento-project%2Fhelm-charts+traefik&type=code). In case another ingress controller is used, adapt
accordingly.
#### [[4.1.1.1 ][Installing Trento Server on an existing Kubernetes cluster]] [\#](id-installation.html#sec-trento-install-trentoserver-on-existing-k8s-cluster "Permalink") 
[ ]
Trento Server consists of a several components delivered as container
images and intended for deployment on a Kubernetes cluster. A manual
production-ready deployment of these components requires Kubernetes
knowledge. Customers without in-house Kubernetes expertise and those who
want to try Trento with a minimum of effort, can use the Trento Helm
chart. This approach automates the deployment of all the required
components on a single Kubernetes cluster node. You can use the Trento
Helm chart to install Trento Server on a existing Kubernetes cluster as
follows:
![Note](static/images/icon-note.svg "Note")
Note
The examples in this section do not specify a Kubernetes namespace for
simplicity. By default, Helm installs to the `default`
namespace.
For production deployments, create and use a dedicated namespace.
Example:
``` programlisting
kubectl create namespace trento
helm upgrade \
   --install trento-server oci://registry.suse.com/trento/trento-server \
   --namespace trento \
   --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
   --set trento-web.adminUser.password=ADMIN_PASSWORD
```
1.  Install Helm:
    ``` programlisting
    curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash
    ```
2.  Connect Helm to an existing Kubernetes cluster.
3.  Use Helm to install Trento Server with the Trento Helm chart:
    ``` programlisting
    helm upgrade \
       --install trento-server oci://registry.suse.com/trento/trento-server \
       --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
       --set trento-web.adminUser.password=ADMIN_PASSWORD
    ```
    When using a Helm version lower than 3.8.0, an experimental flag
    must be set as follows:
    ``` programlisting
    HELM_EXPERIMENTAL_OCI=1 helm upgrade \
       --install trento-server oci://registry.suse.com/trento/trento-server \
       --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
       --set trento-web.adminUser.password=ADMIN_PASSWORD
    ```
4.  To verify that the Trento Server installation was successful, open
    the URL of the Trento Web
    ([`http://TRENTO_SERVER_HOSTNAME`](http://TRENTO_SERVER_HOSTNAME)) from a workstation on the SAP administrator's LAN.
#### [[4.1.1.2 ][Installing Trento Server on K3s]] [\#](id-installation.html#sec-trento-install-trentoserver-on-k3s "Permalink") 
[ ]
If you do not have a Kubernetes cluster, or you have one but you do not
want to use it for Trento, you can use SUSE Rancher's K3s as an
alternative. To deploy Trento Server on K3s, you need a server or VM
(see [Section 3.1, "Trento Server
requirements"](sec-trento-requirements.html#sec-trento-server-requirements "3.1. Trento Server requirements")
for minimum requirements) and follow steps in [Section 4.1.1.2.1,
"Manually installing Trento on a Trento Server
host"](id-installation.html#pro-trento-manually-installing "4.1.1.2.1. Manually installing Trento on a Trento Server host").
![Important](static/images/icon-important.svg "Important")
Important
The following procedure deploys Trento Server on a single-node K3s
cluster. Note that this setup is not recommended for production use.
##### [[4.1.1.2.1 ][Manually installing Trento on a Trento Server host]] [\#](id-installation.html#pro-trento-manually-installing "Permalink") 
[ ]
1.  Log in to the Trento Server host.
2.  Install K3s either as root or a non-root user.
    - Installing as user root:
      ``` screen
      curl -sfL https://get.k3s.io | INSTALL_K3S_SKIP_SELINUX_RPM=true sh
      ```
    - Installing as a non-root user:
      ``` programlisting
      curl -sfL https://get.k3s.io | INSTALL_K3S_SKIP_SELINUX_RPM=true sh -s - --write-kubeconfig-mode 644
      ```
3.  Install Helm as root.
    ``` screen
    curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash
    ```
4.  Set the `KUBECONFIG` environment variable for the same
    user that installed K3s:
    ``` programlisting
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
    ```
5.  With the same user that installed K3s, install Trento Server using
    the Helm chart:
    ``` programlisting
    helm upgrade \
       --install trento-server oci://registry.suse.com/trento/trento-server \
       --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
       --set trento-web.adminUser.password=ADMIN_PASSWORD
    ```
    When using a Helm version lower than 3.8.0, an experimental flag
    must be set as follows:
    ``` programlisting
    HELM_EXPERIMENTAL_OCI=1 helm upgrade \
       --install trento-server oci://registry.suse.com/trento/trento-server \
       --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
       --set trento-web.adminUser.password=ADMIN_PASSWORD
    ```
6.  Monitor the creation and start-up of the Trento Server pods, and
    wait until they are ready and running:
    ``` programlisting
    watch kubectl get pods
    ```
    All pods must be in the ready and running state.
7.  Log out of the Trento Server host.
8.  To verify that the Trento Server installation was successful, open
    the URL of the Trento Web
    ([`http://TRENTO_SERVER_HOSTNAME`](http://TRENTO_SERVER_HOSTNAME)) from a workstation on the SAP administrator's LAN.
#### [[4.1.1.3 ][Deploying Trento Server on selected nodes]] [\#](id-installation.html#sec-trento-deploying-trento-on-selected-nodes "Permalink") 
[ ]
If you use a multi-node Kubernetes cluster, it is possible to deploy
Trento Server images on selected nodes by specifying the field
`nodeSelector` in the helm upgrade command as follows:
``` programlisting
HELM_EXPERIMENTAL_OCI=1 helm upgrade \
   --install trento-server oci://registry.suse.com/trento/trento-server \
   --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
   --set trento-web.adminUser.password=ADMIN_PASSWORD \
   --set prometheus.server.nodeSelector.LABEL=VALUE \
   --set postgresql.primary.nodeSelector.LABEL=VALUE \
   --set trento-web.nodeSelector.LABEL=VALUE \
   --set trento-runner.nodeSelector.LABEL=VALUE
```
#### [[4.1.1.4 ][Configuring event pruning]] [\#](id-installation.html#helm-event-pruning "Permalink") 
[ ]
The event pruning feature allows administrators to manage how long
registered events are stored in the database and how often the expired
events are removed.
The following configuration options are available:
[`pruneEventsOlderThan`]
The number of days registered events are stored in the database. The
    default value is [**10**]. *Keep in mind that
    `pruneEventsOlderThan` can be set to [**0**].
    However, this deletes all events whenever the cron job runs, making
    it impossible to analyze and troubleshoot issues with the
    application*
[`pruneEventsCronjobSchedule`]
The frequency of the cron job that deletes expired events. The
    default value is [**\"0 0 \* \* \*\"**], which runs daily
    at midnight.
To modify the default values, execute the following Helm command:
``` programlisting
helm ... \
    --set trento-web.pruneEventsOlderThan=<<EXPIRATION_IN_DAYS>> \
    --set trento-web.pruneEventsCronjobSchedule="<<NEW_SCHEDULE>>"
```
Replace the placeholders with the desired values:
[`EXPIRATION_IN_DAYS`]
Number of days to retain events in the database before pruning.
[`NEW_SCHEDULE`]
The cron rule specifying how frequently the pruning job is
    performed.
[**Example**] command to retain events for 30 days and
schedule pruning daily at 3 AM:
``` programlisting
helm upgrade \
  --install trento-server oci://registry.suse.com/trento/trento-server \
  --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
  --set trento-web.adminUser.password=ADMIN_PASSWORD \
  --set trento-web.pruneEventsOlderThan=30 \
  --set trento-web.pruneEventsCronjobSchedule="0 3 * * *"
```
#### [[4.1.1.5 ][Enabling email alerts]] [\#](id-installation.html#sec-trento-enabling-email-alerts "Permalink") 
[ ]
Email alerting feature notifies the SAP Basis administrator about
important changes in the SAP Landscape being monitored by Trento.
The reported events include the following:
- Host heartbeat failed
- Cluster health detected critical
- Database health detected critical
- SAP System health detected critical
This feature is disabled by default. It can be enabled at installation
time or anytime at a later stage. In both cases, the procedure is the
same and uses the following placeholders:
[`SMTP_SERVER`]
The SMTP server designated to send email alerts
[`SMTP_PORT`]
Port on the SMTP server
[`SMTP_USER`]
User name to access SMTP server
[`SMTP_PASSWORD`]
Password to access SMTP server
[`ALERTING_SENDER`]
Sender email for alert notifications
[`ALERTING_RECIPIENT`]
Email address to receive alert notifications.
The command to enable email alerts is as follows:
``` programlisting
HELM_EXPERIMENTAL_OCI=1 helm upgrade \
   --install trento-server oci://registry.suse.com/trento/trento-server \
   --set global.trentoWeb.origin=TRENTO_SERVER_HOSTNAME \
   --set trento-web.adminUser.password=ADMIN_PASSWORD \
   --set trento-web.alerting.enabled=true \
   --set trento-web.alerting.smtpServer=SMTP_SERVER \
   --set trento-web.alerting.smtpPort=SMTP_PORT \
   --set trento-web.alerting.smtpUser=SMTP_USER \
   --set trento-web.alerting.smtpPassword=SMTP_PASSWORD \
   --set trento-web.alerting.sender=ALERTING_SENDER \
   --set trento-web.alerting.recipient=ALERTING_RECIPIENT
```
#### [[4.1.1.6 ][Enabling SSL]] [\#](id-installation.html#sec-trento-enabling-ssl "Permalink") 
[ ]
Ingress may be used to provide SSL termination for the Web component of
Trento Server. This would allow to encrypt the communication from the
agent to the server, which is already secured by the corresponding API
key. It would also allow HTTPS access to the Web console with trusted
certificates.
Configuration must be done in the tls section of the
`values.yaml` file of the chart of the Trento Server Web
component.
For details on the required Ingress setup and configuration, refer to:
[https://kubernetes.io/docs/concepts/services-networking/ingress/](https://kubernetes.io/docs/concepts/services-networking/ingress/). Particularly, refer to section
[https://kubernetes.io/docs/concepts/services-networking/ingress/#tls](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls) for details on the secret format in the YAML
configuration file.
Additional steps are required on the Agent side.
### [[4.1.2 ][systemd deployment]] [\#](id-installation.html#sec-systemd-deployment "Permalink") 
[ ]
A systemd-based installation of the Trento Server using RPM packages can
be performed manually on the latest supported versions of SUSE Linux
Enterprise Server for SAP applications, from 15 SP4 up to 16. For
installations on service packs other than the current one, make sure to
update the repository URL as described in the relevant notes throughout
this guide.
#### [[4.1.2.1 ][List of dependencies]] [\#](id-installation.html#id-list-of-dependencies "Permalink") 
[ ]
- [NGINX](https://nginx.org/en/)
- [PostgreSQL](https://www.postgresql.org/)
- [RabbitMQ](https://rabbitmq.com/)
#### [[4.1.2.2 ][Install Trento dependencies]] [\#](id-installation.html#id-install-trento-dependencies "Permalink") 
[ ]
##### [[4.1.2.2.1 ][Install PostgreSQL]] [\#](id-installation.html#id-install-postgresql "Permalink") 
[ ]
The current instructions are tested with the following PostgreSQL
versions:
  SUSE Linux Enterprise Server for SAP applications   PostgreSQL Version
  --------------------------------------------------- --------------------
  15 SP4                                              14.10
  15 SP5                                              15.5
  15 SP6                                              16.9
  15 SP7                                              17.5
  16.0                                                17.6
Using a different version of PostgreSQL may require different steps or
configurations, especially when changing the major number. For more
details, refer to the official [PostgreSQL
documentation](https://www.postgresql.org/docs/).
1.  Install PostgreSQL server:
    ``` programlisting
    zypper in postgresql-server
    ```
2.  Enable and start PostgreSQL server:
    ``` programlisting
    systemctl enable --now postgresql
    ```
##### [[4.1.2.2.2 ][Configure PostgreSQL]] [\#](id-installation.html#id-configure-postgresql "Permalink") 
[ ]
1.  Start `psql` with the `postgres` user to open a
    connection to the database:
    ``` programlisting
    su - postgres
    psql
    ```
2.  Initialize the databases in the `psql` console:
    ``` programlisting
    CREATE DATABASE wanda;
    CREATE DATABASE trento;
    CREATE DATABASE trento_event_store;
    ```
3.  Create the users:
    ``` programlisting
    CREATE USER wanda_user WITH PASSWORD 'wanda_password';
    CREATE USER trento_user WITH PASSWORD 'web_password';
    ```
4.  Grant required privileges to the users and close the connection:
    ``` programlisting
    \c wanda
    GRANT ALL ON SCHEMA public TO wanda_user;
    \c trento
    GRANT ALL ON SCHEMA public TO trento_user;
    \c trento_event_store;
    GRANT ALL ON SCHEMA public TO trento_user;
    \q
    ```
    You can exit from the `psql` console and
    `postgres` user.
5.  Allow the PostgreSQL database to receive connections to the
    respective databases and users. To do this, add the following to
    `/var/lib/pgsql/data/pg_hba.conf`:
    ``` programlisting
    host   wanda                      wanda_user    0.0.0.0/0     scram-sha-256
    host   trento,trento_event_store  trento_user   0.0.0.0/0     scram-sha-256
    ```
    ![Note](static/images/icon-note.svg "Note")
    Note
    The `pg_hba.conf` file works sequentially. This means that
    the rules on the top have preference over the ones below. The
    example above shows a permissive address range. So for this to work,
    the entires must be written at the top of the `host`
    entries. For further information, refer to the
    [pg_hba.conf](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html) documentation.
6.  Allow PostgreSQL to bind on all network interfaces in
    `/var/lib/pgsql/data/postgresql.conf` by changing the
    following line:
    ``` programlisting
    listen_addresses = '*'
    ```
7.  Restart PostgreSQL to apply the changes:
    ``` programlisting
    systemctl restart postgresql
    ```
##### [[4.1.2.2.3 ][Install RabbitMQ]] [\#](id-installation.html#id-install-rabbitmq "Permalink") 
[ ]
1.  Install RabbitMQ server:
    ``` programlisting
    zypper install rabbitmq-server
    ```
2.  Allow connections from external hosts by modifying
    `/etc/rabbitmq/rabbitmq.conf`, so the Trento-agent can
    reach RabbitMQ:
    ``` programlisting
    listeners.tcp.default = 5672
    ```
3.  If firewalld is running, add a rule to firewalld:
    ``` programlisting
    firewall-cmd --zone=public --add-port=5672/tcp --permanent;
    firewall-cmd --reload
    ```
4.  Enable the RabbitMQ service:
    ``` programlisting
    systemctl enable --now rabbitmq-server
    ```
##### [[4.1.2.2.4 ][Configure RabbitMQ]] [\#](id-installation.html#id-configure-rabbitmq "Permalink") 
[ ]
To configure RabbitMQ for a production system, follow the official
suggestions in the [RabbitMQ
guide](https://www.rabbitmq.com/production-checklist.html).
1.  Create a new RabbitMQ user:
    ``` programlisting
    rabbitmqctl add_user trento_user trento_user_password
    ```
2.  Create a virtual host:
    ``` programlisting
    rabbitmqctl add_vhost vhost
    ```
3.  Set permissions for the user on the virtual host:
    ``` programlisting
    rabbitmqctl set_permissions -p vhost trento_user ".*" ".*" ".*"
    ```
#### [[4.1.2.3 ][Install Trento using RPM packages]] [\#](id-installation.html#id-install-trento-using-rpm-packages "Permalink") 
[ ]
The `trento-web` and `trento-wanda` packages are
available by default on supported SUSE Linux Enterprise Server for SAP
applications distributions.
Install Trento web, wanda and checks:
``` programlisting
zypper install trento-web trento-wanda
```
##### [[4.1.2.3.1 ][Create the configuration files]] [\#](id-installation.html#id-create-the-configuration-files "Permalink") 
[ ]
Both services depend on respective configuration files. They must be
placed in `/etc/trento/trento-web` and
`/etc/trento/trento-wanda` respectively, and examples of how
to modify them are available in
`/etc/trento/trento-web.example` and
`/etc/trento/trento-wanda.example`.
![Note](static/images/icon-note.svg "Note")
Note
You can create the content of the secret variables such as
`SECRET_KEY_BASE`, `ACCESS_TOKEN_ENC_SECRET` and
`REFRESH_TOKEN_ENC_SECRET` using `openssl`:
``` programlisting
openssl rand -out /dev/stdout 48 | base64
```
Also ensure that a valid hostname, FQDN, or IP address is configured in
`TRENTO_WEB_ORIGIN` when using HTTPS. Otherwise, WebSocket
connections will fail, preventing real-time updates in the web
interface.
##### [[4.1.2.3.2 ][trento-web configuration]] [\#](id-installation.html#id-trento-web-configuration "Permalink") 
[ ]
``` programlisting
# /etc/trento/trento-web
AMQP_URL=amqp://trento_user:trento_user_password@localhost:5672/vhost
DATABASE_URL=ecto://trento_user:web_password@localhost/trento
EVENTSTORE_URL=ecto://trento_user:web_password@localhost/trento_event_store
ENABLE_ALERTING=false
CHARTS_ENABLED=false
ADMIN_USER=admin
ADMIN_PASSWORD=trentodemo
ENABLE_API_KEY=true
PORT=4000
TRENTO_WEB_ORIGIN=trento.example.com
SECRET_KEY_BASE=some-secret
ACCESS_TOKEN_ENC_SECRET=some-secret
REFRESH_TOKEN_ENC_SECRET=some-secret
CHECKS_SERVICE_BASE_URL=/wanda
OAS_SERVER_URL=https://trento.example.com
```
The `ADMIN_PASSWORD` variable must must meet the following
requiements:
- minimum of 8 characters
- the password not contain 3 consecutive identical numbers or letters
  (for example, 111 or aaa)
- the password must not contain 4 consecutive numbers or letters (for
  example, 1234, abcd, ABCD)
The `ENABLE_ALERTING` enables the [alerting system to receive
email
notifications](https://www.trento-project.io/docs/web/Alerting/alerting.html). Set `ENABLE_ALERTING` to `true`
and add additional variables to the `/etc/trento/trento-web`,
to enable the feature.
``` programlisting
# /etc/trento/trento-web
ENABLE_ALERTING=true
ALERT_SENDER=<<SENDER_EMAIL_ADDRESS>>
ALERT_RECIPIENT=<<RECIPIENT_EMAIL_ADDRESS>>
SMTP_SERVER=<<SMTP_SERVER_ADDRESS>>
SMTP_PORT=<<SMTP_PORT>>
SMTP_USER=<<SMTP_USER>>
SMTP_PASSWORD=<<SMTP_PASSWORD>>
```
##### [[4.1.2.3.3 ][trento-wanda configuration]] [\#](id-installation.html#id-trento-wanda-configuration "Permalink") 
[ ]
``` programlisting
# /etc/trento/trento-wanda
CORS_ORIGIN=http://localhost
AMQP_URL=amqp://trento_user:trento_user_password@localhost:5672/vhost
DATABASE_URL=ecto://wanda_user:wanda_password@localhost/wanda
PORT=4001
SECRET_KEY_BASE=some-secret
OAS_SERVER_URL=https://trento.example.com/wanda
AUTH_SERVER_URL=http://localhost:4000
```
##### [[4.1.2.3.4 ][Start the services]] [\#](id-installation.html#id-start-the-services "Permalink") 
[ ]
![Note](static/images/icon-note.svg "Note")
Note
In some SUSE Linux Enterprise Server for SAP applications environments,
SELinux may be enabled and set to [**enforcing**] mode by
default. If Trento services fail to start or show permission-related
errors, check the SELinux status:
``` programlisting
getenforce
```
If SELinux is set to [**enforcing**], switch it to
[**permissive**] mode either temporarily or permanently:
- [**Temporary change (until reboot):**]
  ``` programlisting
  setenforce 0
  ```
- [**Permanent change (persists after reboot):**]
  Edit `/etc/selinux/config` and set:
  ``` screen
  SELINUX=permissive
  ```
Enable and start the services:
``` programlisting
systemctl enable --now trento-web trento-wanda
```
##### [[4.1.2.3.5 ][Monitor the services]] [\#](id-installation.html#id-monitor-the-services "Permalink") 
[ ]
Use `journalctl` to check if the services are up and running
correctly. For example:
``` programlisting
journalctl -fu trento-web
```
#### [[4.1.2.4 ][Check the health status of Trento Web and Trento Wanda]] [\#](id-installation.html#validate-the-health-status-of-trento-web-and-wanda "Permalink") 
[ ]
You can check if Trento Web and Trento Wanda services function correctly
by accessing accessing the `healthz` and `readyz`
API.
1.  Check Trento Web health status using `curl`:
    ``` programlisting
    curl http://localhost:4000/api/readyz
    ```
    ``` programlisting
    curl http://localhost:4000/api/healthz
    ```
2.  Check Trento wanda health status using `curl`:
    ``` programlisting
    curl http://localhost:4001/api/readyz
    ```
    ``` programlisting
    curl http://localhost:4001/api/healthz
    ```
If Trento web and wanda are ready, and the database connection is set up
correctly, the output should be as follows:
``` programlisting
```
#### [[4.1.2.5 ][Install and configure NGINX]] [\#](id-installation.html#id-install-and-configure-nginx "Permalink") 
[ ]
1.  Install NGINX package:
    ``` programlisting
    zypper install nginx
    ```
2.  If firewalld is running, add firewalld rules for HTTP and HTTPS:
    ``` programlisting
    firewall-cmd --zone=public --add-service=https --permanent
    firewall-cmd --zone=public --add-service=http --permanent
    firewall-cmd --reload
    ```
3.  Start and enable NGINX:
    ``` programlisting
    systemctl enable --now nginx
    ```
4.  Create a `/etc/nginx/conf.d/trento.conf` Trento
    configuration file:
    ``` programlisting
    map $http_upgrade $connection_upgrade 
    upstream web 
    upstream wanda 
    server 
    server 
        # Web rule
        location / 
            allow all;
            # Proxy Headers
            proxy_http_version 1.1;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header Host $http_host;
            proxy_set_header X-Cluster-Client-Ip $remote_addr;
            # The Important Websocket Bits!
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_pass http://web;
        }
    }
    ```
#### [[4.1.2.6 ][Prepare SSL certificate for NGINX]] [\#](id-installation.html#id-prepare-ssl-certificate-for-nginx "Permalink") 
[ ]
Create or provide a certificate for [NGINX](https://nginx.org/en/) to enable SSL for Trento.
##### [[4.1.2.6.1 ][Create a self-signed certificate]] [\#](id-installation.html#option-1-creating-a-self-signed-certificate "Permalink") 
[ ]
1.  Generate a self-signed certificate:
    ![Note](static/images/icon-note.svg "Note")
    Note
    Adjust `subjectAltName = DNS:trento.example.com` by
    replacing `trento.example.com` with your domain and change
    the value `5` to the number of days for which you need the
    certificate to be valid. For example, `-days 365` for one
    year.
    ``` programlisting
    openssl req -newkey rsa:2048 --nodes -keyout trento.key -x509 -days 5 -out trento.crt -addext "subjectAltName = DNS:trento.example.com"
    ```
2.  Copy the generated `trento.key` to a location accessible
    by NGINX:
    ``` programlisting
    cp trento.key /etc/ssl/private/trento.key
    ```
3.  Create a directory for the generated `trento.crt` file.
    The directory must be accessible by NGINX:
    ``` programlisting
    mkdir -p /etc/nginx/ssl/certs/
    ```
4.  Copy the generated `trento.crt` file to the created
    directory:
    ``` programlisting
    cp trento.crt /etc/nginx/ssl/certs/trento.crt
    ```
5.  Check the NGINX configuration:
    ``` programlisting
    nginx -t
    ```
    If the configuration is correct, the output should be as follows:
    ``` programlisting
    nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
    nginx: configuration file /etc/nginx/nginx.conf test is successful
    ```
    If there are issues with the configuration, the output indicates
    what needs to be adjusted.
6.  Enable NGINX:
    ``` programlisting
    systemctl restart nginx
    ```
##### [[4.1.2.6.2 ][Create a signed certificate with Let's Encrypt using PackageHub repository]] [\#](id-installation.html#option-2-using-lets-encrypt-for-a-signed-certificate-using-packagehub-repository "Permalink") 
[ ]
1.  Enable the PackageHub repository (replace `x.x` with your
    OS version, for example `15.7`):
    ``` programlisting
    SUSEConnect --product PackageHub/x.x/x86_64
    zypper refresh
    ```
2.  Install Certbot and its NGINX plugin:
    ![Note](static/images/icon-note.svg "Note")
    Note
    Service Packs include version-specific Certbot NGINX plugin
    packages, for example `python311-certbot-nginx`,
    `python313-certbot-nginx` or
    `python3-certbot-nginx`. Install the package available in
    the Service Pack you currently use.
    ``` programlisting
    zypper install certbot python311-certbot-nginx
    ```
3.  Obtain a certificate and configure NGINX with Certbot:
    ![Note](static/images/icon-note.svg "Note")
    Note
    Replace `example.com` with your domain. For more
    information, refer to [Certbot instructions for
    NGINX](https://certbot.eff.org/instructions?ws=nginx&os=leap)
    ``` programlisting
    certbot --nginx -d trento.example.com
    ```
    ![Note](static/images/icon-note.svg "Note")
    Note
    Certbot certificates are valid for 90 days. Refer to the above link
    for details on how to renew certificates.
#### [[4.1.2.7 ][Accessing the trento-web UI]] [\#](id-installation.html#id-accessing-the-trento-web-ui "Permalink") 
[ ]
Pin the browser to `https://trento.example.com`. You should be
able to login using the credentials specified in the
`ADMIN_USER` and `ADMIN_PASSWORD` environment
variables.
### [[4.1.3 ][Automated deployment with Ansible]] [\#](id-installation.html#sec-ansible-deployment "Permalink") 
[ ]
An automated installation of Trento Server using RPM packages can be
performed with a Ansible playbook. For further information, refer to the
[Trento Ansible
project](https://github.com/trento-project/ansible).
## [[4.2 ][Installing Trento Agents]] [\#](id-installation.html#sec-trento-installing-trentoagent "Permalink") 
[ ]
Before you can install a Trento Agent, you must obtain the API key of
your Trento Server. Proceed as follows:
1.  Open the URL of the Trento Web console. It prompts you for a user
    name and password:
    [![trento-web-login](images/trento-web-login.png "trento-web-login")](images/trento-web-login.png)
2.  Enter the credentials for the `admin` user (specified
    during installation of Trento Server).
3.  Click [**Login**].
4.  When you are logged in, go to [**Settings**]:
    [![trento-settings-apikey](images/trento-settings-apikey.png "trento-settings-apikey")](images/trento-settings-apikey.png)
5.  Click the [**Copy**] button to copy the key to the
    clipboard.
Install the Trento Agent on an SAP host and register it with the Trento
Server as follows:
1.  Install the package:
    ``` programlisting
    > sudo zypper ref
    > sudo zypper install trento-agent
    ```
    A configuration file named `/agent.yaml` is created under
    `/etc/trento/` in SUSE Linux Enterprise Server for SAP
    applications 15 or under `/usr/etc/trento/` in SUSE Linux
    Enterprise Server for SAP applications 16.
2.  Open the configuration file and uncomment (remove the `#`
    character) the entries for `facts-service-url`,
    `server-url` and `api-key`. Update the values if
    necessary:
    - `facts-service-url`: the address of the AMQP RabbitMQ
      service used for communication with the checks engine (wanda). The
      correct value of this parameter depends on how Trento Server was
      deployed.
      In a Kubernetes deployment, it is
      amqp://trento:trento@TRENTO_SERVER_HOSTNAME:5672/. If the default
      RabbitMQ username and password (`trento:trento`) were
      updated using Helm, the parameter must use a user-defined value.
      In a systemd deployment, the correct value is
      `amqp://TRENTO_USER:TRENTO_USER_PASSWORD@TRENTO_SERVER_HOSTNAME:5672/vhost`.
      If `TRENTO_USER` and `TRENTO_USER_PASSWORD`
      have been replaced with custom values, you must use them.
    - `server-url`: URL for the Trento Server
      ([http://TRENTO_SERVER_HOSTNAME](http://TRENTO_SERVER_HOSTNAME))
    - `api-key`: the API key retrieved from the Web console
    - `node-exporter-target`: specifies IP address and port
      for node exporter as `<ip_address>:<port>`. In
      situations where the host has multiple IP addresses and/or the
      exporter is listening to a port different from the default one,
      configuring this settings enables Prometheus to connect to the
      correct IP address and port of the host.
3.  If SSL termination has been enabled on the server side, you can
    encrypt the communication from the agent to the server as follows:
    a.  Provide an HTTPS URL instead of an HTTP one.
    b.  Import the certificate from the Certificate Authority that has
        issued your Trento Server SSL certificate into the Trento Agent
        host as follows:
        i.  Copy the CA certificate in the PEM format to
            `/etc/pki/trust/anchors/`. If the CA certificate
            is in the CRT format, convert it to PEM using the following
            `openssl` command:
            ``` programlisting
            openssl x509 -in mycert.crt -out mycert.pem -outform PEM
            ```
        ii. Run the `update-ca-certificates` command.
4.  Start the Trento Agent:
    ``` programlisting
    > sudo systemctl enable --now trento-agent
    ```
5.  Check the status of the Trento Agent:
    ``` programlisting
    > sudo systemctl status trento-agent
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
6.  Repeat this procedure on all SAP hosts that you want to monitor.
[[Previous][[Chapter 3
]Requirements]](sec-trento-requirements.html)
[[Next][[Chapter 5
]Update]](id-update.html)
On this page
- [[[4.1 ][Installing Trento
  Server]](id-installation.html#sec-trento-installing-trentoserver)]
- [[[4.2 ][Installing Trento
  Agents]](id-installation.html#sec-trento-installing-trentoagent)]
Share this page
- [](id-installation.html# "E-Mail")
- [](id-installation.html# "Print this page")
