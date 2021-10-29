Elasticsearch recheck role
--------------------------

The main goal of this role is to setup the Elasticsearch
and/or Kibana service base on Opensearch Elasticsearch distribution.
The current role definition is deploying Elasticsearch service and
configure tenants and users belong to tenants.
The current deployment is configuring users/tenant in `internal_users`
file, which is a "file database". In the future, the configuration would be
moved to Keycloack auth system.

Example
-------

Simply playbook for deploy a node with Elasticsearch and Kibana
on single machine:

```
- host: somehost
  become: true
  vars:
    tenant_configuration:
      sftests.com:
        logstash_input_port: 9998
        kibana_autologin: "basic"
    internal_users:
      - user: "admin"
        role: "admin"
        password: "admin"
      - user: "kibanaserver"
        role: "kibanauser"
        password: "kibanaserver"
    users:
      - user: "admin"
        role: "admin"
        password: "admin"
        tenant: "sftests.com"
      - user: "logstash"
        role: "logstash"
        password: "logstash"
        tenant: "sftests.com"
      - user: "curator"
        role: "curator"
        password: "curator"
        tenant: "sftests.com"
      - user: "kibana"
        role: "readonly"
        password: "kibana"
        tenant: "sftests.com"
      - user: "zuul"
        role: "admin"
        password: "zuul"
        tenant: "sftests.com"
  tasks:
    - name: Setup ELK stack
      include_role:
        name: ansible-role-elastic-recheck
        tasks_from: main.yml
```

Where in `vars` is including user definition, that looks like:

```
  vars:
    internal_users:
      - user: "admin"
        role: "admin"
        password: "<password>"
      - user: "kibanaserver"
        role: "kibanauser"
        password: "<password>"
    users:
      - user: "<user>"
        role: "<backend role>"
        password: "<user password>"
        tenant: "<tenant name | replace('.', '_') | replace('-', '_') >"
```

The `internal_users` is setup users that are used for internal services.
One most important user is `kibanaserver` user, that should be specified
when Kibana service is included. The `kibanaserver` user has specific
configuration and the user should not be changed.

The `users` dict is "mapped" in Ansible roles with convention:

```
<user>_<tenant | replace('.', '_') | replace('-', '_')>
```

For example, when user definition looks like:
```
    users:
      - {user: "admin", role: "admin", password: "admin", tenant: 'sftests.com'}
```
generated user would look like:
```
admin_sftests_com
```

The `backend roles` configuration you can find [here](https://opensearch.org/docs/security-plugin/access-control/index/)
and [here](https://opensearch.org/docs/security-plugin/access-control/users-roles/).

It has been done because each tenant will have own `admin` user,
`kibana` (readonly user) and others. The current setup is to avoid user name
conflicts in the `internal_users.yaml`. As it was mentioned, in the future
user would be migrated to the Keycloack auth system, which should give
more options for user configuration.

Available `roles`:
- admin
- readonly
- kibanauser (if the user is `kibanaserver`. More in `Software Factory integration` section)


Software Factory integration
----------------------------

The `Software Factory Project` can be configured to use `ansible-role-elastic-recheck`
role. To do that, on the beginning, you need to configure `users` that
later would be used by `sfconfig` tool.

The `sfconfig.yaml` file needs to have a dedicated parameter:

```
external_elasticsearch:
  host: https://elasticsearch-host-2:9200
  cacert_path: /etc/elasticsearch/certs/localCA.pem
  suffix: sftests_com
  users:
    curator_sftests_com:
      password: curator
      role:     curator
    logstash_sftests_com:
      password: logstash
      role: logstash
    kibana_sftests_com:
      password: kibana
      role: readonly

logstash:
  host: elasticsearch-host-2
  port: 9999

kibana:
  readonly_user_autologin: Basic
  host_url: http://elasticsearch-host-2:5601
```

Where:

* in external_elasticsearch:
- `host` - define Elasticsearch API url
- `cacert_path` - CA authority cert that would be verified by Logstash on start
- `suffix` - the tenant name; it would be used by Logstash to configure
             destination index pattern, where the metrics would be send
- `users` - user definition that was also configured on Elasticsearch host.
            NOTE: each user should have correct name, that include the
            tenant name. The `role` subkey is defining what type of users
            should be configured. Mostly it is used to setup correct user
            for `Logstash` service, but for example, if you would like to setup
            own `Kibana` service, you need to choose `kibanaserver` role
            for the user. So far, the `kibanaserver` user have very specific
            configuration and the `ansible-role-elastic-recheck` role is not
            configuring it.

* in logstash:
- `host` - the logstash host which will get metrics from e.g.: gearman worker.
- `port` - port on which logstash service will listen.

* in kibana:
- readonly_user_autologin - if `Basic` is set it means that there will created
                            a special location in Apache2 config, that will
                            inject authentication header, so user don't need
                            to fill login form.
                            Alternative options: `None`, `JWT`.
                            NOTE: this role is only supporting `Basic`
                            parameter.
- host_url - the Kibana service endpoint.

Before you run the `sfconfig` tool, remember to add the external elasticsearch
fqdn into the network - static_hostnames, for example:

```
network:
(...)
  static_hostnames:
  - "123.123.123.123 elasticsearch.sftests.com"
```

Then run the `sfconfig` tool.

## Configure Apache2 frontend with Letsencrypt

The role can enable SSL support for the frontend service like Apache2.
To configure that, set proper variables as in this example:

```
vars:
  setup_ssl: true
  ssl_cert_file: /etc/letsencrypt/live/elasticsearch.sftests.com/cert.pem
  ssl_key_file: /etc/letsencrypt/live/elasticsearch.sftests.com/privkey.pem
  ssl_chain_file: /etc/letsencrypt/live/elasticsearch.sftests.com/fullchain.pem
```


## Configure Letsencrypt certs with Opensearch and Opensearch-dashboards

Manual configuration has been described in one of the Opensearch [issue](https://github.com/opensearch-project/security/issues/52#issuecomment-937875037).
This role is configuring Opensearch to use Letsencrypt certs, but it is not
recommended.
If you would like to use it, set proper variables as in this example:

```
vars:
  # Configure Opensearch SSL
  opensearch_custom_ssl: true
  elastic_ssl_key_file: /etc/letsencrypt/live/elasticsearch.sftests.com/privkey.pem
  elastic_ssl_cert_file: /etc/letsencrypt/live/elasticsearch.sftests.com/fullchain.pem
  elastic_ssl_ca_url: https://letsencrypt.org/certs/lets-encrypt-r3.pem

  # Same variables are configuring Opensearch-dashboards SSL
  dashboards_custom_ssl: true
  elastic_ssl_key_file: /etc/letsencrypt/live/elasticsearch.sftests.com/privkey.pem
  elastic_ssl_cert_file: /etc/letsencrypt/live/elasticsearch.sftests.com/fullchain.pem
```
