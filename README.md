Elasticsearch recheck role
--------------------------

The main goal of this role is to setup the Elasticsearch
and/or Kibana service base on Opendistro for Elasticsearch distribution.
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
        role: "admin"
        password: "logstash"
        tenant: "sftests.com"
      - user: "curator"
        role: "admin"
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
        tenant: "<tenant name | replace('.', '_') >"
```

The `internal_users` is setup users that are used for internal services.
One most important user is `kibanaserver` user, that should be specified
when Kibana service is included. The `kibanaserver` user has specific
configuration and the user should not be changed.

The `users` dict is "mapped" in Ansible roles with convention:

```
<user>_<tenant | replace('.', '_')>
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

The `backend roles` configuration you can find [here](https://opendistro.github.io/for-elasticsearch-docs/docs/security/configuration/configuration/#backend-configuration)
and [here](https://opendistro.github.io/for-elasticsearch-docs/docs/security/access-control/users-roles/#rolesyml).

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
```

Where:
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

Before you run the `sfconfig` tool, remember to add the external elasticsearch
fqdn into the network - static_hostnames, for example:

```
network:
(...)
  static_hostnames:
  - "123.123.123.123 elasticsearch.sftests.com"
```

Then run the `sfconfig` tool.
