---
title: ldap-auth-advanced
keywords:
  - Apache APISIX
  - API Gateway
  - Plugin
  - LDAP Authentication
  - ldap-auth-advanced
description: This document contains information about the Apache APISIX ldap-auth-advanced Plugin.
---

<!--
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
-->

## Description

The `ldap-auth-advanced` Plugin adds LDAP authentication to a Route or a Service using the
**search-then-bind** flow. On each request the Plugin binds to the directory (as a configured
service account or anonymously), searches for the user's entry by an attribute you choose, and
then re-binds as that entry with the supplied password to verify the credential. Because the
login name is resolved through a search rather than templated into a DN, the Plugin supports
directories where the login identifier differs from the entry's RDN — most notably the Active
Directory `sAMAccountName` shape (login attribute `uid`/`sAMAccountName`, RDN `cn`).

Beyond authentication, the Plugin can:

- **Associate a [Consumer](../terminology/consumer.md)** by matching the resolved user DN
  (`user_dn`) or one of the user's group DNs (`group_dn`), so downstream plugins that key on the
  Consumer (rate-limiting, ACL) can differentiate callers. Consumer association is optional
  (`consumer_required`).
- **Retrieve the user's LDAP groups**, either from a membership attribute on the user entry
  (`user_membership_attribute`, e.g. `memberOf`) or by searching a group subtree
  (`group_base_dn`).
- **Authorize by group** with `groups_required`, matched against the retrieved group **names**.

The Plugin uses [lua-resty-ldap](https://github.com/api7/lua-resty-ldap) for connecting with an
LDAP server. It is distinct from the `ldap-auth` Plugin, which binds a fixed Consumer DN directly
and does not perform a search, group retrieval, or group-based authorization.

## Attributes

The following attributes are configured on the Route or Service.

### Connection

| Name | Type | Required | Default | Valid values | Description |
|------|------|----------|---------|--------------|-------------|
| ldap_uri | string | True | | | Address of the LDAP server, in the `host[:port]` form. When the port is omitted it defaults to `636` if `use_ldaps` is enabled, otherwise `389`. |
| use_ldaps | boolean | False | false | | If true, connect over LDAPS (`ldaps://`). Mutually exclusive with `use_starttls`; setting both is a configuration error. |
| use_starttls | boolean | False | false | | If true, upgrade the plaintext connection to TLS with StartTLS. Mutually exclusive with `use_ldaps`; setting both is a configuration error. |
| ssl_verify | boolean | False | true | | Whether to verify the server certificate when TLS is used. If true, set `ssl_trusted_certificate` in `config.yaml` and make sure the host in `ldap_uri` matches the host in the server certificate. |
| timeout | integer | False | 3000 | [1, 60000] | Socket timeout for LDAP operations, in milliseconds. |

### Connection pool

| Name | Type | Required | Default | Valid values | Description |
|------|------|----------|---------|--------------|-------------|
| keepalive | boolean | False | true | | Whether to reuse pooled connections to the LDAP server. |
| keepalive_timeout | integer | False | 60000 | >= 1000 | Idle time before a pooled connection is closed, in milliseconds. |
| keepalive_pool_size | integer | False | 5 | >= 1 | Maximum number of connections in the pool. |
| keepalive_pool_name | string | False | | | Name of the connection pool. Connections with the same pool name are shared. |

### User resolution (search-then-bind)

| Name | Type | Required | Default | Valid values | Description |
|------|------|----------|---------|--------------|-------------|
| base_dn | string | True | | | Base DN under which the user search runs (subtree scope). For example, `ou=users,dc=example,dc=org`. |
| attribute | string | False | cn | `^[A-Za-z][A-Za-z0-9;-]*$` | Attribute used to build the user search filter `(<attribute>=<username>)`. Set to `uid` (or `sAMAccountName`) for the Active Directory login shape. |
| bind_dn | string | False | | | DN of the service account used to bind before the user search. If omitted, the Plugin performs an anonymous search bind. |
| ldap_password | string | False | | | Password for `bind_dn`. Required when `bind_dn` is set. This field is encrypted with AES before being stored, and can also be referenced from an environment variable (`env://` prefix) or a secret manager such as HashiCorp Vault (`secret://` prefix). |

### Search bounds

| Name | Type | Required | Default | Valid values | Description |
|------|------|----------|---------|--------------|-------------|
| size_limit | integer | False | 2 | >= 2 | Maximum number of entries the **user** search may return. The floor of `2` lets the Plugin detect an ambiguous (more than one) match and fail the request. Group collection is not bounded by this value. |
| time_limit | integer | False | 5 | >= 0 | Server-side time limit for the search, in seconds. `0` means the server default. |

### Groups

| Name | Type | Required | Default | Valid values | Description |
|------|------|----------|---------|--------------|-------------|
| group_base_dn | string | False | | | Base DN under which to search for the user's groups (subtree scope). If set, groups are collected by searching `(<group_member_attribute>=<user_dn>)`. If omitted, groups are read from `user_membership_attribute` on the user entry. |
| group_name_attribute | string | False | cn | `^[A-Za-z][A-Za-z0-9;-]*$` | Attribute holding the group's name; the retrieved names are what `groups_required` matches against. |
| group_member_attribute | string | False | member | `^[A-Za-z][A-Za-z0-9;-]*$` | Attribute on a group entry that lists its members, matched against the resolved user DN when `group_base_dn` is set. |
| user_membership_attribute | string | False | memberOf | `^[A-Za-z][A-Za-z0-9;-]*$` | Attribute on the user entry listing the groups it belongs to, used when `group_base_dn` is not set. |

### Authorization

| Name | Type | Required | Default | Valid values | Description |
|------|------|----------|---------|--------------|-------------|
| groups_required | array[array[string]] | False | | outer `minItems` 1, inner `minItems` 1 | Group-based authorization rule matched against the user's group **names**. The outer array is a logical **OR** of clauses; each inner array is a logical **AND** of group names. Names are compared verbatim (no case folding, no tokenisation). If none of the clauses is satisfied the request is rejected with `403`. |

### Consumer

| Name | Type | Required | Default | Valid values | Description |
|------|------|----------|---------|--------------|-------------|
| consumer_required | boolean | False | true | | If true, a matching Consumer must be found (by `user_dn` or `group_dn`) after authentication, otherwise the request fails. If false, the request is authenticated without attaching a Consumer. |
| anonymous_consumer | string | False | | | Name of an anonymous Consumer used as a fallback on authentication failure. If configured, requests that fail authentication are handled as this Consumer instead of being rejected with `401`. |

### Request handling

| Name | Type | Required | Default | Valid values | Description |
|------|------|----------|---------|--------------|-------------|
| header_type | string | False | ldap | ["ldap", "basic"] | Authentication scheme written in the `WWW-Authenticate` response header on a `401`. |
| hide_credentials | boolean | False | false | | If true, do not pass the credential header (the `Proxy-Authorization` or `Authorization` header that carried the credentials) to the Upstream service. |
| realm | string | False | ldap | | Realm included in the `WWW-Authenticate` response header returned with a `401 Unauthorized` response due to authentication failure. |

### Observability

| Name | Type | Required | Default | Valid values | Description |
|------|------|----------|---------|--------------|-------------|
| cache_ttl | integer | False | 60 | >= 0 | Time-to-live, in seconds, for a cached user resolution (user DN and groups). `0` disables the cache, so every request hits the directory. See [Operational notes](#operational-notes). |
| ldap_debug | boolean | False | false | | If true, log LDAP search results (entry DNs and attributes) at warning level for troubleshooting. Passwords are never logged, at any level. |

## Consumer-side attributes

The following attributes are configured on the Consumer, so the Plugin can associate an
authenticated request with it. Exactly one of `user_dn` or `group_dn` must be set.

| Name | Type | Required | Description |
|------|------|----------|-------------|
| user_dn | string | Conditional | Match the request when the resolved user DN equals this value. For example, `cn=user01,ou=users,dc=example,dc=org`. This field supports saving the value in Secret Manager using the [APISIX Secret](../terminology/secret.md) resource. |
| group_dn | string | Conditional | Match the request when one of the user's group DNs equals this value. This field supports saving the value in Secret Manager using the [APISIX Secret](../terminology/secret.md) resource. |

A `user_dn` match takes precedence over a `group_dn` match.

## Examples

The examples below demonstrate how to configure `ldap-auth-advanced` for different scenarios.

:::note

You can fetch the `admin_key` from `config.yaml` and save it to an environment variable with the
following command:

```bash
admin_key=$(yq '.deployment.admin.admin_key[0].key' conf/config.yaml | sed 's/"//g')
```

:::

### Active Directory `sAMAccountName` login

The following example resolves the login name through a `uid` search under `base_dn`, binding
first as a service account (`bind_dn`) before searching. This is the Active Directory
`sAMAccountName` shape, where the login attribute differs from the entry's RDN.

```shell
curl http://127.0.0.1:9180/apisix/admin/routes/1 -H "X-API-KEY: $admin_key" -X PUT -d '
{
    "uri": "/hello",
    "plugins": {
        "ldap-auth-advanced": {
            "ldap_uri": "127.0.0.1:1389",
            "base_dn": "ou=users,dc=example,dc=org",
            "attribute": "uid",
            "bind_dn": "cn=service,dc=example,dc=org",
            "ldap_password": "service-secret"
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "127.0.0.1:1980": 1
        }
    }
}'
```

A user then authenticates with the login name carried in the `uid` attribute:

```shell
curl -i -u jdoe:janesecret http://127.0.0.1:9080/hello
```

To associate the authenticated user with a Consumer, create a Consumer whose `user_dn` matches
the resolved entry:

```shell
curl http://127.0.0.1:9180/apisix/admin/consumers -H "X-API-KEY: $admin_key" -X PUT -d '
{
    "username": "jane",
    "plugins": {
        "ldap-auth-advanced": {
            "user_dn": "cn=Jane Doe,ou=users,dc=example,dc=org"
        }
    }
}'
```

### Authenticate without a Consumer

Set `consumer_required` to `false` to authenticate against the directory without attaching a
Consumer. This is useful when you only need to verify credentials and do not maintain a Consumer
per user.

```shell
curl http://127.0.0.1:9180/apisix/admin/routes/1 -H "X-API-KEY: $admin_key" -X PUT -d '
{
    "uri": "/hello",
    "plugins": {
        "ldap-auth-advanced": {
            "ldap_uri": "127.0.0.1:1389",
            "base_dn": "ou=users,dc=example,dc=org",
            "attribute": "uid",
            "consumer_required": false
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "127.0.0.1:1980": 1
        }
    }
}'
```

Because no Consumer is attached, downstream plugins that key on the Consumer (for example
`limit-count` or `consumer-restriction`) have no Consumer to key on. See
[Operational notes](#operational-notes).

### Authorize by group

The following example requires the user to belong either to the `Domain Admins` group, **or** to
both `Developers` and `VPN Users`. The outer array is a logical OR of clauses; each inner array
is a logical AND of group names. Groups are collected by searching `group_base_dn`.

```shell
curl http://127.0.0.1:9180/apisix/admin/routes/1 -H "X-API-KEY: $admin_key" -X PUT -d '
{
    "uri": "/hello",
    "plugins": {
        "ldap-auth-advanced": {
            "ldap_uri": "127.0.0.1:1389",
            "base_dn": "ou=users,dc=example,dc=org",
            "attribute": "uid",
            "bind_dn": "cn=service,dc=example,dc=org",
            "ldap_password": "service-secret",
            "group_base_dn": "ou=groups,dc=example,dc=org",
            "groups_required": [
                ["Domain Admins"],
                ["Developers", "VPN Users"]
            ]
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "127.0.0.1:1980": 1
        }
    }
}'
```

A user who authenticates but is in none of the required groups receives a `403 Forbidden`.

### Fall back to an anonymous Consumer

The following example lets requests that fail authentication proceed as the anonymous Consumer
`anonymous` rather than being rejected with `401`. First create the anonymous Consumer (typically
with its own downstream policies), then reference it with `anonymous_consumer`.

```shell
curl http://127.0.0.1:9180/apisix/admin/consumers -H "X-API-KEY: $admin_key" -X PUT -d '
{
    "username": "anonymous"
}'
```

```shell
curl http://127.0.0.1:9180/apisix/admin/routes/1 -H "X-API-KEY: $admin_key" -X PUT -d '
{
    "uri": "/hello",
    "plugins": {
        "ldap-auth-advanced": {
            "ldap_uri": "127.0.0.1:1389",
            "base_dn": "ou=users,dc=example,dc=org",
            "attribute": "uid",
            "anonymous_consumer": "anonymous"
        }
    },
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "127.0.0.1:1980": 1
        }
    }
}'
```

Note that the anonymous fallback applies only to authentication failures. A `groups_required`
rejection (`403`) and an LDAP transport error (`500`) never fall back to the anonymous Consumer.

## Operational notes

### Caching and authorization staleness

When `cache_ttl > 0`, a successful LDAP resolution (the user DN and the retrieved groups) is
cached, keyed by the plugin configuration identity plus a hash of the credential. Only successes
are cached.

On a cache **hit** the LDAP resolution is served from cache — the directory is not contacted — but
authorization (`groups_required`) and the Consumer decision are **re-evaluated on every request**
against the cached groups. Consequently a revocation made in the directory (a password change or a
group removal) takes effect within at most `cache_ttl` seconds, when the cached entry expires.

`cache_ttl: 0` disables the cache entirely, so every request hits the directory and revocations
take effect immediately. The default is `60` seconds.

### Status semantics

| Condition | Status | Anonymous fallback |
|-----------|--------|--------------------|
| Authentication failure (missing/invalid credentials, empty password, user not found, ambiguous match, bind failure) | `401` | Yes — if `anonymous_consumer` is set, the request is handled as that Consumer instead. |
| Authenticated, but no Consumer matches while `consumer_required` is `true` (a Consumer-association failure, distinct from a credential failure) | `401` | Yes — this path is routed through the same auth-failure handling, so a configured `anonymous_consumer` applies here too. |
| `groups_required` not satisfied | `403` | No — a `403` never falls back to the anonymous Consumer. |
| LDAP transport, TLS, or timeout error | `500` | No — a transport error never falls back to the anonymous Consumer and is never reported as `401`. |

A misconfigured or unresolvable `anonymous_consumer` (for example, one naming a Consumer that does not exist) does **not** silently allow the request through: the Plugin logs an error and the request degrades to the normal `401`.

### Empty password

An empty password is always rejected with `401` before any bind is attempted. This is deliberate:
per RFC 4513 §5.1.2 a simple bind with a DN and a zero-length password is treated as an
*unauthenticated* bind and returns success at the server, which would otherwise authenticate
anyone whose username resolves.

### `consumer_required: false`

Setting `consumer_required` to `false` authenticates the request without attaching a Consumer.
Downstream plugins that identify callers by their Consumer — such as rate-limiting (`limit-count`)
and ACL (`consumer-restriction`) plugins — then have no Consumer to key on. Use a Consumer
association (the default) when such plugins must distinguish callers.

### `X-Authenticated-Groups` header

On the authenticated-success path only, the Plugin sets the `X-Authenticated-Groups` request
header to a comma-separated list of the user's group names before proxying to the Upstream. Any
client-supplied `X-Authenticated-Groups` value is always stripped, on every path, so the Upstream
never sees a spoofed value. The header is not emitted on the `401`, `403`, `500`, or anonymous
paths.

Because the list is comma-separated, a group whose name itself contains a comma is ambiguous in
this header. Operators whose directories use comma-bearing group names should account for this
when parsing the header downstream.

## Delete Plugin

To remove the `ldap-auth-advanced` Plugin, delete the corresponding JSON configuration from the
Plugin configuration. APISIX will automatically reload and you do not have to restart for this to
take effect.

```shell
curl http://127.0.0.1:9180/apisix/admin/routes/1 -H "X-API-KEY: $admin_key" -X PUT -d '
{
    "uri": "/hello",
    "plugins": {},
    "upstream": {
        "type": "roundrobin",
        "nodes": {
            "127.0.0.1:1980": 1
        }
    }
}'
```
