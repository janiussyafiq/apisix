---
title: ldap-auth-advanced
keywords:
  - Apache APISIX
  - API 网关
  - Plugin
  - LDAP Authentication
  - ldap-auth-advanced
description: 本篇文档介绍了 Apache APISIX ldap-auth-advanced 插件的相关信息。
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

## 描述

`ldap-auth-advanced` 插件使用**先搜索后绑定**（search-then-bind）的流程为路由或服务添加 LDAP
身份认证。在每个请求中，插件会先绑定到目录（以配置的服务账号身份或匿名身份），根据你指定的属性
搜索用户条目，然后以该条目的身份携带用户提供的密码重新绑定，以校验凭据。由于登录名是通过搜索
解析的，而不是直接拼接为 DN，因此该插件支持登录标识与条目 RDN 不一致的目录——最典型的是
Active Directory 的 `sAMAccountName` 形式（登录属性为 `uid`/`sAMAccountName`，RDN 为 `cn`）。

除身份认证外，该插件还可以：

- **关联 [Consumer](../terminology/consumer.md)**：通过匹配解析出的用户 DN（`user_dn`）或用户
  所属的某个组 DN（`group_dn`）来关联 Consumer，从而使基于 Consumer 的下游插件（限流、ACL）
  能够区分调用方。Consumer 关联是可选的（`consumer_required`）。
- **获取用户的 LDAP 用户组**：既可以从用户条目上的成员属性获取
  （`user_membership_attribute`，例如 `memberOf`），也可以通过搜索用户组子树获取
  （`group_base_dn`）。
- **基于用户组授权**：使用 `groups_required`，按获取到的用户组**名称**进行匹配。

该插件使用 [lua-resty-ldap](https://github.com/api7/lua-resty-ldap) 连接 LDAP 服务器。它与
`ldap-auth` 插件不同：`ldap-auth` 直接以固定的 Consumer DN 绑定，不执行搜索、用户组获取或
基于用户组的授权。

## 属性

以下属性配置在路由或服务上。

### 连接

| 名称 | 类型 | 必选项 | 默认值 | 有效值 | 描述 |
|------|------|--------|--------|--------|------|
| ldap_uri | string | 是 | | | LDAP 服务器地址，格式为 `host[:port]`。当省略端口时，若启用了 `use_ldaps` 则默认为 `636`，否则为 `389`。 |
| use_ldaps | boolean | 否 | false | | 如果设置为 `true`，则通过 LDAPS（`ldaps://`）连接。与 `use_starttls` 互斥，同时设置两者会导致配置校验错误。 |
| use_starttls | boolean | 否 | false | | 如果设置为 `true`，则使用 StartTLS 将明文连接升级为 TLS。与 `use_ldaps` 互斥，同时设置两者会导致配置校验错误。 |
| ssl_verify | boolean | 否 | true | | 使用 TLS 时是否校验服务器证书。如果设置为 `true`，你必须在 `config.yaml` 中设置 `ssl_trusted_certificate`，并确保 `ldap_uri` 中的 host 与服务器证书中的 host 匹配。 |
| timeout | integer | 否 | 3000 | [1, 60000] | LDAP 操作的套接字超时时间，单位为毫秒。 |

### 连接池

| 名称 | 类型 | 必选项 | 默认值 | 有效值 | 描述 |
|------|------|--------|--------|--------|------|
| keepalive | boolean | 否 | true | | 是否复用到 LDAP 服务器的连接池连接。 |
| keepalive_timeout | integer | 否 | 60000 | >= 1000 | 连接池中连接被关闭前的空闲时间，单位为毫秒。 |
| keepalive_pool_size | integer | 否 | 5 | >= 1 | 连接池中的最大连接数。 |
| keepalive_pool_name | string | 否 | | | 连接池名称。具有相同池名称的连接会被共享。 |

### 用户解析（先搜索后绑定）

| 名称 | 类型 | 必选项 | 默认值 | 有效值 | 描述 |
|------|------|--------|--------|--------|------|
| base_dn | string | 是 | | | 执行用户搜索的基准 DN（子树范围）。例如：`ou=users,dc=example,dc=org`。 |
| attribute | string | 否 | cn | `^[A-Za-z][A-Za-z0-9;-]*$` | 用于构造用户搜索过滤器 `(<attribute>=<username>)` 的属性。对于 Active Directory 登录形式，请设置为 `uid`（或 `sAMAccountName`）。 |
| bind_dn | string | 否 | | | 执行用户搜索前用于绑定的服务账号 DN。如果省略，插件将执行匿名搜索绑定。 |
| ldap_password | string | 否 | | | `bind_dn` 对应的密码。当设置了 `bind_dn` 时必填。该字段在存储前会使用 AES 加密，也可以通过环境变量（`env://` 前缀）或诸如 HashiCorp Vault 之类的密钥管理器（`secret://` 前缀）引用。 |

### 搜索限制

| 名称 | 类型 | 必选项 | 默认值 | 有效值 | 描述 |
|------|------|--------|--------|--------|------|
| size_limit | integer | 否 | 2 | >= 2 | **用户**搜索最多可返回的条目数。下限 `2` 使插件能够检测到不唯一（多于一个）的匹配并拒绝请求。用户组的获取不受该值限制。 |
| time_limit | integer | 否 | 5 | >= 0 | 搜索的服务器端时间限制，单位为秒。`0` 表示使用服务器默认值。 |

### 用户组

| 名称 | 类型 | 必选项 | 默认值 | 有效值 | 描述 |
|------|------|--------|--------|--------|------|
| group_base_dn | string | 否 | | | 搜索用户所属用户组的基准 DN（子树范围）。如果设置，则通过搜索 `(<group_member_attribute>=<user_dn>)` 收集用户组。如果省略，则从用户条目的 `user_membership_attribute` 读取用户组。 |
| group_name_attribute | string | 否 | cn | `^[A-Za-z][A-Za-z0-9;-]*$` | 保存用户组名称的属性；获取到的名称即 `groups_required` 匹配的对象。 |
| group_member_attribute | string | 否 | member | `^[A-Za-z][A-Za-z0-9;-]*$` | 用户组条目上列出其成员的属性。当设置了 `group_base_dn` 时，会用解析出的用户 DN 与该属性匹配。 |
| user_membership_attribute | string | 否 | memberOf | `^[A-Za-z][A-Za-z0-9;-]*$` | 用户条目上列出其所属用户组的属性，在未设置 `group_base_dn` 时使用。 |

### 授权

| 名称 | 类型 | 必选项 | 默认值 | 有效值 | 描述 |
|------|------|--------|--------|--------|------|
| groups_required | array[array[string]] | 否 | | 外层 `minItems` 1，内层 `minItems` 1 | 基于用户组的授权规则，按用户组**名称**匹配。外层数组是各子句之间的逻辑**或（OR）**；每个内层数组是若干用户组名称之间的逻辑**与（AND）**。名称按原样逐字比较（不做大小写转换，不做分词）。如果没有任何子句被满足，请求将返回 `403`。 |

### Consumer

| 名称 | 类型 | 必选项 | 默认值 | 有效值 | 描述 |
|------|------|--------|--------|--------|------|
| consumer_required | boolean | 否 | true | | 如果设置为 `true`，认证后必须找到匹配的 Consumer（通过 `user_dn` 或 `group_dn`），否则请求失败。如果设置为 `false`，请求在通过认证后不关联任何 Consumer。 |
| anonymous_consumer | string | 否 | | | 用作认证失败回退的匿名 Consumer 名称。如果配置，认证失败的请求将作为该 Consumer 处理，而不是返回 `401`。 |

### 请求处理

| 名称 | 类型 | 必选项 | 默认值 | 有效值 | 描述 |
|------|------|--------|--------|--------|------|
| header_type | string | 否 | ldap | ["ldap", "basic"] | 认证失败返回 `401` 时，写入 `WWW-Authenticate` 响应头中的认证方案。 |
| hide_credentials | boolean | 否 | false | | 如果设置为 `true`，则不将携带凭据的请求头（实际使用的 `Proxy-Authorization` 或 `Authorization` 头）传递给上游服务。 |
| realm | string | 否 | ldap | | 认证失败返回 `401 Unauthorized` 响应时，包含在 `WWW-Authenticate` 响应头中的域（realm）。 |

### 可观测性

| 名称 | 类型 | 必选项 | 默认值 | 有效值 | 描述 |
|------|------|--------|--------|--------|------|
| cache_ttl | integer | 否 | 60 | >= 0 | 缓存用户解析结果（用户 DN 与用户组）的存活时间，单位为秒。`0` 表示禁用缓存，此时每个请求都会访问目录。参见[运维说明](#运维说明)。 |
| ldap_debug | boolean | 否 | false | | 如果设置为 `true`，则以 warning 级别记录 LDAP 搜索结果（条目 DN 与属性）以便排查问题。任何级别下都不会记录密码。 |

## Consumer 端属性

以下属性配置在 Consumer 上，供插件将已认证的请求与其关联。`user_dn` 与 `group_dn` 必须且只能
设置其中一个。

| 名称 | 类型 | 必选项 | 描述 |
|------|------|--------|------|
| user_dn | string | 条件必选 | 当解析出的用户 DN 与该值相等时匹配该请求。例如：`cn=user01,ou=users,dc=example,dc=org`。该字段支持使用 [APISIX Secret](../terminology/secret.md) 资源，将值保存在 Secret Manager 中。 |
| group_dn | string | 条件必选 | 当用户所属的某个用户组 DN 与该值相等时匹配该请求。该字段支持使用 [APISIX Secret](../terminology/secret.md) 资源，将值保存在 Secret Manager 中。 |

`user_dn` 匹配优先于 `group_dn` 匹配。

## 示例

以下示例演示了如何为不同场景配置 `ldap-auth-advanced`。

:::note

你可以这样从 `config.yaml` 中获取 `admin_key` 并存入环境变量：

```bash
admin_key=$(yq '.deployment.admin.admin_key[0].key' conf/config.yaml | sed 's/"//g')
```

:::

### Active Directory `sAMAccountName` 登录

以下示例通过在 `base_dn` 下按 `uid` 搜索来解析登录名，并在搜索前以服务账号（`bind_dn`）身份先
绑定。这是 Active Directory 的 `sAMAccountName` 形式，其登录属性与条目 RDN 不一致。

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

随后用户使用其 `uid` 属性中携带的登录名进行认证：

```shell
curl -i -u jdoe:janesecret http://127.0.0.1:9080/hello
```

若要将已认证用户与 Consumer 关联，请创建一个 `user_dn` 与解析出的条目匹配的 Consumer：

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

### 不关联 Consumer 的认证

将 `consumer_required` 设置为 `false`，即可在不关联 Consumer 的情况下对目录进行认证。当你只需
校验凭据、而不为每个用户维护 Consumer 时，这很有用。

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

由于没有关联任何 Consumer，基于 Consumer 的下游插件（例如 `limit-count` 或
`consumer-restriction`）将没有可用于区分的 Consumer。参见[运维说明](#运维说明)。

### 基于用户组授权

以下示例要求用户属于 `Domain Admins` 用户组，**或者**同时属于 `Developers` 和 `VPN Users`。
外层数组是各子句之间的逻辑或；每个内层数组是若干用户组名称之间的逻辑与。用户组通过搜索
`group_base_dn` 收集。

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

通过认证但不属于任何所需用户组的用户将收到 `403 Forbidden`。

### 回退到匿名 Consumer

以下示例让认证失败的请求作为匿名 Consumer `anonymous` 继续处理，而不是返回 `401`。请先创建
该匿名 Consumer（通常带有其自身的下游策略），然后通过 `anonymous_consumer` 引用它。

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

请注意，匿名回退仅适用于认证失败的情况。`groups_required` 未满足导致的拒绝（`403`）以及 LDAP
传输错误（`500`）都不会回退到匿名 Consumer。

## 运维说明

### 缓存与授权时效性

当 `cache_ttl > 0` 时，一次成功的 LDAP 解析（用户 DN 与获取到的用户组）会被缓存，缓存键为插件
配置标识加上凭据的哈希值。只有成功的结果会被缓存。

当命中缓存时，LDAP 解析结果直接从缓存返回——不会访问目录——但授权（`groups_required`）与
Consumer 决策会针对缓存中的用户组在**每个请求上重新评估**。因此，在目录中所做的撤销（密码变更
或用户组移除）最多在 `cache_ttl` 秒内生效，即缓存条目过期时。

`cache_ttl: 0` 会完全禁用缓存，此时每个请求都会访问目录，撤销立即生效。默认值为 `60` 秒。

### 状态码语义

| 条件 | 状态码 | 匿名回退 |
|------|--------|----------|
| 认证失败（凭据缺失/无效、空密码、用户不存在、匹配不唯一、绑定失败） | `401` | 是——如果设置了 `anonymous_consumer`，请求将改为作为该 Consumer 处理。 |
| 已认证，但在 `consumer_required` 为 `true` 时没有匹配的 Consumer（Consumer 关联失败，区别于凭据认证失败） | `401` | 是——该路径经由与认证失败相同的处理流程，因此已配置的 `anonymous_consumer` 同样适用。 |
| `groups_required` 未满足 | `403` | 否——`403` 永远不会回退到匿名 Consumer。 |
| LDAP 传输、TLS 或超时错误 | `500` | 否——传输错误永远不会回退到匿名 Consumer，也永远不会被报告为 `401`。 |

配置错误或无法解析的 `anonymous_consumer`（例如指向一个不存在的 Consumer）**不会**静默放行请求：插件会记录一条错误日志，请求降级为正常的 `401`。

### 空密码

空密码在尝试任何绑定之前都会被以 `401` 拒绝。这是有意为之：根据 RFC 4513 §5.1.2，使用 DN 加
零长度密码的简单绑定被视为*未认证*（unauthenticated）绑定，并在服务器端返回成功——否则任何
用户名可解析的调用方都会被认证通过。

### `consumer_required: false`

将 `consumer_required` 设置为 `false` 会在不关联 Consumer 的情况下对请求进行认证。此时，按
Consumer 区分调用方的下游插件——例如限流（`limit-count`）与 ACL（`consumer-restriction`）
插件——将没有可用于区分的 Consumer。当这些插件需要区分调用方时，请使用 Consumer 关联
（即默认行为）。

### `X-Authenticated-Groups` 请求头

仅在认证成功路径上，插件会在代理到上游之前将 `X-Authenticated-Groups` 请求头设置为用户所属
用户组名称的逗号分隔列表。任何客户端提供的 `X-Authenticated-Groups` 值在所有路径上都会被
剥离，因此上游永远不会看到被伪造的值。该请求头不会在 `401`、`403`、`500` 或匿名路径上发出。

由于该列表以逗号分隔，因此名称本身包含逗号的用户组在该请求头中会产生歧义。目录中使用带逗号
用户组名称的运维人员在下游解析该请求头时应考虑这一点。

## 删除插件

当你需要禁用 `ldap-auth-advanced` 插件时，可以通过以下命令删除相应的 JSON 配置。APISIX 将
自动重新加载，无需重启服务：

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
