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

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

Apache APISIX is a dynamic, real-time API gateway written in Lua/OpenResty. It routes HTTP and stream (TCP/UDP) traffic through a plugin-based pipeline, with configuration stored in etcd (hot-reloaded without restarts).

## Common Commands

```bash
make deps          # Install Lua dependencies via LuaRocks
make install-runtime  # Install OpenResty runtime
make init          # Initialize runtime environment and etcd config
make run           # Start APISIX server
make reload        # Reload after config changes (no restart)
make stop          # Gracefully stop the server
make verify        # Verify Nginx config syntax
make lint          # Run luacheck + lj-releng style checks
make test          # Run full test suite
```

### Running a Single Test

Tests use Perl's `prove` with the `Test::Nginx::Socket::Lua` framework:

```bash
# Run a single test file
prove -I../test-nginx/lib -I./ -r t/plugin/key-auth.t

# Run with verbose output
prove -I../test-nginx/lib -I./ -r t/admin/api.t --verbose
```

CI splits tests into parallel jobs matching these patterns: `t/plugin/[a-k]*.t`, `t/plugin/[l-z]*.t`, `t/admin t/cli t/core`, `t/node t/router`, `t/stream-*`.

## Architecture

### Request Lifecycle (HTTP)

```
Request → Route matching → Global rules → Plugin chain → Upstream selection → Proxy → Response filters → Log
```

Implemented in `apisix/init.lua`. The phases are: `rewrite`, `access`, `header_filter`, `body_filter`, `log`.

### Core Source Layout

- `apisix/init.lua` — HTTP request lifecycle, phase handlers
- `apisix/plugin.lua` — Plugin loader, executor, priority ordering, multi-language RPC
- `apisix/router.lua` — Route matching (radixtree backends)
- `apisix/upstream.lua` + `apisix/balancer.lua` — Upstream management, load balancing (round-robin, chash, EWMA, least-conn)
- `apisix/ssl.lua` — Dynamic TLS certificate handling
- `apisix/admin/` — REST Admin API route handlers
- `apisix/core/` — Shared utilities: config providers, logging, JSON, DNS, request/response helpers
- `apisix/plugins/` — 100+ built-in plugins
- `apisix/stream/` — TCP/UDP stream proxy
- `apisix/discovery/` — Service discovery integrations (Consul, Nacos, Eureka, K8s, DNS)
- `apisix/cli/` — CLI entry point (`bin/apisix` → `apisix/cli/apisix.lua`)

### Plugin System

Each plugin lives in `apisix/plugins/<name>.lua` and implements a subset of phase hooks (`rewrite`, `access`, `header_filter`, `body_filter`, `log`). Plugins declare a JSON Schema for their config and a numeric `priority` — higher priority runs first. The plugin loader in `apisix/plugin.lua` handles dynamic loading, schema validation, and multi-language dispatch (Lua, Go, Java, Python via RPC; also WASM).

### Configuration

- Runtime config: `conf/config.yaml` (copy from `conf/config.yaml.example`)
- Default config source: etcd (also supports YAML-only standalone mode via `apisix/core/config_yaml.lua`)
- Config changes in etcd are watched and applied without restarts

### Test Framework

Tests in `t/` are `.t` files using Test::Nginx DSL blocks:

- `--- request` / `--- response_headers` / `--- error_code` — HTTP assertions
- `--- yaml_config` — Override APISIX config for that test
- `--- error_log` / `--- no_error_log` — Log assertions
- `t/APISIX.pm` — Custom test harness that starts a real APISIX+Nginx for each test block

### CI Services

Integration tests require external services (etcd, Redis, Consul, Nacos, Postgres, MySQL, etc.). Docker Compose files are in `ci/pod/`. For local development, start the necessary services before running tests.

## Code Style

See `CODE_STYLE.md` for Lua conventions. Key points:

- 4-space indentation
- `local` variables always declared at narrowest scope
- `ngx.log` for logging (use appropriate log levels)
- Plugin config validated by JSON Schema before any runtime code runs

## When analyzing issues

Always read both the plugin file AND its test file.
Check if the issue mentions a phase — bugs often happen because logic is in the wrong phase.
Check the plugin's priority if ordering with other plugins is involved.

## Agent skills

### Issue tracker

GitHub issues on `janiussyafiq/apisix` (your fork), accessed via `gh`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
