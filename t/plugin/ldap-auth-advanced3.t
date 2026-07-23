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
use t::APISIX 'no_plan';

repeat_each(1);
no_long_string();
no_root_location();
no_shuffle();
add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->request) {
        $block->set_value("request", "GET /t");
    }
});

run_tests();


__DATA__

=== TEST 1: cache_ttl below 0 is rejected (schema minimum 0)
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                cache_ttl = -1,
            })
            ngx.say(ok and "passed" or "rejected")
        }
    }
--- response_body
rejected



=== TEST 2: cache_ttl defaults to 60
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local conf = {
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
            }
            local ok, err = plugin.check_schema(conf)
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say(conf.cache_ttl)
        }
    }
--- response_body
60



=== TEST 3: create the throwaway cacheuser (uid=cacheuser / cachepass)
--- config
    location /t {
        content_by_lua_block {
            -- Throwaway user for the password-rotation tests, so the fixture
            -- users are never perturbed; the teardown block removes it again.
            require("lib.ldap_cacheuser").create_cacheuser()
            ngx.say("created")
        }
    }
--- response_body
created



=== TEST 4: set up the cache routes (ttl0 / default / short / a / b)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            -- Identical routes differing only in cache_ttl and route identity;
            -- every uri maps to a real test-upstream handler (200 vs 401).
            local routes = {
                { id = 1,  uri = "/hello",         ttl = 0 },
                { id = 2,  uri = "/uri",           ttl = 60 },
                { id = 3,  uri = "/hello1",        ttl = 1 },
                { id = 10, uri = "/server_port",   ttl = 60 },
                { id = 11, uri = "/hello_chunked", ttl = 60 },
            }
            for _, r in ipairs(routes) do
                local code = t('/apisix/admin/routes/' .. r.id, ngx.HTTP_PUT,
                    [[{
                        "plugins": { "ldap-auth-advanced": {
                            "ldap_uri": "127.0.0.1:1389",
                            "base_dn": "ou=users,dc=example,dc=org",
                            "attribute": "uid",
                            "consumer_required": false,
                            "cache_ttl": ]] .. r.ttl .. [[
                        } },
                        "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                        "uri": "]] .. r.uri .. [["
                    }]])
                if code >= 300 then
                    ngx.status = code
                    ngx.say("route ", r.id, " failed")
                    return
                end
            end
            ngx.say("passed")
        }
    }
--- response_body
passed



=== TEST 5: cache_ttl=0 -> directory hit every request; a rotated password fails immediately (401)
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.ldap_cacheuser")
            local port = ngx.var.server_port
            h.wait_route(port, "/hello")
            h.set_pw("cachepass")
            local primed = h.req(port, "/hello", "cachepass")  -- fresh bind -> 200
            h.set_pw("newpass")                                -- rotate in the directory
            local after = h.req(port, "/hello", "cachepass")   -- fresh bind of the OLD pw -> 401
            h.set_pw("cachepass")                              -- restore
            ngx.say("primed: ", primed)
            ngx.say("after_rotation: ", after)
        }
    }
--- response_body
primed: 200
after_rotation: 401



=== TEST 6: default cache_ttl serves a stale hit -- a rotated password still 200 within the TTL
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.ldap_cacheuser")
            local port = ngx.var.server_port
            h.wait_route(port, "/uri")
            h.set_pw("cachepass")
            local primed = h.req(port, "/uri", "cachepass")  -- miss -> resolve -> 200, cached
            h.set_pw("newpass")                              -- rotate in the directory
            local after = h.req(port, "/uri", "cachepass")   -- cache HIT -> still 200 (stale)
            h.set_pw("cachepass")                            -- restore
            ngx.say("primed: ", primed)
            ngx.say("after_rotation: ", after)
        }
    }
--- response_body
primed: 200
after_rotation: 200



=== TEST 7: a short cache_ttl expires -- the stale hit stops serving after the TTL
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.ldap_cacheuser")
            local port = ngx.var.server_port
            h.wait_route(port, "/hello1")
            h.set_pw("cachepass")
            local primed = h.req(port, "/hello1", "cachepass")   -- miss -> 200, cached with ttl=1
            h.set_pw("newpass")                                  -- rotate in the directory
            local within = h.req(port, "/hello1", "cachepass")   -- within 1s: HIT -> 200 (stale)
            ngx.sleep(2)                                         -- let the entry (ttl=1) expire
            local expired = h.req(port, "/hello1", "cachepass")  -- expired -> fresh bind OLD pw -> 401
            h.set_pw("cachepass")                                -- restore
            ngx.say("primed: ", primed)
            ngx.say("within_ttl: ", within)
            ngx.say("after_expiry: ", expired)
        }
    }
--- timeout: 10
--- response_body
primed: 200
within_ttl: 200
after_expiry: 401



=== TEST 8: two routes cache the same credential independently -- one route's cache never serves the other
--- config
    location /t {
        content_by_lua_block {
            local h = require("lib.ldap_cacheuser")
            local port = ngx.var.server_port
            h.wait_route(port, "/server_port")
            h.wait_route(port, "/hello_chunked")
            h.set_pw("cachepass")
            -- route A: miss -> 200, caches under A's key
            local a_primed = h.req(port, "/server_port", "cachepass")
            h.set_pw("newpass")               -- rotate in the directory
            -- route B has its own cache key -> miss -> fresh bind OLD pw -> 401
            local b_independent = h.req(port, "/hello_chunked", "cachepass")
            -- route A still holds its own entry -> HIT -> 200
            local a_still_hit = h.req(port, "/server_port", "cachepass")
            h.set_pw("cachepass")             -- restore
            ngx.say("a_primed: ", a_primed)
            ngx.say("b_independent: ", b_independent)
            ngx.say("a_still_hit: ", a_still_hit)
        }
    }
--- response_body
a_primed: 200
b_independent: 401
a_still_hit: 200



=== TEST 9: a config-version change is a cache MISS -- plugin_ctx_id embeds conf_version (creds: cacheuser:cachepass)
--- config
    location /t {
        content_by_lua_block {
            -- Direct rewrite() calls with hand-built ctxs: a conf_version bump
            -- must change the cache key (and avoids any route-reload race).
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local set_pw = require("lib.ldap_cacheuser").set_pw
            local conf = {
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                attribute = "uid",
                consumer_required = false,
            }
            assert(plugin.check_schema(conf))     -- populate defaults (cache_ttl=60)
            local function rw(ver)
                local ctx = { conf_type = "route", conf_id = "cachecfg",
                              conf_version = ver, var = {} }
                return plugin.rewrite(conf, ctx)  -- nil on success, 401 on auth fail
            end
            set_pw("cachepass")
            local primed = rw(1)                  -- miss -> resolve -> caches under version 1
            set_pw("newpass")                     -- rotate in the directory
            local same_version = rw(1)            -- same key -> HIT -> success (stale)
            local new_version = rw(2)             -- conf_version bumped -> MISS -> bind OLD pw -> 401
            set_pw("cachepass")                   -- restore
            ngx.say("primed: ", primed == nil and "ok" or tostring(primed))
            ngx.say("same_version: ", same_version == nil and "ok" or tostring(same_version))
            ngx.say("new_version: ", tostring(new_version))
        }
    }
--- more_headers
Authorization: ldap Y2FjaGV1c2VyOmNhY2hlcGFzcw==
--- response_body
primed: ok
same_version: ok
new_version: 401



=== TEST 10: teardown -- delete the throwaway cacheuser (restore fixture state)
--- config
    location /t {
        content_by_lua_block {
            require("lib.ldap_cacheuser").delete_cacheuser()
            ngx.say("cleaned")
        }
    }
--- response_body
cleaned



=== TEST 11: reset to a clean Consumer set + create the anonymous Consumer, set the anonymous route
--- config
    location /t {
        content_by_lua_block {
            local core = require("apisix.core")
            local t = require("lib.test_admin").test
            -- drop all plugin Consumers so a valid user maps to NO Consumer
            for _, name in ipairs({ "ldapadvgrpadmins", "ldapadvgrpsuper",
                                    "ldapadvuser01dn", "ldapadvjdoedn" }) do
                t('/apisix/admin/consumers/' .. name, ngx.HTTP_DELETE)
            end
            -- the anonymous Consumer carries no plugin config, so it can never
            -- be a match target
            local code, body = t('/apisix/admin/consumers', ngx.HTTP_PUT,
                core.json.encode({ username = "ldapadvanon" }))
            if code >= 300 then
                ngx.status = code
                ngx.say(body)
                return
            end
            code, body = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "anonymous_consumer": "ldapadvanon"
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/uri"
            }]])
            if code >= 300 then ngx.status = code end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 12: valid user, NO matching Consumer -> attaches anonymous, reaches upstream, NO X-Authenticated-Groups (creds: user01:password1)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
X-Authenticated-Groups: injected
--- error_code: 200
--- response_body_like eval
qr/x-consumer-username: ldapadvanon/
--- response_body_unlike eval
qr/x-authenticated-groups|injected/



=== TEST 13: invalid credentials (wrong password) -> anonymous fallback still reaches upstream (creds: user01:wrong)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOndyb25n
--- error_code: 200
--- response_body_like eval
qr/x-consumer-username: ldapadvanon/
--- response_body_unlike eval
qr/x-authenticated-groups/



=== TEST 14: no credential header at all -> anonymous fallback, reaches upstream
--- request
GET /uri
--- error_code: 200
--- response_body_like eval
qr/x-consumer-username: ldapadvanon/



=== TEST 15: point the anonymous route at a dead LDAP port (transport-error case)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1390",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "timeout": 1000,
                    "consumer_required": false,
                    "anonymous_consumer": "ldapadvanon"
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/uri"
            }]])
            if code >= 300 then ngx.status = code end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 16: LDAP unreachable + anonymous_consumer -> 500, NEVER anonymous (creds: user01:password1)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
X-Authenticated-Groups: injected
--- error_code: 500
--- response_headers
X-Authenticated-Groups:
--- response_body_unlike eval
qr/x-consumer-username/
--- error_log
LDAP connect failed



=== TEST 17: groups_required route with anonymous_consumer set (403 case)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [=[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "consumer_required": false,
                    "groups_required": [["superadmin"]],
                    "anonymous_consumer": "ldapadvanon"
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/uri"
            }]=])
            if code >= 300 then ngx.status = code end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 18: user01 (not in superadmin) fails groups_required + anonymous_consumer -> 403, NEVER anonymous (creds: user01:password1)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
X-Authenticated-Groups: injected
--- error_code: 403
--- response_body
{"message":"Forbidden"}
--- response_headers
X-Authenticated-Groups:
--- response_body_unlike eval
qr/x-consumer-username/
--- grep_error_log eval
qr/groups_required not satisfied/
--- grep_error_log_out
groups_required not satisfied



=== TEST 19: set up the hide_credentials success route (consumer_required=false, /uri echoes request headers)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "consumer_required": false,
                    "hide_credentials": true
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/uri"
            }]])
            if code >= 300 then ngx.status = code end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 20: hide_credentials strips the Authorization header the upstream sees (success path, header_type ldap) (creds: user01:password1)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body_unlike eval
qr/authorization:/



=== TEST 21: with BOTH headers present, Proxy-Authorization is used -> hide strips ONLY it; Authorization is untouched (creds: user01:password1)
--- request
GET /uri
--- more_headers
Proxy-Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body_like eval
qr/\nauthorization: ldap /
--- response_body_unlike eval
qr/proxy-authorization/



=== TEST 22: set up a hide_credentials + anonymous_consumer route (strip on the anonymous path too)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "anonymous_consumer": "ldapadvanon",
                    "hide_credentials": true
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/uri"
            }]])
            if code >= 300 then ngx.status = code end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 23: on the anonymous path hide_credentials strips the used header; upstream sees anonymous, no credential (creds: user01:password1)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body_like eval
qr/x-consumer-username: ldapadvanon/
--- response_body_unlike eval
qr/authorization:/



=== TEST 24: set up the ldap_debug=false route (default; consumer_required=false so the memberOf groups collect)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "consumer_required": false
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/uri"
            }]])
            if code >= 300 then ngx.status = code end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 25: ldap_debug default (false) -> the group-name log is NOT emitted (creds: user01:password1)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- no_error_log
ldap-auth-advanced: groups:



=== TEST 26: set up the ldap_debug=true route
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "consumer_required": false,
                    "ldap_debug": true
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/uri"
            }]])
            if code >= 300 then ngx.status = code end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 27: ldap_debug=true -> the group names ARE logged, still with NO password (creds: user01:password1)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- error_log
ldap-auth-advanced: groups:
--- no_error_log
password1



=== TEST 28: set up an anonymous_consumer route with cache_ttl > 0 (scaffold: an absorbed auth failure must not poison the cache)
--- config
    location /t {
        content_by_lua_block {
            local core = require("apisix.core")
            local t = require("lib.test_admin").test
            -- Ensure the anonymous Consumer exists (idempotent PUT).
            local code, body = t('/apisix/admin/consumers', ngx.HTTP_PUT,
                core.json.encode({ username = "ldapadvanon" }))
            if code >= 300 then
                ngx.status = code
                ngx.say(body)
                return
            end
            -- anonymous_consumer + cache_ttl>0: an absorbed auth failure must
            -- never be cached under the wrong-password key.
            code, body = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "anonymous_consumer": "ldapadvanon",
                    "cache_ttl": 60
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/uri"
            }]])
            if code >= 300 then ngx.status = code end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 29: wrong password TWICE (anonymous_consumer + cache_ttl>0) both fall back to anonymous, never a poisoned nil-user_dn cache hit -> 500
--- config
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local port = ngx.var.server_port
            local function req()
                local hc = http.new()
                local res = hc:request_uri("http://127.0.0.1:" .. port .. "/uri",
                    { headers = { ["Authorization"] =
                        "ldap " .. ngx.encode_base64("user01:wrongpass") } })
                if not res then return "ERR" end
                local anon = res.body
                    and res.body:find("x-consumer-username: ldapadvanon", 1, true)
                return res.status .. (anon and " anon" or " noanon")
            end
            -- first wrong-password request: absorbed by the anonymous fallback,
            -- nothing cached
            local first = req()
            -- second identical request: a poisoned {user_dn=nil} hit would 500;
            -- it must fall back to anonymous again
            local second = req()
            ngx.say("first: ", first)
            ngx.say("second: ", second)
        }
    }
--- response_body
first: 200 anon
second: 200 anon
