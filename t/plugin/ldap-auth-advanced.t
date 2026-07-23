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

=== TEST 1: minimal valid conf (ldap_uri + base_dn) passes
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
            })
            ngx.say(ok and "passed" or err)
        }
    }
--- response_body
passed



=== TEST 2: missing ldap_uri is rejected
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema({
                base_dn = "ou=users,dc=example,dc=org",
            })
            ngx.say(ok and "passed" or err)
        }
    }
--- response_body_like eval
qr/property "ldap_uri" is required/



=== TEST 3: missing base_dn is rejected
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
            })
            ngx.say(ok and "passed" or err)
        }
    }
--- response_body_like eval
qr/property "base_dn" is required/



=== TEST 4: use_ldaps and use_starttls are mutually exclusive
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                use_ldaps = true,
                use_starttls = true,
            })
            ngx.say(ok and "passed" or err)
        }
    }
--- response_body
use_ldaps and use_starttls are mutually exclusive



=== TEST 5: use_ldaps alone (port-less uri) passes
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema({
                ldap_uri = "ldap.example.org",
                base_dn = "ou=users,dc=example,dc=org",
                use_ldaps = true,
            })
            ngx.say(ok and "passed" or err)
        }
    }
--- response_body
passed



=== TEST 6: bind_dn set without ldap_password is rejected
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                bind_dn = "cn=amdin,dc=example,dc=org",
            })
            ngx.say(ok and "passed" or err)
        }
    }
--- response_body
ldap_password is required when bind_dn is set



=== TEST 7: bind_dn with ldap_password passes
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                bind_dn = "cn=amdin,dc=example,dc=org",
                ldap_password = "adminpassword",
            })
            ngx.say(ok and "passed" or err)
        }
    }
--- response_body
passed



=== TEST 8: attribute with a bad pattern is rejected
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                attribute = "1abc",
            })
            ngx.say(ok and "passed" or "rejected")
        }
    }
--- response_body
rejected



=== TEST 9: attribute containing a space is rejected
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                attribute = "a b",
            })
            ngx.say(ok and "passed" or "rejected")
        }
    }
--- response_body
rejected



=== TEST 10: valid attribute (uid) passes
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                attribute = "uid",
            })
            ngx.say(ok and "passed" or err)
        }
    }
--- response_body
passed



=== TEST 11: size_limit below the floor of 2 is rejected
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                size_limit = 1,
            })
            ngx.say(ok and "passed" or "rejected")
        }
    }
--- response_body
rejected



=== TEST 12: consumer schema with user_dn passes
--- config
    location /t {
        content_by_lua_block {
            local core = require("apisix.core")
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema(
                { user_dn = "cn=user01,ou=users,dc=example,dc=org" },
                core.schema.TYPE_CONSUMER)
            ngx.say(ok and "passed" or err)
        }
    }
--- response_body
passed



=== TEST 13: empty consumer schema is rejected
--- config
    location /t {
        content_by_lua_block {
            local core = require("apisix.core")
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema({}, core.schema.TYPE_CONSUMER)
            ngx.say(ok and "passed" or "rejected")
        }
    }
--- response_body
rejected



=== TEST 14: set up a route protected by ldap-auth-advanced (live LDAP)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1',
                ngx.HTTP_PUT,
                [[{
                    "plugins": {
                        "ldap-auth-advanced": {
                            "ldap_uri": "127.0.0.1:1389",
                            "base_dn": "ou=users,dc=example,dc=org",
                            "attribute": "uid"
                        }
                    },
                    "upstream": {
                        "nodes": {
                            "127.0.0.1:1980": 1
                        },
                        "type": "roundrobin"
                    },
                    "uri": "/hello"
                }]]
                )
            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 15: no credential header -> 401 with WWW-Authenticate ldap realm
--- request
GET /hello
--- error_code: 401
--- response_headers
WWW-Authenticate: ldap realm="ldap"



=== TEST 16: malformed base64 payload -> 401
--- request
GET /hello
--- more_headers
Authorization: ldap aca_a
--- error_code: 401



=== TEST 17: base64 payload without a ':' separator -> 401
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcm9ubHk=
--- error_code: 401



=== TEST 18: empty password rejected at step 1 (INV-1; RFC 4513 5.1.2 unauthenticated bind, directory permits bind_anon_dn)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAxOg==
--- error_code: 401
--- grep_error_log eval
qr/empty password/
--- grep_error_log_out
empty password



=== TEST 19: scheme word parsed case-insensitively (uppercase) and still hits INV-1
--- request
GET /hello
--- more_headers
Authorization: LDAP dXNlcjAxOg==
--- error_code: 401
--- grep_error_log eval
qr/empty password/
--- grep_error_log_out
empty password



=== TEST 20: scheme word parsed case-insensitively (mixed case) and still hits INV-1
--- request
GET /hello
--- more_headers
Authorization: lDaP dXNlcjAxOg==
--- error_code: 401
--- grep_error_log eval
qr/empty password/
--- grep_error_log_out
empty password



=== TEST 21: set up a route with header_type basic
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1',
                ngx.HTTP_PUT,
                [[{
                    "plugins": {
                        "ldap-auth-advanced": {
                            "ldap_uri": "127.0.0.1:1389",
                            "base_dn": "ou=users,dc=example,dc=org",
                            "attribute": "uid",
                            "header_type": "basic"
                        }
                    },
                    "upstream": {
                        "nodes": {
                            "127.0.0.1:1980": 1
                        },
                        "type": "roundrobin"
                    },
                    "uri": "/hello"
                }]]
                )
            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 22: header_type basic emits a Basic-scheme WWW-Authenticate
--- request
GET /hello
--- error_code: 401
--- response_headers
WWW-Authenticate: basic realm="ldap"



=== TEST 23: inbound X-Authenticated-Groups is cleared at step 1 on every path (INV-5 first half)
--- config
    location /t {
        content_by_lua_block {
            local core = require("apisix.core")
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ctx = { var = {} }
            local before = core.request.header(ctx, "X-Authenticated-Groups") or "nil"
            -- no credential header -> auth_failed path; the strip must still happen
            plugin.rewrite({ header_type = "ldap", realm = "ldap" }, ctx)
            local after = core.request.header(ctx, "X-Authenticated-Groups") or "nil"
            ngx.say("before: ", before)
            ngx.say("after: ", after)
        }
    }
--- more_headers
X-Authenticated-Groups: injected
--- response_body
before: injected
after: nil



=== TEST 24: set up a route with multi-auth wrapping ldap-auth-advanced and basic-auth
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1',
                ngx.HTTP_PUT,
                [[{
                    "plugins": {
                        "multi-auth": {
                            "auth_plugins": [
                                {
                                    "ldap-auth-advanced": {
                                        "ldap_uri": "127.0.0.1:1389",
                                        "base_dn": "ou=users,dc=example,dc=org",
                                        "attribute": "uid"
                                    }
                                },
                                {
                                    "basic-auth": {}
                                }
                            ]
                        }
                    },
                    "upstream": {
                        "nodes": {
                            "127.0.0.1:1980": 1
                        },
                        "type": "roundrobin"
                    },
                    "uri": "/hello"
                }]]
                )
            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 25: under multi-auth ldap-auth-advanced declines quietly (INV-9)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAxOg==
--- error_code: 401
--- response_body
{"message":"Authorization Failed"}
--- response_headers
WWW-Authenticate: Basic realm="basic"
--- no_error_log
empty password



=== TEST 26: set up the plain search-then-bind route (uid attribute)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1',
                ngx.HTTP_PUT,
                [[{
                    "plugins": {
                        "ldap-auth-advanced": {
                            "ldap_uri": "127.0.0.1:1389",
                            "base_dn": "ou=users,dc=example,dc=org",
                            "attribute": "uid",
                            "keepalive_pool_size": 4
                        }
                    },
                    "upstream": {
                        "nodes": {
                            "127.0.0.1:1980": 1
                        },
                        "type": "roundrobin"
                    },
                    "uri": "/hello"
                }]]
                )
            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 27: consumer_required (default true) with NO matching Consumer -> 401 (fails closed)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 401
--- grep_error_log eval
qr/no Consumer is configured/
--- grep_error_log_out
no Consumer is configured



=== TEST 28: create the ldap-auth-advanced Consumers (user_dn associations)
--- config
    location /t {
        content_by_lua_block {
            local core = require("apisix.core")
            local t = require("lib.test_admin").test
            local users = {
                { name = "ldapadvuser01", dn = "cn=user01,ou=users,dc=example,dc=org" },
                { name = "ldapadvuser02", dn = "cn=user02,ou=users,dc=example,dc=org" },
                { name = "ldapadvjdoe",   dn = "cn=Jane Doe,ou=users,dc=example,dc=org" },
                { name = "ldapadvsecret", dn = "cn=Secret User,ou=users,dc=example,dc=org" },
            }
            for _, u in ipairs(users) do
                local code, body = t('/apisix/admin/consumers',
                    ngx.HTTP_PUT,
                    core.json.encode({
                        username = u.name,
                        plugins = {
                            ["ldap-auth-advanced"] = { user_dn = u.dn },
                        },
                    }))
                if code >= 300 then
                    ngx.status = code
                    ngx.say(body)
                    return
                end
            end
            ngx.say("passed")
        }
    }
--- response_body
passed



=== TEST 29: happy path -- uid=user01 (cn=user01) matches Consumer ldapadvuser01 (200 + attached)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body
hello world
--- error_log
find consumer ldapadvuser01



=== TEST 30: AD-shape happy path -- uid=jdoe (cn=Jane Doe) matches Consumer ldapadvjdoe (200)
--- request
GET /hello
--- more_headers
Authorization: ldap amRvZTpqYW5lc2VjcmV0
--- error_code: 200
--- response_body
hello world
--- error_log
find consumer ldapadvjdoe



=== TEST 31: wrong password -> 401 (step-4 result-code failure, not a transport error)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAxOndyb25n
--- error_code: 401



=== TEST 32: unknown user -> 401 (step-3 search returns 0 entries)
--- request
GET /hello
--- more_headers
Authorization: ldap bm91c2VyOng=
--- error_code: 401



=== TEST 33: ambiguous match (two uid=dupuser entries) -> 401 + "ambiguous" warn
--- request
GET /hello
--- more_headers
Authorization: ldap ZHVwdXNlcjpkdXBwYXNzMQ==
--- error_code: 401
--- grep_error_log eval
qr/ambiguous user match/
--- grep_error_log_out
ambiguous user match



=== TEST 34: set up the search-then-bind route with consumer_required=false
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1',
                ngx.HTTP_PUT,
                [[{
                    "plugins": {
                        "ldap-auth-advanced": {
                            "ldap_uri": "127.0.0.1:1389",
                            "base_dn": "ou=users,dc=example,dc=org",
                            "attribute": "uid",
                            "consumer_required": false
                        }
                    },
                    "upstream": {
                        "nodes": {
                            "127.0.0.1:1980": 1
                        },
                        "type": "roundrobin"
                    },
                    "uri": "/hello"
                }]]
                )
            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 35: consumer_required=false -> user01 authenticated, no Consumer attached (200)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body
hello world
--- no_error_log
find consumer



=== TEST 36: point the route at a dead LDAP port (transport-error case)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1',
                ngx.HTTP_PUT,
                [[{
                    "plugins": {
                        "ldap-auth-advanced": {
                            "ldap_uri": "127.0.0.1:1390",
                            "base_dn": "ou=users,dc=example,dc=org",
                            "attribute": "uid",
                            "timeout": 1000
                        }
                    },
                    "upstream": {
                        "nodes": {
                            "127.0.0.1:1980": 1
                        },
                        "type": "roundrobin"
                    },
                    "uri": "/hello"
                }]]
                )
            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 37: LDAP unreachable -> 500 (INV-8: transport error is never auth_failed)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 500
--- error_log
LDAP connect failed



=== TEST 38: set up an LDAPS route on 1636 (use_ldaps, ssl_verify off)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1',
                ngx.HTTP_PUT,
                [[{
                    "plugins": {
                        "ldap-auth-advanced": {
                            "ldap_uri": "127.0.0.1:1636",
                            "base_dn": "ou=users,dc=example,dc=org",
                            "attribute": "uid",
                            "use_ldaps": true,
                            "ssl_verify": false
                        }
                    },
                    "upstream": {
                        "nodes": {
                            "127.0.0.1:1980": 1
                        },
                        "type": "roundrobin"
                    },
                    "uri": "/hello"
                }]]
                )
            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 39: happy path over LDAPS (200)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body
hello world



=== TEST 40: set up a StartTLS route on 1389 (use_starttls, ssl_verify off)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1',
                ngx.HTTP_PUT,
                [[{
                    "plugins": {
                        "ldap-auth-advanced": {
                            "ldap_uri": "127.0.0.1:1389",
                            "base_dn": "ou=users,dc=example,dc=org",
                            "attribute": "uid",
                            "use_starttls": true,
                            "ssl_verify": false
                        }
                    },
                    "upstream": {
                        "nodes": {
                            "127.0.0.1:1980": 1
                        },
                        "type": "roundrobin"
                    },
                    "uri": "/hello"
                }]]
                )
            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 41: happy path over StartTLS (200)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body
hello world



=== TEST 42: restore the plain search-then-bind route for the injection suite
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1',
                ngx.HTTP_PUT,
                [[{
                    "plugins": {
                        "ldap-auth-advanced": {
                            "ldap_uri": "127.0.0.1:1389",
                            "base_dn": "ou=users,dc=example,dc=org",
                            "attribute": "uid"
                        }
                    },
                    "upstream": {
                        "nodes": {
                            "127.0.0.1:1980": 1
                        },
                        "type": "roundrobin"
                    },
                    "uri": "/hello"
                }]]
                )
            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 43: INV-6 filter-injection usernames each 401 (none widens the search)
--- config
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local port = ngx.var.server_port
            -- RFC 4515 s3 specials plus a NUL byte. Once escaped, every payload
            -- is a literal that matches NO user, so each 401s via the "user not
            -- found" path. The log assertions below are the real proof of
            -- escaping: an UNescaped "*" would build the presence filter (uid=*),
            -- match >1 entry, and 401 via the "ambiguous user match" path instead
            -- -- so we assert "user not found" IS logged and "ambiguous user
            -- match" is NOT (status 401 alone cannot tell the two paths apart).
            local injections = { "*", "*)(objectClass=*", "(", ")", "\\", "\0" }
            local all_401 = true
            local statuses = {}
            for _, u in ipairs(injections) do
                local hc = http.new()
                local cred = ngx.encode_base64(u .. ":x")
                local res, err = hc:request_uri(
                    "http://127.0.0.1:" .. port .. "/hello",
                    { headers = { ["Authorization"] = "ldap " .. cred } })
                local st = res and res.status or ("ERR:" .. tostring(err))
                statuses[#statuses + 1] = tostring(st)
                if st ~= 401 then all_401 = false end
            end
            ngx.say("all_401: ", tostring(all_401))
            ngx.say("statuses: ", table.concat(statuses, ","))
        }
    }
--- response_body
all_401: true
statuses: 401,401,401,401,401,401
--- error_log
user not found
--- no_error_log
ambiguous user match



=== TEST 44: username with an invalid UTF-8 byte -> clean 401, never a 500 (INV-6/INV-8)
--- config
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local port = ngx.var.server_port
            -- 0xFF is a lone high byte: never valid UTF-8. filter.escape leaves it
            -- untouched, so if it reached the search the fork filter grammar would
            -- reject it as a "syntax error", which the plugin's non-result-code
            -- branch turns into HTTP 500. A malformed username is a bad credential
            -- (a client error), so it must be rejected up front as a clean 401 --
            -- never surfaced as a server-side 500.
            local hc = http.new()
            local cred = ngx.encode_base64(string.char(0xff) .. ":x")
            local res, err = hc:request_uri(
                "http://127.0.0.1:" .. port .. "/hello",
                { headers = { ["Authorization"] = "ldap " .. cred } })
            ngx.say("status: ", res and res.status or ("ERR:" .. tostring(err)))
        }
    }
--- response_body
status: 401
--- error_log
invalid username
--- no_error_log
LDAP user search failed



=== TEST 45: well-formed multibyte UTF-8 username reaches the search and 401s as not-found (INV-6)
--- config
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local port = ngx.var.server_port
            -- "h" + U+00E9 (e-acute, bytes 0xC3 0xA9) + "llo": valid 2-byte UTF-8.
            -- It must pass the encoding check and reach the search, where it
            -- matches no user -> the "user not found" 401 path. This proves valid
            -- multibyte input is NOT rejected as bad encoding (only invalid byte
            -- sequences are).
            local hc = http.new()
            local username = "h" .. string.char(0xc3, 0xa9) .. "llo"
            local cred = ngx.encode_base64(username .. ":x")
            local res, err = hc:request_uri(
                "http://127.0.0.1:" .. port .. "/hello",
                { headers = { ["Authorization"] = "ldap " .. cred } })
            ngx.say("status: ", res and res.status or ("ERR:" .. tostring(err)))
        }
    }
--- response_body
status: 401
--- error_log
user not found
--- no_error_log
invalid username



=== TEST 46: username with a grammar-reserved ASCII byte (trailing '~') -> clean 401, never a 500 (INV-6/INV-8)
--- config
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local port = ngx.var.server_port
            -- "admin~" is valid ASCII (it passes any UTF-8 check) but filter.escape
            -- leaves '~' untouched and the fork filter grammar rejects a trailing
            -- '~' as a "syntax error". Before the compile pre-check this reached the
            -- search and the non-result-code branch turned that "syntax error" into
            -- HTTP 500. A malformed username is a bad credential (a client error),
            -- so it must be rejected up front as a clean 401 with "invalid username"
            -- -- never surfaced as a 500 and never logged as an LDAP search failure.
            local hc = http.new()
            local cred = ngx.encode_base64("admin~:x")
            local res, err = hc:request_uri(
                "http://127.0.0.1:" .. port .. "/hello",
                { headers = { ["Authorization"] = "ldap " .. cred } })
            ngx.say("status: ", res and res.status or ("ERR:" .. tostring(err)))
        }
    }
--- response_body
status: 401
--- error_log
invalid username
--- no_error_log
LDAP user search failed



=== TEST 47: set up the three concurrent-probe routes (churn + anon-secret + svc-secret)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            -- route 1 (/hello): bind_dn UNSET, the pool-churn route.
            local code = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "keepalive_pool_size": 4
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/hello"
            }]])
            -- route 2 (/uri): bind_dn UNSET -- searches anonymously (Route A).
            local code2 = t('/apisix/admin/routes/2', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "keepalive_pool_size": 4
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/uri"
            }]])
            -- route 3 (/hello1): bind_dn SET -- searches as the service account (Route B).
            local code3 = t('/apisix/admin/routes/3', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "bind_dn": "cn=amdin,dc=example,dc=org",
                    "ldap_password": "adminpassword",
                    "keepalive_pool_size": 4
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/hello1"
            }]])
            local ok = code < 300 and code2 < 300 and code3 < 300
            ngx.say(ok and "passed" or "failed")
        }
    }
--- response_body
passed



=== TEST 48: CONCURRENT bind-state-leak probe (INV-2/INV-3): anon re-bind must not leak
--- config
    location /probe {
        content_by_lua_block {
            local http = require("resty.http")
            local args = ngx.req.get_uri_args()
            local hc = http.new()
            local cred = ngx.encode_base64(args.u .. ":" .. args.p)
            local res, err = hc:request_uri(
                "http://127.0.0.1:" .. ngx.var.server_port .. args.path,
                { headers = { ["Authorization"] = "ldap " .. cred } })
            ngx.print(res and tostring(res.status) or ("ERR:" .. tostring(err)))
        }
    }
    location /t {
        content_by_lua_block {
            -- Phase 1: CONCURRENTLY authenticate several end users on the
            -- bind_dn-UNSET churn route so multiple pooled sockets end step-4
            -- bound as DIFFERENT end users (the INV-2/INV-3 precondition).
            -- keepalive_pool_size=4 (>1) and all routes share pool 127.0.0.1:1389.
            local churn = {
                {u="user01", p="password1"}, {u="user02", p="password2"},
                {u="jdoe",   p="janesecret"},
            }
            local reqs = {}
            for i = 1, 9 do
                local c = churn[((i - 1) % 3) + 1]
                reqs[i] = { "/probe", { args = { path = "/hello", u = c.u, p = c.p } } }
            end
            -- ngx.thread.spawn drives the concurrent capture_multi wave.
            local th = assert(ngx.thread.spawn(function()
                return { ngx.location.capture_multi(reqs) }
            end))
            local _, churn_resps = ngx.thread.wait(th)
            local churn_all_200 = true
            for _, r in ipairs(churn_resps) do
                if r.body ~= "200" then churn_all_200 = false end
            end

            -- Phase 2: Route A (bind_dn UNSET) authenticating `secretuser`, which
            -- is hidden from an anonymous search. Its step-3 simple_bind("","")
            -- MUST reset any reused (end-user-bound) socket to anonymous -> the
            -- search finds nothing -> 401. A leaked end-user bind would resolve
            -- secretuser and 200.
            local a = {}
            for i = 1, 5 do
                a[i] = { "/probe", { args = { path = "/uri", u = "secretuser", p = "secretpass" } } }
            end
            local ares = { ngx.location.capture_multi(a) }
            local routeA_all_401 = true
            for _, r in ipairs(ares) do
                if r.body ~= "401" then routeA_all_401 = false end
            end

            -- Phase 3: Route B (bind_dn SET) authenticating `secretuser`. Its
            -- step-3 simple_bind(service-account) resolves secretuser -> 200.
            local b = {}
            for i = 1, 5 do
                b[i] = { "/probe", { args = { path = "/hello1", u = "secretuser", p = "secretpass" } } }
            end
            local bres = { ngx.location.capture_multi(b) }
            local routeB_all_200 = true
            for _, r in ipairs(bres) do
                if r.body ~= "200" then routeB_all_200 = false end
            end

            ngx.say("churn_all_200: ", tostring(churn_all_200))
            ngx.say("routeA_anon_all_401: ", tostring(routeA_all_401))
            ngx.say("routeB_svc_all_200: ", tostring(routeB_all_200))
        }
    }
--- timeout: 15
--- response_body
churn_all_200: true
routeA_anon_all_401: true
routeB_svc_all_200: true



=== TEST 49: group schema fields default correctly (cn / member / memberOf)
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local conf = {
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                group_base_dn = "ou=groups,dc=example,dc=org",
            }
            local ok, err = plugin.check_schema(conf)
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say(conf.group_name_attribute, " ",
                    conf.group_member_attribute, " ",
                    conf.user_membership_attribute)
        }
    }
--- response_body
cn member memberOf



=== TEST 50: group_name_attribute with a bad pattern is rejected
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                group_name_attribute = "a b",
            })
            ngx.say(ok and "passed" or "rejected")
        }
    }
--- response_body
rejected



=== TEST 51: group_member_attribute with a bad pattern is rejected
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                group_member_attribute = "1bad",
            })
            ngx.say(ok and "passed" or "rejected")
        }
    }
--- response_body
rejected



=== TEST 52: user_membership_attribute with a bad pattern is rejected
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                user_membership_attribute = "has space",
            })
            ngx.say(ok and "passed" or "rejected")
        }
    }
--- response_body
rejected



=== TEST 53: set up the three group-collection routes
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            -- route 1 (/hello): SEARCH path, bind_dn SET (service account) --
            -- exercises the simple_bind(bind_dn, ldap_password) re-bind branch.
            -- ldap_debug enables the group-name log these blocks observe.
            local code = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "group_base_dn": "ou=groups,dc=example,dc=org",
                    "bind_dn": "cn=amdin,dc=example,dc=org",
                    "ldap_password": "adminpassword",
                    "consumer_required": false,
                    "ldap_debug": true
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/hello"
            }]])
            -- route 2 (/uri): ATTRIBUTE path, no group_base_dn -- reads memberOf
            -- off the step-3 user entry (no second LDAP round trip).
            local code2 = t('/apisix/admin/routes/2', ngx.HTTP_PUT, [[{
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
            -- route 3 (/hello1): SEARCH path, bind_dn UNSET -- exercises the
            -- simple_bind("", "") anonymous re-bind branch (INV-4 crux route).
            local code3 = t('/apisix/admin/routes/3', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "group_base_dn": "ou=groups,dc=example,dc=org",
                    "consumer_required": false,
                    "ldap_debug": true
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/hello1"
            }]])
            local ok = code < 300 and code2 < 300 and code3 < 300
            ngx.say(ok and "passed" or "failed")
        }
    }
--- response_body
passed



=== TEST 54: user01 via the SEARCH path collects Domain Admins + developers
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body
hello world
--- error_log
groups:
Domain Admins
developers



=== TEST 55: user01 via the memberOf path collects Domain Admins + developers
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- error_log
groups:
Domain Admins
developers



=== TEST 56: jdoe (space in the login->cn) via the SEARCH path collects Domain Admins + ops
--- request
GET /hello
--- more_headers
Authorization: ldap amRvZTpqYW5lc2VjcmV0
--- error_code: 200
--- response_body
hello world
--- error_log
groups:
Domain Admins
ops



=== TEST 57: jdoe via the memberOf path collects Domain Admins + ops (space in the group RDN value)
--- request
GET /uri
--- more_headers
Authorization: ldap amRvZTpqYW5lc2VjcmV0
--- error_code: 200
--- error_log
groups:
Domain Admins
ops



=== TEST 58: user02 via the SEARCH path collects superadmin only
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAyOnBhc3N3b3JkMg==
--- error_code: 200
--- response_body
hello world
--- error_log
groups: superadmin



=== TEST 59: user02 via the memberOf path collects superadmin only
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAyOnBhc3N3b3JkMg==
--- error_code: 200
--- error_log
groups: superadmin



=== TEST 60: INV-4 observable -- the group member attribute is identity-dependent
--- config
    location /t {
        content_by_lua_block {
            -- Prove the fixture ACL that makes the INV-4 test non-vacuous: the
            -- `member` attribute of the ou=groups entries is readable by the
            -- configured search identity (anonymous) but NOT by a regular
            -- end user. A (member=<user_dn>) search therefore resolves the
            -- groups ONLY when the pinned socket is bound as the configured
            -- identity -- so a plugin that skipped the step-5 re-bind (leaving
            -- the socket bound as the END USER from step 4) would collect none.
            local client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")
            local filter = require("resty.ldap.filter")

            local function member_hits(bind_dn, bind_pw)
                local c = client:new("127.0.0.1", 1389, { socket_timeout = 3000 })
                assert(c:connect())
                assert(c:simple_bind(bind_dn, bind_pw))
                local entries = assert(c:search(
                    "ou=groups,dc=example,dc=org",
                    protocol.SEARCH_SCOPE_WHOLE_SUBTREE,
                    protocol.SEARCH_DEREF_ALIASES_ALWAYS,
                    10, 5, false,
                    "(member=" .. filter.escape(
                        "cn=user01,ou=users,dc=example,dc=org") .. ")",
                    { "cn" }))
                c:close()
                local n = 0
                for _, e in ipairs(entries) do
                    if e.entry_dn then n = n + 1 end
                end
                return n
            end

            -- bound as the END USER (user01): the member ACL denies it -> 0.
            ngx.say("end_user_hits: ",
                    member_hits("cn=user01,ou=users,dc=example,dc=org", "password1"))
            -- bound as the configured identity (anonymous): allowed -> 2.
            ngx.say("anonymous_hits: ", member_hits("", ""))
        }
    }
--- response_body
end_user_hits: 0
anonymous_hits: 2



=== TEST 61: INV-4 crux -- user01 on the anonymous-rebind SEARCH route still collects its groups
--- request
GET /hello1
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- error_log
groups:
Domain Admins
developers



=== TEST 62: multiuser via the SEARCH path collects ALL three groups (unbounded group search)
--- request
GET /hello
--- more_headers
Authorization: ldap bXVsdGl1c2VyOm11bHRpcGFzcw==
--- error_code: 200
--- response_body
hello world
--- error_log
groups:
Domain Admins
developers
ops



=== TEST 63: multiuser via the memberOf path also collects all three groups
--- request
GET /uri
--- more_headers
Authorization: ldap bXVsdGl1c2VyOm11bHRpcGFzcw==
--- error_code: 200
--- error_log
groups:
Domain Admins
developers
ops



=== TEST 64: groups_required (outer OR of inner ANDs) is a valid schema
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                groups_required = {{"Domain Admins", "ops"}, {"superadmin"}},
            })
            ngx.say(ok and "passed" or err)
        }
    }
--- response_body
passed



=== TEST 65: groups_required that is not an array is rejected
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                groups_required = "superadmin",
            })
            ngx.say(ok and "passed" or "rejected")
        }
    }
--- response_body
rejected



=== TEST 66: groups_required with an empty inner array is rejected (inner minItems 1)
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                groups_required = {{}},
            })
            ngx.say(ok and "passed" or "rejected")
        }
    }
--- response_body
rejected



=== TEST 67: groups_required with a non-string group name is rejected
--- config
    location /t {
        content_by_lua_block {
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok = plugin.check_schema({
                ldap_uri = "127.0.0.1:1389",
                base_dn = "ou=users,dc=example,dc=org",
                groups_required = {{123}},
            })
            ngx.say(ok and "passed" or "rejected")
        }
    }
--- response_body
rejected



=== TEST 68: set up the groups_required route (memberOf path, /uri echoes the outbound header)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            -- consumer_required=false isolates step 6 (authorization) from step 7;
            -- the /uri upstream echoes request headers so step 8's outbound
            -- X-Authenticated-Groups is observable in the response body.
            local code, body = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [=[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "consumer_required": false,
                    "groups_required": [["Domain Admins", "ops"], ["superadmin"]]
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



=== TEST 69: jdoe satisfies inner AND [Domain Admins, ops] -> 200 + outbound header carries both names
--- request
GET /uri
--- more_headers
Authorization: ldap amRvZTpqYW5lc2VjcmV0
X-Authenticated-Groups: injected
--- error_code: 200
--- response_body_like eval
qr/x-authenticated-groups: (Domain Admins,ops|ops,Domain Admins)\n/
--- response_body_unlike eval
qr/injected/



=== TEST 70: user01 (Domain Admins + developers) satisfies no inner AND -> 403, distinct from the 401 body (INV-8)
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
--- grep_error_log eval
qr/groups_required not satisfied/
--- grep_error_log_out
groups_required not satisfied



=== TEST 71: user02 satisfies the OR alternate [superadmin] -> 200 + exact single-group header (inbound stripped)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAyOnBhc3N3b3JkMg==
X-Authenticated-Groups: injected
--- error_code: 200
--- response_body_like eval
qr/x-authenticated-groups: superadmin\n/
--- response_body_unlike eval
qr/injected/



=== TEST 72: on the groups_required route a wrong password -> 401 body, distinct from the 403 body (INV-8), no outbound header
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOndyb25n
X-Authenticated-Groups: injected
--- error_code: 401
--- response_body
{"message":"Authorization required"}
--- response_headers
X-Authenticated-Groups:



=== TEST 73: set up a groups_required route with a space-containing name in the OR position
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
                    "groups_required": [["developers"], ["Domain Admins"]]
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



=== TEST 74: jdoe passes via the space-containing OR alternate "Domain Admins" (INV-13 verbatim, space preserved)
--- request
GET /uri
--- more_headers
Authorization: ldap amRvZTpqYW5lc2VjcmV0
--- error_code: 200
--- response_body_like eval
qr/x-authenticated-groups: (Domain Admins,ops|ops,Domain Admins)\n/



=== TEST 75: set up a groups_required route with a space-containing name inside an inner AND
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
                    "groups_required": [["Domain Admins", "developers"]]
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



=== TEST 76: user01 satisfies the inner AND [Domain Admins, developers] (space-containing AND term) -> 200
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body_like eval
qr/x-authenticated-groups: (Domain Admins,developers|developers,Domain Admins)\n/



=== TEST 77: user02 (superadmin only) fails the inner AND [Domain Admins, developers] -> 403
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAyOnBhc3N3b3JkMg==
--- error_code: 403
--- response_body
{"message":"Forbidden"}



=== TEST 78: set up a groups_required route whose required name differs only by case
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
                    "groups_required": [["domain admins"]]
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



=== TEST 79: "domain admins" does NOT match the collected "Domain Admins" -> 403 (INV-13, no case folding)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 403
--- response_body
{"message":"Forbidden"}
--- grep_error_log eval
qr/groups_required not satisfied/
--- grep_error_log_out
groups_required not satisfied



=== TEST 80: point a groups_required route at a dead LDAP port (transport-error case)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [=[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1390",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "timeout": 1000,
                    "consumer_required": false,
                    "groups_required": [["superadmin"]]
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



=== TEST 81: LDAP unreachable -> 500 and the outbound header is absent (INV-5/INV-8)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAyOnBhc3N3b3JkMg==
X-Authenticated-Groups: injected
--- error_code: 500
--- response_headers
X-Authenticated-Groups:
--- error_log
LDAP connect failed



=== TEST 82: consumer schema with group_dn only passes (oneOf alternate)
--- config
    location /t {
        content_by_lua_block {
            local core = require("apisix.core")
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok, err = plugin.check_schema(
                { group_dn = "cn=Domain Admins,ou=groups,dc=example,dc=org" },
                core.schema.TYPE_CONSUMER)
            ngx.say(ok and "passed" or err)
        }
    }
--- response_body
passed



=== TEST 83: consumer schema with BOTH user_dn and group_dn is rejected (oneOf: exactly one)
--- config
    location /t {
        content_by_lua_block {
            local core = require("apisix.core")
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local ok = plugin.check_schema({
                user_dn  = "cn=user01,ou=users,dc=example,dc=org",
                group_dn = "cn=Domain Admins,ou=groups,dc=example,dc=org",
            }, core.schema.TYPE_CONSUMER)
            ngx.say(ok and "passed" or "rejected")
        }
    }
--- response_body
rejected



=== TEST 84: set up the group-collection route (group_base_dn, service-account bind, consumer_required default true)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "group_base_dn": "ou=groups,dc=example,dc=org",
                    "bind_dn": "cn=amdin,dc=example,dc=org",
                    "ldap_password": "adminpassword"
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/hello"
            }]])
            if code >= 300 then ngx.status = code end
            ngx.say(body)
        }
    }
--- response_body
passed



=== TEST 85: reset to a clean Consumer set and create group_dn-only Consumers (INV-13: maps on DNs)
--- config
    location /t {
        content_by_lua_block {
            local core = require("apisix.core")
            local t = require("lib.test_admin").test
            -- Drop the earlier user_dn Consumers so user01 has NO user_dn
            -- Consumer -- isolating the pure group_dn match that follows.
            for _, name in ipairs({ "ldapadvuser01", "ldapadvuser02",
                                    "ldapadvjdoe", "ldapadvsecret" }) do
                local code = t('/apisix/admin/consumers/' .. name, ngx.HTTP_DELETE)
                if code >= 300 then
                    ngx.status = code
                    ngx.say("delete ", name, " failed")
                    return
                end
            end
            -- INV-13: the Consumer group_dn matches group DNs, not names.
            local groups = {
                { name = "ldapadvgrpadmins",
                  dn = "cn=Domain Admins,ou=groups,dc=example,dc=org" },
                { name = "ldapadvgrpsuper",
                  dn = "cn=superadmin,ou=groups,dc=example,dc=org" },
            }
            for _, g in ipairs(groups) do
                local code, body = t('/apisix/admin/consumers',
                    ngx.HTTP_PUT,
                    core.json.encode({
                        username = g.name,
                        plugins = {
                            ["ldap-auth-advanced"] = { group_dn = g.dn },
                        },
                    }))
                if code >= 300 then
                    ngx.status = code
                    ngx.say(body)
                    return
                end
            end
            ngx.say("passed")
        }
    }
--- response_body
passed



=== TEST 86: user01 (in Domain Admins, no user_dn Consumer) matches the group_dn Consumer -> 200
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body
hello world
--- error_log
find consumer ldapadvgrpadmins



=== TEST 87: user02 (in superadmin) matches a different group_dn Consumer -> 200 (two group Consumers coexist)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAyOnBhc3N3b3JkMg==
--- error_code: 200
--- response_body
hello world
--- error_log
find consumer ldapadvgrpsuper



=== TEST 88: add user_dn Consumers for user01 and jdoe (now both a user_dn and a group_dn Consumer could match)
--- config
    location /t {
        content_by_lua_block {
            local core = require("apisix.core")
            local t = require("lib.test_admin").test
            local users = {
                { name = "ldapadvuser01dn", dn = "cn=user01,ou=users,dc=example,dc=org" },
                { name = "ldapadvjdoedn",   dn = "cn=Jane Doe,ou=users,dc=example,dc=org" },
            }
            for _, u in ipairs(users) do
                local code, body = t('/apisix/admin/consumers',
                    ngx.HTTP_PUT,
                    core.json.encode({
                        username = u.name,
                        plugins = {
                            ["ldap-auth-advanced"] = { user_dn = u.dn },
                        },
                    }))
                if code >= 300 then
                    ngx.status = code
                    ngx.say(body)
                    return
                end
            end
            ngx.say("passed")
        }
    }
--- response_body
passed



=== TEST 89: user01 -- user_dn Consumer WINS over the group_dn Consumer (INV-10 precedence)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body
hello world
--- error_log
find consumer ldapadvuser01dn
--- no_error_log
find consumer ldapadvgrpadmins



=== TEST 90: jdoe -- user_dn Consumer attaches while group_dn Consumers coexist (jdoe is in Domain Admins)
--- request
GET /hello
--- more_headers
Authorization: ldap amRvZTpqYW5lc2VjcmV0
--- error_code: 200
--- response_body
hello world
--- error_log
find consumer ldapadvjdoedn
--- no_error_log
find consumer ldapadvgrpadmins



=== TEST 91: user02 -- still resolves via the superadmin group_dn Consumer (user_dn and group_dn sets coexist)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAyOnBhc3N3b3JkMg==
--- error_code: 200
--- response_body
hello world
--- error_log
find consumer ldapadvgrpsuper



=== TEST 92: secretuser -- no user_dn Consumer and in NO group -> 401 (INV-10 no match, consumer_required)
--- request
GET /hello
--- more_headers
Authorization: ldap c2VjcmV0dXNlcjpzZWNyZXRwYXNz
--- error_code: 401
--- grep_error_log eval
qr/no Consumer maps/
--- grep_error_log_out
no Consumer maps



=== TEST 93: consumer schema with NEITHER user_dn nor group_dn is rejected (oneOf: at least one required)
--- config
    location /t {
        content_by_lua_block {
            local core = require("apisix.core")
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            -- a Consumer block that carries some unrelated field but neither DN:
            -- the oneOf (exactly one of user_dn / group_dn) matches ZERO branches,
            -- so it is rejected for having nothing to match on (complements the
            -- both-set rejection in TEST 83).
            local ok = plugin.check_schema({ nickname = "nobody" },
                                           core.schema.TYPE_CONSUMER)
            ngx.say(ok and "passed" or "rejected")
        }
    }
--- response_body
rejected



=== TEST 94: set up the unescape-observation routes (comma-in-cn group "Sales, EMEA")
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            -- route 1 (/hello): SEARCH path, group_base_dn + service-account bind,
            -- consumer_required=false -- reads the group NAME from the cn attribute.
            -- ldap_debug enables the group-name log these blocks observe.
            local code = t('/apisix/admin/routes/1', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid",
                    "group_base_dn": "ou=groups,dc=example,dc=org",
                    "bind_dn": "cn=amdin,dc=example,dc=org",
                    "ldap_password": "adminpassword",
                    "consumer_required": false,
                    "ldap_debug": true
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/hello"
            }]])
            -- route 2 (/uri): memberOf path (no group_base_dn), consumer_required
            -- =false -- reads the group NAME from the first RDN of the memberOf DN,
            -- which OpenLDAP renders with the comma hex-escaped (cn=Sales\2C EMEA).
            -- The /uri upstream echoes request headers so the outbound
            -- X-Authenticated-Groups (step 8) is observable in the body.
            local code2 = t('/apisix/admin/routes/2', ngx.HTTP_PUT, [[{
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
            local ok = code < 300 and code2 < 300
            ngx.say(ok and "passed" or "failed")
        }
    }
--- response_body
passed



=== TEST 95: salesuser via the SEARCH path -- group NAME is the cn value "Sales, EMEA"
--- request
GET /hello
--- more_headers
Authorization: ldap c2FsZXN1c2VyOnNhbGVzcGFzcw==
--- error_code: 200
--- response_body
hello world
--- error_log
groups: Sales, EMEA



=== TEST 96: salesuser via the memberOf path -- UNESCAPED first RDN equals the SEARCH-path name "Sales, EMEA" (INV-13)
--- request
GET /uri
--- more_headers
Authorization: ldap c2FsZXN1c2VyOnNhbGVzcGFzcw==
X-Authenticated-Groups: injected
--- error_code: 200
--- response_body_like eval
qr/x-authenticated-groups: Sales, EMEA\n/
--- response_body_unlike eval
qr/Sales\\2C EMEA|injected/
--- error_log
groups: Sales, EMEA



=== TEST 97: switch the memberOf-path /uri route to consumer_required (default true)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/2', ngx.HTTP_PUT, [[{
                "plugins": { "ldap-auth-advanced": {
                    "ldap_uri": "127.0.0.1:1389",
                    "base_dn": "ou=users,dc=example,dc=org",
                    "attribute": "uid"
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



=== TEST 98: multiuser (in Domain Admins, no user_dn Consumer) matches the group_dn Consumer via the memberOf path -> 200
--- request
GET /uri
--- more_headers
Authorization: ldap bXVsdGl1c2VyOm11bHRpcGFzcw==
--- error_code: 200
--- error_log
find consumer ldapadvgrpadmins



=== TEST 99: consumer-miss on the memberOf path -- salesuser authenticates with a group but no Consumer maps -> 401, NO outbound header (INV-5/INV-10)
--- request
GET /uri
--- more_headers
Authorization: ldap c2FsZXN1c2VyOnNhbGVzcGFzcw==
X-Authenticated-Groups: injected
--- error_code: 401
--- response_headers
X-Authenticated-Groups:
--- grep_error_log eval
qr/no Consumer maps/
--- grep_error_log_out
no Consumer maps



=== TEST 100: cache_ttl below 0 is rejected (schema minimum 0)
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



=== TEST 101: cache_ttl defaults to 60 (INV-11)
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



=== TEST 102: create the throwaway cacheuser (uid=cacheuser / cachepass)
--- config
    location /t {
        content_by_lua_block {
            -- A dedicated throwaway user for the mutation tests: its password is
            -- rotated in the directory and restored so the truth-table users
            -- (user01/user02/jdoe/multiuser/...) are never perturbed. Created at
            -- runtime (delete-then-add is idempotent across re-runs) and deleted
            -- again by the final teardown block, so the container's fixture state
            -- is left exactly as it was -- no recreate, INV-4/concurrent probes
            -- untouched.
            local admin = "-x -H ldap://127.0.0.1:1389 "
                          .. "-D 'cn=amdin,dc=example,dc=org' -w adminpassword"
            os.execute("docker exec $(docker ps -qf name=openldap) ldapdelete " .. admin
                       .. " 'cn=Cache User,ou=users,dc=example,dc=org' "
                       .. ">/dev/null 2>&1")
            os.execute("printf 'dn: cn=Cache User,ou=users,dc=example,"
                .. "dc=org\\nobjectClass: inetOrgPerson\\ncn: Cache User\\nsn: User"
                .. "\\nuid: cacheuser\\nuserPassword: cachepass\\n' | docker exec -i "
                .. "$(docker ps -qf name=openldap) ldapadd " .. admin .. " >/dev/null 2>&1")
            ngx.say("created")
        }
    }
--- response_body
created



=== TEST 103: set up the cache routes (ttl0 / default / short / a / b)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            -- consumer_required=false isolates the cache (step 2 / step-5 write)
            -- from the Consumer decision (step 7). Every route resolves cacheuser
            -- identically; only cache_ttl and the route identity differ. The uris
            -- map to real test-upstream handlers (so an authenticated request
            -- proxies through to a 200, distinct from a 401 auth failure); route
            -- ids 1/2/3 keep their existing uris to avoid duplicate-uri matches.
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



=== TEST 104: cache_ttl=0 -> directory hit every request; a rotated password fails immediately (401)
--- config
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local port = ngx.var.server_port
            local admin = "-x -H ldap://127.0.0.1:1389 "
                          .. "-D 'cn=amdin,dc=example,dc=org' -w adminpassword"
            local function set_pw(pw)
                local ok = os.execute("printf 'dn: cn=Cache User,ou=users,dc=example,"
                    .. "dc=org\\nchangetype: modify\\nreplace: userPassword\\nuserPassword: "
                    .. pw .. "\\n' | docker exec -i $(docker ps -qf name=openldap) ldapmodify "
                    .. admin .. " >/dev/null 2>&1")
                -- Fail loudly if the mutation did not apply: a silently-failing
                -- ldapmodify leaves the directory unchanged and would let a stale-hit
                -- assertion false-pass. (os.execute returns 0 on Lua 5.1, true on 5.2+.)
                assert(ok == 0 or ok == true, "ldapmodify failed to rotate cacheuser password")
            end
            local function req(pw)
                local hc = http.new()
                local res = hc:request_uri("http://127.0.0.1:" .. port .. "/hello",
                    { headers = { ["Authorization"] =
                        "ldap " .. ngx.encode_base64("cacheuser:" .. pw) } })
                return res and res.status or 0
            end
            -- Each scenario block restarts nginx (it defines its own /t location);
            -- wait for the route's etcd sync so the first proxied request does not
            -- race it. A no-credential probe 401s once the route is live.
            local function wait_route(path)
                for _ = 1, 100 do
                    local hc = http.new()
                    local res = hc:request_uri("http://127.0.0.1:" .. port .. path)
                    if res and res.status ~= 404 then return end
                    ngx.sleep(0.1)
                end
            end
            wait_route("/hello")
            set_pw("cachepass")
            local primed = req("cachepass")      -- fresh bind -> 200
            set_pw("newpass")                    -- rotate in the directory
            local after = req("cachepass")       -- cache disabled: fresh bind of the
                                                 -- OLD password -> directory rejects -> 401
            set_pw("cachepass")                  -- restore
            ngx.say("primed: ", primed)
            ngx.say("after_rotation: ", after)
        }
    }
--- response_body
primed: 200
after_rotation: 401



=== TEST 105: default cache_ttl serves a stale hit -- a rotated password still 200 within the TTL (INV-11)
--- config
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local port = ngx.var.server_port
            local admin = "-x -H ldap://127.0.0.1:1389 "
                          .. "-D 'cn=amdin,dc=example,dc=org' -w adminpassword"
            local function set_pw(pw)
                local ok = os.execute("printf 'dn: cn=Cache User,ou=users,dc=example,"
                    .. "dc=org\\nchangetype: modify\\nreplace: userPassword\\nuserPassword: "
                    .. pw .. "\\n' | docker exec -i $(docker ps -qf name=openldap) ldapmodify "
                    .. admin .. " >/dev/null 2>&1")
                -- Fail loudly if the mutation did not apply: a silently-failing
                -- ldapmodify leaves the directory unchanged and would let a stale-hit
                -- assertion false-pass. (os.execute returns 0 on Lua 5.1, true on 5.2+.)
                assert(ok == 0 or ok == true, "ldapmodify failed to rotate cacheuser password")
            end
            local function req(pw)
                local hc = http.new()
                local res = hc:request_uri("http://127.0.0.1:" .. port .. "/uri",
                    { headers = { ["Authorization"] =
                        "ldap " .. ngx.encode_base64("cacheuser:" .. pw) } })
                return res and res.status or 0
            end
            local function wait_route(path)
                for _ = 1, 100 do
                    local hc = http.new()
                    local res = hc:request_uri("http://127.0.0.1:" .. port .. path)
                    if res and res.status ~= 404 then return end
                    ngx.sleep(0.1)
                end
            end
            wait_route("/uri")
            set_pw("cachepass")
            local primed = req("cachepass")      -- miss -> resolve -> 200, caches the resolution
            set_pw("newpass")                    -- rotate in the directory
            local after = req("cachepass")       -- HIT (key = user + sha256(old pw)): steps 3-5
                                                 -- skipped, served from cache -> still 200
            set_pw("cachepass")                  -- restore
            ngx.say("primed: ", primed)
            ngx.say("after_rotation: ", after)
        }
    }
--- response_body
primed: 200
after_rotation: 200



=== TEST 106: a short cache_ttl expires -- the stale hit stops serving after the TTL (INV-11)
--- config
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local port = ngx.var.server_port
            local admin = "-x -H ldap://127.0.0.1:1389 "
                          .. "-D 'cn=amdin,dc=example,dc=org' -w adminpassword"
            local function set_pw(pw)
                local ok = os.execute("printf 'dn: cn=Cache User,ou=users,dc=example,"
                    .. "dc=org\\nchangetype: modify\\nreplace: userPassword\\nuserPassword: "
                    .. pw .. "\\n' | docker exec -i $(docker ps -qf name=openldap) ldapmodify "
                    .. admin .. " >/dev/null 2>&1")
                -- Fail loudly if the mutation did not apply: a silently-failing
                -- ldapmodify leaves the directory unchanged and would let a stale-hit
                -- assertion false-pass. (os.execute returns 0 on Lua 5.1, true on 5.2+.)
                assert(ok == 0 or ok == true, "ldapmodify failed to rotate cacheuser password")
            end
            local function req(pw)
                local hc = http.new()
                local res = hc:request_uri("http://127.0.0.1:" .. port .. "/hello1",
                    { headers = { ["Authorization"] =
                        "ldap " .. ngx.encode_base64("cacheuser:" .. pw) } })
                return res and res.status or 0
            end
            local function wait_route(path)
                for _ = 1, 100 do
                    local hc = http.new()
                    local res = hc:request_uri("http://127.0.0.1:" .. port .. path)
                    if res and res.status ~= 404 then return end
                    ngx.sleep(0.1)
                end
            end
            wait_route("/hello1")
            set_pw("cachepass")
            local primed = req("cachepass")      -- miss -> resolve -> 200, caches with ttl=1
            set_pw("newpass")                    -- rotate in the directory
            local within = req("cachepass")      -- within 1s: HIT -> 200 (stale)
            ngx.sleep(2)                         -- let the entry (ttl=1) expire
            local expired = req("cachepass")     -- expired: miss -> fresh bind OLD pw -> 401
            set_pw("cachepass")                  -- restore
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



=== TEST 107: two routes cache the same credential independently -- one route's cache never serves the other (INV-11)
--- config
    location /t {
        content_by_lua_block {
            local http = require("resty.http")
            local port = ngx.var.server_port
            local admin = "-x -H ldap://127.0.0.1:1389 "
                          .. "-D 'cn=amdin,dc=example,dc=org' -w adminpassword"
            local function set_pw(pw)
                local ok = os.execute("printf 'dn: cn=Cache User,ou=users,dc=example,"
                    .. "dc=org\\nchangetype: modify\\nreplace: userPassword\\nuserPassword: "
                    .. pw .. "\\n' | docker exec -i $(docker ps -qf name=openldap) ldapmodify "
                    .. admin .. " >/dev/null 2>&1")
                -- Fail loudly if the mutation did not apply: a silently-failing
                -- ldapmodify leaves the directory unchanged and would let a stale-hit
                -- assertion false-pass. (os.execute returns 0 on Lua 5.1, true on 5.2+.)
                assert(ok == 0 or ok == true, "ldapmodify failed to rotate cacheuser password")
            end
            local function req(path, pw)
                local hc = http.new()
                local res = hc:request_uri("http://127.0.0.1:" .. port .. path,
                    { headers = { ["Authorization"] =
                        "ldap " .. ngx.encode_base64("cacheuser:" .. pw) } })
                return res and res.status or 0
            end
            local function wait_route(path)
                for _ = 1, 100 do
                    local hc = http.new()
                    local res = hc:request_uri("http://127.0.0.1:" .. port .. path)
                    if res and res.status ~= 404 then return end
                    ngx.sleep(0.1)
                end
            end
            wait_route("/server_port")
            wait_route("/hello_chunked")
            set_pw("cachepass")
            local a_primed = req("/server_port", "cachepass") -- route A: miss -> 200, caches under A's key
            set_pw("newpass")                                 -- rotate in the directory
            -- route B has its OWN plugin_ctx_id (distinct conf_id) -> no entry ->
            -- fresh bind of the OLD password -> directory rejects -> 401.
            local b_independent = req("/hello_chunked", "cachepass")
            -- route A still holds its own entry -> HIT -> 200.
            local a_still_hit = req("/server_port", "cachepass")
            set_pw("cachepass")                           -- restore
            ngx.say("a_primed: ", a_primed)
            ngx.say("b_independent: ", b_independent)
            ngx.say("a_still_hit: ", a_still_hit)
        }
    }
--- response_body
a_primed: 200
b_independent: 401
a_still_hit: 200



=== TEST 108: a config-version change is a cache MISS -- plugin_ctx_id embeds conf_version (INV-11)
--- config
    location /t {
        content_by_lua_block {
            -- Direct rewrite() calls with hand-built ctxs isolate the key's
            -- conf_version dependency deterministically (no route-reload race): a
            -- config change bumps ctx.conf_version, which plugin_ctx_id folds into
            -- the cache key, so a pre-change entry is never served post-change.
            local plugin = require("apisix.plugins.ldap-auth-advanced")
            local admin = "-x -H ldap://127.0.0.1:1389 "
                          .. "-D 'cn=amdin,dc=example,dc=org' -w adminpassword"
            local function set_pw(pw)
                local ok = os.execute("printf 'dn: cn=Cache User,ou=users,dc=example,"
                    .. "dc=org\\nchangetype: modify\\nreplace: userPassword\\nuserPassword: "
                    .. pw .. "\\n' | docker exec -i $(docker ps -qf name=openldap) ldapmodify "
                    .. admin .. " >/dev/null 2>&1")
                -- Fail loudly if the mutation did not apply: a silently-failing
                -- ldapmodify leaves the directory unchanged and would let a stale-hit
                -- assertion false-pass. (os.execute returns 0 on Lua 5.1, true on 5.2+.)
                assert(ok == 0 or ok == true, "ldapmodify failed to rotate cacheuser password")
            end
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



=== TEST 109: teardown -- delete the throwaway cacheuser (restore fixture state)
--- config
    location /t {
        content_by_lua_block {
            local admin = "-x -H ldap://127.0.0.1:1389 "
                          .. "-D 'cn=amdin,dc=example,dc=org' -w adminpassword"
            os.execute("docker exec $(docker ps -qf name=openldap) ldapdelete " .. admin
                       .. " 'cn=Cache User,ou=users,dc=example,dc=org' "
                       .. ">/dev/null 2>&1")
            ngx.say("cleaned")
        }
    }
--- response_body
cleaned



=== TEST 110: reset to a clean Consumer set + create the anonymous Consumer, set the anonymous route
--- config
    location /t {
        content_by_lua_block {
            local core = require("apisix.core")
            local t = require("lib.test_admin").test
            -- Drop every ldap-auth-advanced Consumer left by the earlier blocks so
            -- an authenticated user maps to NO Consumer -- isolating the step-7
            -- auth_failed -> anonymous_consumer fallback that follows.
            for _, name in ipairs({ "ldapadvgrpadmins", "ldapadvgrpsuper",
                                    "ldapadvuser01dn", "ldapadvjdoedn" }) do
                t('/apisix/admin/consumers/' .. name, ngx.HTTP_DELETE)
            end
            -- The anonymous Consumer carries NO ldap-auth-advanced plugin, so it is
            -- absent from consumers_conf(plugin_name) and can never be a match target;
            -- it is reachable only via get_anonymous_consumer on the 401 seam.
            local code, body = t('/apisix/admin/consumers', ngx.HTTP_PUT,
                core.json.encode({ username = "ldapadvanon" }))
            if code >= 300 then
                ngx.status = code
                ngx.say(body)
                return
            end
            -- consumer_required defaults true: a valid user with no mapped Consumer
            -- hits auth_failed at step 7, where anonymous_consumer takes over.
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



=== TEST 111: valid user, NO matching Consumer -> attaches anonymous, reaches upstream, NO X-Authenticated-Groups (INV-5/INV-8)
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



=== TEST 112: invalid credentials (wrong password) -> anonymous fallback still reaches upstream (INV-8 401 path)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOndyb25n
--- error_code: 200
--- response_body_like eval
qr/x-consumer-username: ldapadvanon/
--- response_body_unlike eval
qr/x-authenticated-groups/



=== TEST 113: no credential header at all -> anonymous fallback (step-1 auth_failed), reaches upstream
--- request
GET /uri
--- error_code: 200
--- response_body_like eval
qr/x-consumer-username: ldapadvanon/



=== TEST 114: point the anonymous route at a dead LDAP port (INV-8 transport-error case)
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



=== TEST 115: LDAP unreachable + anonymous_consumer -> 500, NEVER anonymous (INV-8)
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



=== TEST 116: groups_required route with anonymous_consumer set (INV-8 403 case)
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



=== TEST 117: user01 (not in superadmin) fails groups_required + anonymous_consumer -> 403, NEVER anonymous (INV-8)
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



=== TEST 118: set up the hide_credentials success route (consumer_required=false, /uri echoes request headers)
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



=== TEST 119: hide_credentials strips the Authorization header the upstream sees (success path, header_type ldap)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body_unlike eval
qr/authorization:/



=== TEST 120: with BOTH headers present, step 1 uses Proxy-Authorization -> hide strips ONLY it; Authorization is untouched
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



=== TEST 121: set up a hide_credentials + anonymous_consumer route (strip on the anonymous path too)
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



=== TEST 122: on the anonymous path hide_credentials strips the used header; upstream sees anonymous, no credential
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body_like eval
qr/x-consumer-username: ldapadvanon/
--- response_body_unlike eval
qr/authorization:/



=== TEST 123: set up the ldap_debug=false route (default; consumer_required=false so the memberOf groups collect)
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



=== TEST 124: ldap_debug default (false) -> the group-name log is NOT emitted (INV-12)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- no_error_log
ldap-auth-advanced: groups:



=== TEST 125: set up the ldap_debug=true route
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



=== TEST 126: ldap_debug=true -> the group names ARE logged, still with NO password (INV-12)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- error_log
ldap-auth-advanced: groups:
--- no_error_log
password1



=== TEST 127: set up an anonymous_consumer route with cache_ttl > 0 (scaffold: an absorbed auth failure must not poison the cache)
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
            -- anonymous_consumer set AND cache_ttl 60 (>0): a wrong-password auth
            -- failure must fall back to the anonymous Consumer, and that fallback must
            -- NEVER be cached under the wrong-password key. The /uri upstream
            -- echoes request headers so the attached x-consumer-username is observable.
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



=== TEST 128: wrong password TWICE (anonymous_consumer + cache_ttl>0) both fall back to anonymous, never a poisoned nil-user_dn cache hit -> 500
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
            -- First wrong-password request: the step-4 result-code failure reaches
            -- auth_failed, which attaches the anonymous Consumer (INV-8) and returns
            -- BEFORE the cache write -- the `if not user_dn then return` sentinel fires,
            -- so nothing is stored under the wrong-password key.
            local first = req()
            -- Second identical request: had the first poisoned the cache with
            -- {user_dn=nil}, this HIT would crash on #groups and 500. It must instead
            -- fall back to the anonymous Consumer again -> 200.
            local second = req()
            ngx.say("first: ", first)
            ngx.say("second: ", second)
        }
    }
--- response_body
first: 200 anon
second: 200 anon
