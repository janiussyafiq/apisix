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

=== TEST 1: group schema fields default correctly (cn / member / memberOf)
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



=== TEST 2: group_name_attribute with a bad pattern is rejected
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



=== TEST 3: group_member_attribute with a bad pattern is rejected
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



=== TEST 4: user_membership_attribute with a bad pattern is rejected
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



=== TEST 5: set up the three group-collection routes
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
                    "bind_dn": "cn=admin,dc=example,dc=org",
                    "ldap_password": "adminpassword",
                    "consumer_required": false,
                    "ldap_debug": true
                } },
                "upstream": { "nodes": { "127.0.0.1:1980": 1 }, "type": "roundrobin" },
                "uri": "/hello"
            }]])
            -- route 2 (/uri): ATTRIBUTE path, no group_base_dn -- reads memberOf
            -- off the user's search entry (no second LDAP round trip).
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
            -- simple_bind("", "") anonymous re-bind branch.
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



=== TEST 6: user01 via the SEARCH path collects Domain Admins + developers (creds: user01:password1)
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



=== TEST 7: user01 via the memberOf path collects Domain Admins + developers (creds: user01:password1)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- error_log
groups:
Domain Admins
developers



=== TEST 8: jdoe (space in the login->cn) via the SEARCH path collects Domain Admins + ops (creds: jdoe:janesecret)
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



=== TEST 9: jdoe via the memberOf path collects Domain Admins + ops (space in the group RDN value) (creds: jdoe:janesecret)
--- request
GET /uri
--- more_headers
Authorization: ldap amRvZTpqYW5lc2VjcmV0
--- error_code: 200
--- error_log
groups:
Domain Admins
ops



=== TEST 10: user02 via the SEARCH path collects superadmin only (creds: user02:password2)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAyOnBhc3N3b3JkMg==
--- error_code: 200
--- response_body
hello world
--- error_log
groups: superadmin



=== TEST 11: user02 via the memberOf path collects superadmin only (creds: user02:password2)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAyOnBhc3N3b3JkMg==
--- error_code: 200
--- error_log
groups: superadmin



=== TEST 12: fixture ACL check -- the group member attribute is identity-dependent
--- config
    location /t {
        content_by_lua_block {
            -- Prove the fixture ACL that makes the re-bind test non-vacuous: the
            -- `member` attribute of the ou=groups entries is readable by the
            -- configured search identity (anonymous) but NOT by a regular
            -- end user. A (member=<user_dn>) search therefore resolves the
            -- groups ONLY when the pinned socket is bound as the configured
            -- identity -- so a plugin that skipped the group-search re-bind
            -- (leaving the socket bound as the END USER) would collect none.
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



=== TEST 13: user01 on the anonymous-rebind SEARCH route still collects its groups (creds: user01:password1)
--- request
GET /hello1
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- error_log
groups:
Domain Admins
developers



=== TEST 14: multiuser via the SEARCH path collects ALL three groups (unbounded group search) (creds: multiuser:multipass)
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



=== TEST 15: multiuser via the memberOf path also collects all three groups (creds: multiuser:multipass)
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



=== TEST 16: groups_required (outer OR of inner ANDs) is a valid schema
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



=== TEST 17: groups_required that is not an array is rejected
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



=== TEST 18: groups_required with an empty inner array is rejected (inner minItems 1)
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



=== TEST 19: groups_required with a non-string group name is rejected
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



=== TEST 20: set up the groups_required route (memberOf path, /uri echoes the outbound header)
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            -- consumer_required=false isolates authorization from the Consumer
            -- decision; the /uri upstream echoes request headers so the outbound
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



=== TEST 21: jdoe satisfies inner AND [Domain Admins, ops] -> 200 + outbound header carries both names (creds: jdoe:janesecret)
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



=== TEST 22: user01 (Domain Admins + developers) satisfies no inner AND -> 403, distinct from the 401 body (creds: user01:password1)
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



=== TEST 23: user02 satisfies the OR alternate [superadmin] -> 200 + exact single-group header (inbound stripped) (creds: user02:password2)
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



=== TEST 24: on the groups_required route a wrong password -> 401 body, distinct from the 403 body, no outbound header (creds: user01:wrong)
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



=== TEST 25: set up a groups_required route with a space-containing name in the OR position
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



=== TEST 26: jdoe passes via the space-containing OR alternate "Domain Admins" (verbatim match, space preserved) (creds: jdoe:janesecret)
--- request
GET /uri
--- more_headers
Authorization: ldap amRvZTpqYW5lc2VjcmV0
--- error_code: 200
--- response_body_like eval
qr/x-authenticated-groups: (Domain Admins,ops|ops,Domain Admins)\n/



=== TEST 27: set up a groups_required route with a space-containing name inside an inner AND
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



=== TEST 28: user01 satisfies the inner AND [Domain Admins, developers] (space-containing AND term) -> 200 (creds: user01:password1)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body_like eval
qr/x-authenticated-groups: (Domain Admins,developers|developers,Domain Admins)\n/



=== TEST 29: user02 (superadmin only) fails the inner AND [Domain Admins, developers] -> 403 (creds: user02:password2)
--- request
GET /uri
--- more_headers
Authorization: ldap dXNlcjAyOnBhc3N3b3JkMg==
--- error_code: 403
--- response_body
{"message":"Forbidden"}



=== TEST 30: set up a groups_required route whose required name differs only by case
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



=== TEST 31: "domain admins" does NOT match the collected "Domain Admins" -> 403 (no case folding) (creds: user01:password1)
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



=== TEST 32: point a groups_required route at a dead LDAP port (transport-error case)
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



=== TEST 33: LDAP unreachable -> 500 and the outbound header is absent (creds: user02:password2)
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



=== TEST 34: consumer schema with group_dn only passes (oneOf alternate)
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



=== TEST 35: consumer schema with BOTH user_dn and group_dn is rejected (oneOf: exactly one)
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



=== TEST 36: set up the group-collection route (group_base_dn, service-account bind, consumer_required default true)
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
                    "bind_dn": "cn=admin,dc=example,dc=org",
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



=== TEST 37: reset to a clean Consumer set and create group_dn-only Consumers (maps on DNs)
--- config
    location /t {
        content_by_lua_block {
            local core = require("apisix.core")
            local t = require("lib.test_admin").test
            -- Drop any leftover user_dn Consumers (absent in a fresh etcd) so
            -- user01 has NO user_dn Consumer -- isolating the pure group_dn
            -- match that follows.
            for _, name in ipairs({ "ldapadvuser01", "ldapadvuser02",
                                    "ldapadvjdoe", "ldapadvsecret" }) do
                t('/apisix/admin/consumers/' .. name, ngx.HTTP_DELETE)
            end
            -- The Consumer group_dn matches group DNs, not names.
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



=== TEST 38: user01 (in Domain Admins, no user_dn Consumer) matches the group_dn Consumer -> 200 (creds: user01:password1)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAxOnBhc3N3b3JkMQ==
--- error_code: 200
--- response_body
hello world
--- error_log
find consumer ldapadvgrpadmins



=== TEST 39: user02 (in superadmin) matches a different group_dn Consumer -> 200 (two group Consumers coexist) (creds: user02:password2)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAyOnBhc3N3b3JkMg==
--- error_code: 200
--- response_body
hello world
--- error_log
find consumer ldapadvgrpsuper



=== TEST 40: add user_dn Consumers for user01 and jdoe (now both a user_dn and a group_dn Consumer could match)
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



=== TEST 41: user01 -- user_dn Consumer WINS over the group_dn Consumer (creds: user01:password1)
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



=== TEST 42: jdoe -- user_dn Consumer attaches while group_dn Consumers coexist (jdoe is in Domain Admins) (creds: jdoe:janesecret)
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



=== TEST 43: user02 -- still resolves via the superadmin group_dn Consumer (user_dn and group_dn sets coexist) (creds: user02:password2)
--- request
GET /hello
--- more_headers
Authorization: ldap dXNlcjAyOnBhc3N3b3JkMg==
--- error_code: 200
--- response_body
hello world
--- error_log
find consumer ldapadvgrpsuper



=== TEST 44: secretuser -- no user_dn Consumer and in NO group -> 401 (no match, consumer_required) (creds: secretuser:secretpass)
--- request
GET /hello
--- more_headers
Authorization: ldap c2VjcmV0dXNlcjpzZWNyZXRwYXNz
--- error_code: 401
--- grep_error_log eval
qr/no Consumer maps/
--- grep_error_log_out
no Consumer maps



=== TEST 45: consumer schema with NEITHER user_dn nor group_dn is rejected (oneOf: at least one required)
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



=== TEST 46: set up the unescape-observation routes (comma-in-cn group "Sales, EMEA")
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
                    "bind_dn": "cn=admin,dc=example,dc=org",
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
            -- X-Authenticated-Groups is observable in the body.
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



=== TEST 47: salesuser via the SEARCH path -- group NAME is the cn value "Sales, EMEA" (creds: salesuser:salespass)
--- request
GET /hello
--- more_headers
Authorization: ldap c2FsZXN1c2VyOnNhbGVzcGFzcw==
--- error_code: 200
--- response_body
hello world
--- error_log
groups: Sales, EMEA



=== TEST 48: salesuser via the memberOf path -- UNESCAPED first RDN equals the SEARCH-path name "Sales, EMEA" (creds: salesuser:salespass)
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



=== TEST 49: switch the memberOf-path /uri route to consumer_required (default true)
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



=== TEST 50: multiuser (in Domain Admins, no user_dn Consumer) matches the group_dn Consumer via the memberOf path -> 200 (creds: multiuser:multipass)
--- request
GET /uri
--- more_headers
Authorization: ldap bXVsdGl1c2VyOm11bHRpcGFzcw==
--- error_code: 200
--- error_log
find consumer ldapadvgrpadmins



=== TEST 51: consumer-miss on the memberOf path -- salesuser authenticates with a group but no Consumer maps -> 401, NO outbound header (creds: salesuser:salespass)
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
