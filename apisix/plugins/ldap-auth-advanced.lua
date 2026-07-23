--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local core = require("apisix.core")
local schema_def = require("apisix.schema_def")
local auth_utils = require("apisix.utils.auth")
local consumer_mod = require("apisix.consumer")
local ldap_client = require("resty.ldap.client")
local ldap_protocol = require("resty.ldap.protocol")
local ldap_filter = require("resty.ldap.filter")
local resty_sha256 = require("resty.sha256")
local resty_lrucache = require("resty.lrucache")
local to_hex = require("resty.string").to_hex
local ngx = ngx
local ipairs = ipairs
local pairs = pairs
local type = type
local ngx_decode_base64 = ngx.decode_base64
local ngx_re_match = ngx.re.match
local str_find = string.find
local str_sub = string.sub
local str_byte = string.byte
local str_char = string.char
local str_gsub = string.gsub
local str_lower = string.lower
local table_concat = table.concat
local parse_addr = core.utils.parse_addr

-- RFC 4512 attribute-description shape: a leading letter, then letters,
-- digits, semicolons (option separators) or hyphens.
local ATTR_PATTERN = "^[A-Za-z][A-Za-z0-9;-]*$"

local schema = {
    type = "object",
    title = "work with route or service object",
    properties = {
        -- connection
        ldap_uri     = { type = "string" },                        -- "host[:port]"
        use_ldaps    = { type = "boolean", default = false },
        use_starttls = { type = "boolean", default = false },
        ssl_verify   = { type = "boolean", default = true },
        timeout      = { type = "integer", minimum = 1, maximum = 60000,
                         default = 3000 },                          -- milliseconds

        -- connection pool
        keepalive           = { type = "boolean", default = true },
        keepalive_timeout   = { type = "integer", minimum = 1000, default = 60000 },
        keepalive_pool_size = { type = "integer", minimum = 1, default = 5 },
        keepalive_pool_name = { type = "string" },

        -- user resolution (search-then-bind)
        base_dn       = { type = "string" },                       -- search root
        attribute     = { type = "string",                         -- filter: (attribute=username)
                          default = "cn", pattern = ATTR_PATTERN },
        bind_dn       = { type = "string" },                       -- absent => anonymous search
        ldap_password = { type = "string" },

        -- search bounds
        size_limit = { type = "integer", minimum = 2, default = 2 },
        time_limit = { type = "integer", minimum = 0, default = 5 }, -- seconds; 0 = server default

        -- groups
        group_base_dn = { type = "string" },  -- absent => memberOf attribute path
        group_name_attribute = { type = "string", default = "cn", pattern = ATTR_PATTERN },
        group_member_attribute = { type = "string", default = "member", pattern = ATTR_PATTERN },
        user_membership_attribute = { type = "string", default = "memberOf",
                                      pattern = ATTR_PATTERN },

        -- authorization: outer array ORs, inner array ANDs
        groups_required = {
            type = "array", minItems = 1,
            items = { type = "array", minItems = 1, items = { type = "string" } },
        },

        -- consumer
        consumer_required  = { type = "boolean", default = true },
        anonymous_consumer = schema_def.anonymous_consumer_schema,

        -- request handling
        header_type      = { type = "string", enum = {"ldap", "basic"}, default = "ldap" },
        hide_credentials = { type = "boolean", default = false },
        realm            = schema_def.get_realm_schema("ldap"),

        -- observability
        cache_ttl  = { type = "integer", minimum = 0, default = 60 },   -- seconds
        ldap_debug = { type = "boolean", default = false },
    },
    encrypt_fields = {"ldap_password"},
    required = {"ldap_uri", "base_dn"},
}

local consumer_schema = {
    type = "object",
    title = "work with consumer object",
    properties = {
        user_dn  = { type = "string" },
        group_dn = { type = "string" },
    },
    -- exactly one of user_dn / group_dn per Consumer
    oneOf = { {required = {"user_dn"}}, {required = {"group_dn"}} },
}

local plugin_name = "ldap-auth-advanced"


local _M = {
    version = 0.1,
    priority = 2541,
    type = 'auth',
    name = plugin_name,
    schema = schema,
    consumer_schema = consumer_schema,
}

function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_CONSUMER then
        return core.schema.check(consumer_schema, conf)
    end

    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end

    if conf.use_ldaps and conf.use_starttls then
        return false, "use_ldaps and use_starttls are mutually exclusive"
    end

    if conf.bind_dn and not conf.ldap_password then
        return false, "ldap_password is required when bind_dn is set"
    end

    -- ldap_uri may omit ":port"; the effective port (636 with use_ldaps,
    -- else 389) is resolved when the connection is opened.

    return true
end

-- ctx key recording which header (Proxy-Authorization or Authorization)
-- carried the credentials, so hide_credentials strips exactly that one.
local CRED_HEADER_CTX_KEY = "ldap_auth_advanced_cred_header"


local function strip_credential_header(conf, ctx)
    if not conf.hide_credentials then
        return
    end
    local header = ctx[CRED_HEADER_CTX_KEY]
    if header then
        core.request.set_header(ctx, header, nil)
    end
end


-- Shared 401 helper for the authentication-failure paths. When
-- anonymous_consumer is set, attach the anonymous Consumer instead of
-- returning 401; authorization (403) and transport (500) failures never
-- fall back to it.
local function auth_failed(conf, ctx, reason)
    if conf.anonymous_consumer then
        local anon, anon_conf, cerr =
            consumer_mod.get_anonymous_consumer(conf.anonymous_consumer)
        if anon then
            strip_credential_header(conf, ctx)
            consumer_mod.attach_consumer(ctx, anon, anon_conf)
            return
        end
        core.log.error(plugin_name, ": failed to get anonymous consumer ",
                       conf.anonymous_consumer, ": ", cerr or "not found")
    end

    -- under multi-auth, decline quietly and let the wrapper render the 401
    if auth_utils.is_running_under_multi_auth(ctx) then
        return 401
    end

    if reason then
        core.log.warn(plugin_name, ": ", reason)
    end
    core.response.set_header("WWW-Authenticate",
                             conf.header_type .. " realm=\"" .. conf.realm .. "\"")
    return 401, { message = "Authorization required" }
end


-- groups_required denial: an already-authenticated user failing authorization
-- gets a real 403 -- never a 401 and never the anonymous_consumer fallback.
local function forbidden(reason)
    if reason then
        core.log.warn(plugin_name, ": ", reason)
    end
    return 403, { message = "Forbidden" }
end


-- groups_required is an outer OR of inner ANDs, matched against the collected
-- group names verbatim (no case folding, no trimming).
local function groups_satisfied(groups_required, groups)
    local have = {}
    for i = 1, #groups do
        have[groups[i].name] = true
    end
    for _, inner in ipairs(groups_required) do
        local all = true
        for _, name in ipairs(inner) do
            if not have[name] then
                all = false
                break
            end
        end
        if all then
            return true
        end
    end
    return false
end


-- Extract username/password from the credential header: the scheme word is
-- conf.header_type ("ldap" or "basic", case-insensitive), the payload is
-- base64("username:password").
local function extract_credentials(conf, ctx)
    -- Proxy-Authorization is checked before Authorization
    local header_name = "Proxy-Authorization"
    local auth_header = core.request.header(ctx, header_name)
    if not auth_header then
        header_name = "Authorization"
        auth_header = core.request.header(ctx, header_name)
    end
    if not auth_header then
        return nil, nil, "missing authorization header"
    end
    ctx[CRED_HEADER_CTX_KEY] = header_name

    local m, err = ngx_re_match(auth_header,
                                "(?i:" .. conf.header_type .. ")\\s(.+)", "jo")
    if err then
        return nil, nil, "error matching authorization header: " .. err
    end
    if not m then
        return nil, nil, "invalid authorization header format"
    end

    local decoded = ngx_decode_base64(m[1])
    if not decoded then
        return nil, nil, "failed to base64-decode authorization header"
    end

    -- split on the FIRST colon only: the password may itself contain ':'
    local sep = str_find(decoded, ":", 1, true)
    if not sep then
        return nil, nil, "invalid credential: missing ':' separator"
    end

    return str_sub(decoded, 1, sep - 1), str_sub(decoded, sep + 1)
end


-- Tell a directory result-code failure (an auth failure -> 401) apart from a
-- socket/TLS/timeout error (an outage -> 500) by the library's error prefixes.
-- connect() only ever fails on transport.
local function is_result_code_failure(err)
    if type(err) ~= "string" then
        return false
    end
    return str_sub(err, 1, 18) == "simple bind failed"
        or str_sub(err, 1, 13) == "search failed"
end


-- Attribute lookup with a case-insensitive fallback: the server may echo the
-- requested descriptor in a different case.
local function attr_values(attributes, name)
    if not attributes then
        return nil
    end
    local vals = attributes[name]
    if vals then
        return vals
    end
    local lname = str_lower(name)
    for k, v in pairs(attributes) do
        if str_lower(k) == lname then
            return v
        end
    end
    return nil
end


-- Decode a hex digit byte to its value, or nil if it is not [0-9A-Fa-f].
local function hex_nibble(b)
    if b >= 48 and b <= 57 then       -- '0'-'9'
        return b - 48
    elseif b >= 65 and b <= 70 then   -- 'A'-'F'
        return b - 55
    elseif b >= 97 and b <= 102 then  -- 'a'-'f'
        return b - 87
    end
    return nil
end


-- Reverse RFC 4514 RDN-value escaping ("\2C" or "\," -> the literal char) so
-- group names taken from a DN match the unescaped attribute values byte for
-- byte. A value with no backslash is returned unchanged.
local function unescape_rdn_value(v)
    if not str_find(v, "\\", 1, true) then
        return v
    end
    local out = {}
    local i = 1
    local n = #v
    while i <= n do
        local b = str_byte(v, i)
        if b == 92 and i < n then          -- '\' escapes what follows
            local h1 = hex_nibble(str_byte(v, i + 1))
            local h2 = i + 2 <= n and hex_nibble(str_byte(v, i + 2))
            if h1 and h2 then
                out[#out + 1] = str_char(h1 * 16 + h2)
                i = i + 3
            else
                out[#out + 1] = str_sub(v, i + 1, i + 1)
                i = i + 2
            end
        else
            out[#out + 1] = str_sub(v, i, i)
            i = i + 1
        end
    end
    return table_concat(out)
end


-- The value of a DN's first RDN, unescaped, e.g.
-- "cn=Domain Admins,ou=groups,..." -> "Domain Admins".
local function first_rdn_value(dn)
    local eq = str_find(dn, "=", 1, true)
    if not eq then
        return dn
    end
    local i = eq + 1
    local n = #dn
    while i <= n do
        local b = str_byte(dn, i)
        if b == 92 then           -- '\' escapes the next byte
            i = i + 2
        elseif b == 44 then       -- ',' ends the first RDN
            return unescape_rdn_value(str_sub(dn, eq + 1, i - 1))
        else
            i = i + 1
        end
    end
    return unescape_rdn_value(str_sub(dn, eq + 1))
end


-- Map group search entries to {dn, name} pairs; when an entry did not carry
-- the name attribute, fall back to its DN's first RDN value.
local function collect_search_groups(entries, name_attr)
    local groups = {}
    for _, entry in ipairs(entries) do
        if entry.entry_dn then
            local vals = attr_values(entry.attributes, name_attr)
            groups[#groups + 1] = {
                dn = entry.entry_dn,
                name = (vals and vals[1]) or first_rdn_value(entry.entry_dn),
            }
        end
    end
    return groups
end


-- Each membership-attribute value on the user entry is a group DN; its name
-- is the DN's first RDN value. No extra LDAP round trip.
local function collect_membership_groups(user_entry, member_attr)
    local groups = {}
    local vals = attr_values(user_entry.attributes, member_attr)
    if vals then
        for _, dn in ipairs(vals) do
            groups[#groups + 1] = { dn = dn, name = first_rdn_value(dn) }
        end
    end
    return groups
end


-- Strip CR/LF and other control bytes from a group name before it is joined
-- into the X-Authenticated-Groups header (header-injection defense). Group
-- matching always uses the raw name, never this sanitized copy.
local function sanitize_group_name(name)
    return (str_gsub(name, "[%z\1-\31]", ""))
end


-- Build the user_dn and group_dn lookup maps in one pass over the Consumers.
-- consumer_mod.consumers_kv() cannot serve two match attributes, so the maps
-- are built here and cached against the Consumer config version.
local consumer_lrucache = core.lrucache.new({ ttl = 300, count = 512 })

local function build_consumer_maps(consumer_conf)
    local by_user_dn = {}
    local by_group_dn = {}
    for _, node in ipairs(consumer_conf.nodes) do
        local auth_conf = node.auth_conf
        if auth_conf then
            if auth_conf.user_dn then
                by_user_dn[auth_conf.user_dn] = node
            elseif auth_conf.group_dn then
                by_group_dn[auth_conf.group_dn] = node
            end
        end
    end
    return { by_user_dn = by_user_dn, by_group_dn = by_group_dn }
end


-- Credential-resolution cache: successful LDAP resolutions only.
-- Authorization and the Consumer decision are never cached -- they re-run on
-- every request. Raw resty.lrucache so the per-entry TTL is exactly
-- conf.cache_ttl.
local cache = resty_lrucache.new(1024)


-- The cache key carries a one-way hash of the password; the raw password is
-- never stored, keyed on, or logged.
local function sha256_hex(s)
    local h = resty_sha256:new()
    h:update(s)
    return to_hex(h:final())
end


-- The LDAP round trip: resolve the user DN, authenticate the user's bind and
-- collect the groups on ONE pinned connection. Returns (nil, nil, user_dn,
-- groups) on success, or (code, body) on failure. The socket is closed on
-- every failure path and released to the pool only on success, so a poisoned
-- socket is never pooled.
local function ldap_resolve(conf, ctx, username, password)
    -- The only client-controlled part of the search filter is the escaped
    -- username. filter.escape leaves bytes the filter grammar rejects (e.g.
    -- invalid UTF-8), and a grammar reject at search time would surface as a
    -- 500 -- misclassifying a bad credential as a server fault. Pre-compile
    -- the filter so any reject is a clean 401.
    local search_filter = "(" .. conf.attribute .. "="
                          .. ldap_filter.escape(username) .. ")"
    if not ldap_filter.compile(search_filter) then
        return auth_failed(conf, ctx, "invalid username")
    end

    -- ldap_uri is "host" or "host:port"; when the port is omitted it
    -- defaults to 636 under LDAPS, else 389.
    local host, port = parse_addr(conf.ldap_uri)
    if not port then
        port = conf.use_ldaps and 636 or 389
    end

    local client = ldap_client:new(host, port, {
        socket_timeout      = conf.timeout,
        keepalive_timeout   = conf.keepalive_timeout,
        keepalive_pool_size = conf.keepalive_pool_size,
        keepalive_pool_name = conf.keepalive_pool_name,
        start_tls           = conf.use_starttls,
        ldaps               = conf.use_ldaps,
        ssl_verify          = conf.ssl_verify,
    })

    local ok, cerr = client:connect()
    if not ok then
        -- connect() fails only on a socket/TLS error: an outage, never auth
        core.log.error(plugin_name, ": LDAP connect failed: ", cerr)
        client:close()
        return 500
    end

    -- Bind before every search: a pooled socket may arrive bound as a
    -- previous request's end user. Anonymous bind when bind_dn is unset.
    local bind_ok, berr
    if conf.bind_dn then
        bind_ok, berr = client:simple_bind(conf.bind_dn, conf.ldap_password)
    else
        bind_ok, berr = client:simple_bind("", "")
    end
    if not bind_ok then
        client:close()
        if is_result_code_failure(berr) then
            -- a rejected search bind is a misconfiguration; fail closed
            return auth_failed(conf, ctx, "search bind rejected by directory")
        end
        core.log.error(plugin_name, ": LDAP search bind failed: ", berr)
        return 500
    end

    -- Search for the user. Request user_membership_attribute so the memberOf
    -- group path can read it off this same entry with no extra round trip.
    -- size_limit floors at 2 (schema minimum) so a 2nd match is observable.
    local entries, serr = client:search(
        conf.base_dn,
        ldap_protocol.SEARCH_SCOPE_WHOLE_SUBTREE,
        ldap_protocol.SEARCH_DEREF_ALIASES_ALWAYS,
        conf.size_limit, conf.time_limit,
        false,
        search_filter,
        { conf.user_membership_attribute })
    if entries == false then
        client:close()
        if is_result_code_failure(serr) then
            return auth_failed(conf, ctx, "user search rejected by directory")
        end
        core.log.error(plugin_name, ": LDAP user search failed: ", serr)
        return 500
    end

    -- count SearchResultEntry rows (the library drops SearchResultDone)
    local user_dn
    local user_entry
    local match_count = 0
    for _, entry in ipairs(entries) do
        if entry.entry_dn then
            match_count = match_count + 1
            user_dn = entry.entry_dn
            user_entry = entry
        end
    end
    if match_count == 0 then
        client:close()
        return auth_failed(conf, ctx, "user not found")
    end
    if match_count > 1 then
        -- the login attribute is not unique under base_dn: a directory
        -- misconfiguration. Fail closed rather than bind an arbitrary entry.
        client:close()
        return auth_failed(conf, ctx,
                           "ambiguous user match (>1 entry); check attribute uniqueness")
    end

    -- Authenticate: bind as the resolved user. A result-code failure is a
    -- wrong password (401); a transport error is an outage (500).
    local auth_ok, aerr = client:simple_bind(user_dn, password)
    if not auth_ok then
        client:close()
        if is_result_code_failure(aerr) then
            return auth_failed(conf, ctx, "user authentication failed")
        end
        core.log.error(plugin_name, ": LDAP authentication bind failed: ", aerr)
        return 500
    end

    -- Collect the authenticated user's groups on the same pinned socket. Two
    -- sources: a live search under group_base_dn, or the membership attribute
    -- already fetched with the user entry.
    local groups
    if conf.group_base_dn then
        -- The socket is currently bound as the END USER. Re-bind as the
        -- configured identity (service account, or anonymous when bind_dn is
        -- unset) so the group search never runs under the caller.
        local rb_ok, rberr
        if conf.bind_dn then
            rb_ok, rberr = client:simple_bind(conf.bind_dn, conf.ldap_password)
        else
            rb_ok, rberr = client:simple_bind("", "")
        end
        if not rb_ok then
            client:close()
            if is_result_code_failure(rberr) then
                return auth_failed(conf, ctx, "group-search re-bind rejected by directory")
            end
            core.log.error(plugin_name, ": LDAP group-search re-bind failed: ", rberr)
            return 500
        end

        local group_filter = "(" .. conf.group_member_attribute .. "="
                             .. ldap_filter.escape(user_dn) .. ")"
        -- The group search is unbounded (LDAP sizeLimit 0; the directory's
        -- own server limit still applies): conf.size_limit bounds only the
        -- user-search ambiguity check, and capping here would silently drop
        -- a user's groups past the 2nd.
        local gentries, gerr = client:search(
            conf.group_base_dn,
            ldap_protocol.SEARCH_SCOPE_WHOLE_SUBTREE,
            ldap_protocol.SEARCH_DEREF_ALIASES_ALWAYS,
            0, conf.time_limit,
            false,
            group_filter,
            { conf.group_name_attribute })
        if gentries == false then
            client:close()
            if is_result_code_failure(gerr) then
                return auth_failed(conf, ctx, "group search rejected by directory")
            end
            core.log.error(plugin_name, ": LDAP group search failed: ", gerr)
            return 500
        end
        groups = collect_search_groups(gentries, conf.group_name_attribute)
    else
        groups = collect_membership_groups(user_entry, conf.user_membership_attribute)
    end

    if conf.keepalive == false then
        client:close()
    else
        client:set_keepalive()
    end

    return nil, nil, user_dn, groups
end


function _M.rewrite(conf, ctx)
    -- Strip any client-supplied X-Authenticated-Groups before any auth work;
    -- the outbound header is written only after auth and authorization pass.
    core.request.set_header(ctx, "X-Authenticated-Groups", nil)

    local username, password, err = extract_credentials(conf, ctx)
    if err then
        return auth_failed(conf, ctx, err)
    end

    -- A zero-length password would be an RFC 4513 5.1.2 unauthenticated bind,
    -- which authenticates anyone whose username resolves. Reject before any
    -- bind can be attempted.
    if password == "" then
        return auth_failed(conf, ctx, "empty password rejected before bind")
    end

    if username == "" then
        return auth_failed(conf, ctx, "empty username")
    end

    -- Cache lookup. cache_ttl == 0 disables read AND write. plugin_ctx_id
    -- folds the plugin's conf identity + conf_version into the key, so a
    -- config change (or a different route) yields a different key.
    local cache_key
    if conf.cache_ttl and conf.cache_ttl > 0 then
        cache_key = core.lrucache.plugin_ctx_id(ctx,
                        username .. ":" .. sha256_hex(password))
    end

    local user_dn, groups
    local hit = cache_key and cache:get(cache_key)
    if hit then
        -- reuse the cached LDAP resolution (no connection is opened);
        -- authorization and the Consumer decision below still re-run
        user_dn = hit.user_dn
        groups = hit.groups
    else
        local code, body
        code, body, user_dn, groups = ldap_resolve(conf, ctx, username, password)
        if code then
            return code, body
        end
        -- Neither a status nor a user_dn: the auth failure was absorbed by
        -- the anonymous_consumer fallback inside auth_failed. Proceed as the
        -- anonymous identity -- no groups header, no cache write.
        if not user_dn then
            return
        end
        -- Cache the successful resolution only; no failure path reaches
        -- here. The groups table is stored by reference and reused on every
        -- hit; it is only read after collection, never mutated.
        if cache_key then
            cache:set(cache_key, { user_dn = user_dn, groups = groups }, conf.cache_ttl)
        end
    end

    -- The collected group names are directory data, so the log is gated
    -- behind ldap_debug; the password is never logged at any level.
    local names = {}
    for i = 1, #groups do
        names[i] = sanitize_group_name(groups[i].name)
    end
    if conf.ldap_debug then
        core.log.warn(plugin_name, ": groups: ", table_concat(names, ","))
    end

    -- Authorize against groups_required: absent -> any authenticated user
    -- passes; unsatisfied -> 403, never a 401 or the anonymous fallback.
    if conf.groups_required and not groups_satisfied(conf.groups_required, groups) then
        return forbidden("groups_required not satisfied")
    end

    -- Associate a Consumer with the authenticated identity, unless
    -- consumer_required is false.
    if conf.consumer_required ~= false then
        local consumer_conf = consumer_mod.consumers_conf(plugin_name)
        if not consumer_conf or not consumer_conf.nodes then
            return auth_failed(conf, ctx, "consumer_required but no Consumer is configured")
        end

        local maps = consumer_lrucache(consumer_conf, consumer_conf.conf_version,
                                       build_consumer_maps, consumer_conf)

        -- A user_dn Consumer wins; otherwise take the first collected group
        -- whose DN maps to a Consumer, in collection order.
        local consumer = maps.by_user_dn[user_dn]
        if not consumer then
            for i = 1, #groups do
                consumer = maps.by_group_dn[groups[i].dn]
                if consumer then
                    break
                end
            end
        end
        if not consumer then
            return auth_failed(conf, ctx,
                               "no Consumer maps to the authenticated user_dn or group_dn")
        end

        consumer_mod.attach_consumer(ctx, consumer, consumer_conf)
    end

    -- The sole place the outbound X-Authenticated-Groups header is written --
    -- reached only after authentication AND authorization pass, so it is
    -- absent on every 401/403/500 path. Comma-separated, collection order.
    core.request.set_header(ctx, "X-Authenticated-Groups", table_concat(names, ","))

    -- drop the credential header consumed at extraction (hide_credentials)
    strip_credential_header(conf, ctx)
end

return _M
