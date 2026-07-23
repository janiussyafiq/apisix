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

-- Helpers for the ldap-auth-advanced cache tests: manage the throwaway
-- cacheuser in the CI OpenLDAP container and issue authenticated requests.
local http = require("resty.http")

local _M = {}

local ADMIN = "-x -H ldap://127.0.0.1:1389 "
              .. "-D 'cn=admin,dc=example,dc=org' -w adminpassword"
local USER_DN = "cn=Cache User,ou=users,dc=example,dc=org"
-- resolve the container at run time: the compose project name (and so the
-- container name) differs between local runs and CI
local CONTAINER = "$(docker ps -qf name=openldap)"


function _M.delete_cacheuser()
    os.execute("docker exec " .. CONTAINER .. " ldapdelete " .. ADMIN
               .. " '" .. USER_DN .. "' >/dev/null 2>&1")
end


function _M.create_cacheuser()
    _M.delete_cacheuser()      -- delete-then-add is idempotent across re-runs
    os.execute("printf 'dn: " .. USER_DN .. "\\nobjectClass: inetOrgPerson"
               .. "\\ncn: Cache User\\nsn: User\\nuid: cacheuser"
               .. "\\nuserPassword: cachepass\\n' | docker exec -i "
               .. CONTAINER .. " ldapadd " .. ADMIN .. " >/dev/null 2>&1")
end


function _M.set_pw(pw)
    local ok = os.execute("printf 'dn: " .. USER_DN .. "\\nchangetype: modify"
               .. "\\nreplace: userPassword\\nuserPassword: " .. pw
               .. "\\n' | docker exec -i " .. CONTAINER .. " ldapmodify "
               .. ADMIN .. " >/dev/null 2>&1")
    -- assert the rotation applied, or stale-hit assertions false-pass
    assert(ok == 0 or ok == true, "ldapmodify failed to rotate cacheuser password")
end


function _M.req(port, path, pw)
    local hc = http.new()
    local res = hc:request_uri("http://127.0.0.1:" .. port .. path,
        { headers = { ["Authorization"] =
            "ldap " .. ngx.encode_base64("cacheuser:" .. pw) } })
    return res and res.status or 0
end


-- wait for the route's etcd sync before the first real request
function _M.wait_route(port, path)
    for _ = 1, 100 do
        local hc = http.new()
        local res = hc:request_uri("http://127.0.0.1:" .. port .. path)
        if res and res.status ~= 404 then
            return
        end
        ngx.sleep(0.1)
    end
end


return _M
