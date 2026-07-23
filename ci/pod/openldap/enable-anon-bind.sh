#!/bin/bash
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
# Runs once on a fresh Bitnami OpenLDAP boot (mounted into
# /docker-entrypoint-initdb.d). At this stage slapd is stopped, so we start it
# in the background with the bitnami helpers, enable RFC 4513 s5.1.2
# unauthenticated bind, then stop it again before the container's foreground
# slapd starts.
#
# olcAllows: bind_anon_dn makes a simple bind with a non-empty DN and a
# zero-length password SUCCEED at the server (result: anonymous). This is the
# flag that governs "DN present, password empty" -- bind_anon_cred governs the
# opposite case (empty DN, non-empty credentials) and does NOT enable this.
# The permissive directory lets the plugin's INV-1 test prove that the *plugin*
# rejects empty passwords even against a server that would accept the bind.
#
# It also installs two identity-dependent olcAccess observables on the data
# database:
#   * cn=Secret User is invisible to an anonymous search yet readable by any
#     authenticated identity -- the observable that the concurrent
#     bind-state-leak probe (INV-2/INV-3) asserts on: a (uid=secretuser) search
#     resolves only when the pinned socket is bound as a real identity.
#   * the `member` attribute of the ou=groups entries is readable by anonymous
#     (the configured group-search identity) but NOT by a regular authenticated
#     end user -- the observable that the INV-4 test asserts on: after step 4
#     the pinned socket is bound as the END USER, so a group search that skipped
#     the step-5 re-bind would run as that end user and (member=<user_dn>) would
#     match nothing. The group cn (and every other attribute) stays readable to
#     all, so only the membership matching is gated on the bind identity. The
#     rootdn (cn=amdin) bypasses ACLs entirely, so a service-account re-bind
#     reads member as well.
# The final catch-all rule preserves the prior default (read to all) for every
# other entry and attribute, so the ldap-auth regression, the stock user01/
# user02 logins, and the memberOf attribute on user entries are all unaffected.
# anonymous keeps `auth` on the secret entry's userPassword so the entry can
# still be bound once an authenticated search has resolved it.

set -o errexit
set -o nounset
set -o pipefail

. /opt/bitnami/scripts/liblog.sh
. /opt/bitnami/scripts/libopenldap.sh

eval "$(ldap_env)"

info "Enabling RFC 4513 unauthenticated bind (olcAllows: bind_anon_dn)"

ldap_start_bg

ldapmodify -Y EXTERNAL -H "ldapi:///" <<EOF
dn: cn=config
changetype: modify
add: olcAllows
olcAllows: bind_anon_dn
EOF

info "Installing the bind-identity olcAccess rule on the data database"

# Resolve the data database DN by suffix so we do not hard-code the {N} index.
DATA_DB_DN="$(ldapsearch -Y EXTERNAL -H "ldapi:///" -b cn=config \
    "(olcSuffix=dc=example,dc=org)" dn 2>/dev/null \
    | awk '/^dn:/ { $1=""; sub(/^ /,""); print; exit }')"

ldapmodify -Y EXTERNAL -H "ldapi:///" <<EOF
dn: ${DATA_DB_DN}
changetype: modify
replace: olcAccess
olcAccess: {0}to dn.exact="cn=Secret User,ou=users,dc=example,dc=org" attrs=userPassword by anonymous auth by users read by * none
olcAccess: {1}to dn.exact="cn=Secret User,ou=users,dc=example,dc=org" by users read by * none
olcAccess: {2}to dn.subtree="ou=groups,dc=example,dc=org" attrs=member by anonymous read by users none
olcAccess: {3}to * by * read
EOF

ldap_stop
