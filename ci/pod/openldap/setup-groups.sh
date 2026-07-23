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
# /docker-entrypoint-initdb.d, after the /ldifs bootstrap tree is loaded).
#
# The plugin resolves a user's groups two ways, and this hook makes both
# observable:
#   1. SEARCH path  -- (member=<user_dn>) under ou=groups returns the groups.
#   2. memberOf path -- the memberof overlay back-populates memberOf on users.
#
# The memberof overlay only auto-populates memberOf for member links added
# AFTER it becomes active. Bitnami loads /ldifs (ad.ldif) during ldap_initialize
# and runs this hook afterwards, so we MUST activate the overlay here and only
# then add the group entries -- if the groups were in /ldifs their member links
# would predate the overlay and memberOf would stay empty. Loading the groups
# after activation also keeps the pre-existing cn=readers group (from ad.ldif,
# loaded before this hook) out of memberOf, so both group-source paths agree.

set -o errexit
set -o nounset
set -o pipefail

. /opt/bitnami/scripts/liblog.sh
. /opt/bitnami/scripts/libopenldap.sh

eval "$(ldap_env)"

ldap_start_bg

info "Activating the memberof + refint overlays (before any group member links)"

ldapadd -Y EXTERNAL -H "ldapi:///" -f /overlays/memberof.ldif

info "Loading authorization groups (overlay now back-populates memberOf)"

ldapadd -H "ldapi:///" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASSWORD" -f /overlays/groups.ldif

ldap_stop
