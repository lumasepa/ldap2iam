#!/usr/bin/env bash

SCRIPT_PATH="$( cd "$(dirname "$0")" ; pwd -P )"

${SCRIPT_PATH}/start_grafana.sh
${SCRIPT_PATH}/start_vault.sh

${SCRIPT_PATH}/ldap2vault -c ${SCRIPT_PATH}/ldap2vault.conf.yaml