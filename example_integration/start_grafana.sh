#!/usr/bin/env bash

SCRIPT_PATH="$( cd "$(dirname "$0")" ; pwd -P )"

CONTAINER_NAME="dev-grafana"

docker ps | grep "${CONTAINER_NAME}"

if [ "$?" == "" ]
then
    docker kill "${CONTAINER_NAME}"
fi

docker rm "${CONTAINER_NAME}" > /dev/null

docker run -d --net host --name "${CONTAINER_NAME}" \
    -v ${SCRIPT_PATH}/ldap.toml:/etc/grafana/ldap.toml \
    -v ${SCRIPT_PATH}/grafana.ini:/etc/grafana/grafana.ini \
    grafana/grafana
