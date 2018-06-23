#!/usr/bin/env bash

SCRIPT_PATH="$( cd "$(dirname "$0")" ; pwd -P )"

CONTAINER_NAME="dev-vault"

docker ps | grep "${CONTAINER_NAME}"

if [ "$?" != "0" ]
then
    docker kill "${CONTAINER_NAME}"
fi

docker rm "${CONTAINER_NAME}" > /dev/null

docker run --net host --cap-add=IPC_LOCK -d --name=${CONTAINER_NAME} vault

