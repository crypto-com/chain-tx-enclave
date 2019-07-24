#!/bin/bash

source /root/.docker_bashrc

trap 'kill -TERM $PID; wait $PID' TERM INT
./tx-validation-app tcp://0.0.0.0:${APP_PORT} &
PID=$!
wait $PID
wait $PID
exit $?
