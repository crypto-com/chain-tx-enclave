#!/bin/bash
set -e

source /root/.docker_bashrc

echo "[Config]SGX_MODE=${SGX_MODE}"
echo "[Config]NETWORK_ID=${NETWORK_ID}"

if [ x"${SGX_MODE}" == "xHW" ]; then
  LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service &
fi

trap 'kill -TERM $PID' TERM INT
./tx-validation-app tcp://0.0.0.0:${APP_PORT} &
PID=$!
wait $PID
wait $PID
exit $?
