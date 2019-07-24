FROM baiduxlab/sgx-rust:1604-1.0.8
LABEL maintainer="Crypto.com"

ARG SGX_MODE=SW
ARG NETWORK_ID

ENV SGX_MODE=${SGX_MODE}
ENV NETWORK_ID=${NETWORK_ID}
ENV APP_PORT=25933

RUN echo 'source /opt/sgxsdk/environment' >> /root/.docker_bashrc && \
    echo 'source /root/.cargo/env' >> /root/.docker_bashrc

# install zmq
RUN apt-get update && \
    apt-get install -y --no-install-recommends libzmq3-dev && \
    rm -rf /var/lib/apt/lists/*

# Build Transaction Enclave
COPY . .

RUN ["/bin/bash", "-c", "source /root/.docker_bashrc && make"]

WORKDIR /root/bin

CMD ["/bin/bash", "-c", "source /root/.docker_bashrc && ./tx-validation-app tcp://0.0.0.0:${APP_PORT}"]
