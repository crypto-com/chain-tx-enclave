# Crypto.com Chain Transaction Enclaves
See the [main repository's README](https://github.com/crypto-com/chain)

```
docker build -t chain-tx .

```

Simulation mode (set SGX_MODE ?= SW in Makefile):
```
docker run -ti --rm  -v ~/chain-tx-enclave/:/root/sgx -it chain-tx /bin/bash
```

Hardware mode (set SGX_MODE ?= HW in Makefile):
```
docker run -ti --device /dev/isgx -v ~/chain-tx-enclave/:/root/sgx -it chain-tx /bin/bash

root@docker:/# LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service &
```

Build:
```
cd sgx

SGX_MODE = [SW|HW] NETWORK_ID = <NETWORK_HEX_ID> make
```