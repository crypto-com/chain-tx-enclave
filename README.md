<p align="center">
  <img src="https://avatars0.githubusercontent.com/u/41934032?s=400&v=4" alt="Crypto.com Chain" width="400">
</p>

<h2 align="center">(Work in Progress) <a href="https://crypto.com">Crypto.com<a> Chain Transaction Enclaves</h2

For more details, see the [Crypto.com Chain README](https://github.com/crypto-com/chain)

## Common Parameters

- `SGX_MODE`:
  - `SW` for Software Simulation mode
  - `HW` for Hardware mode
- `NETWORK_HEX_ID`: Network HEX Id of Tendermint
- `APP_PORT`: Listening Port inside the Docker instance (Default: 25933)

## Docker

### Build the Docker image
```bash
$ docker build -t chain-tx . \
--build-arg SGX_MODE=<SW|HW> \
--build-arg NETWORK_ID=<NETWORK_HEX_ID>
```

### Run the Docker instance

- Software Simulation Mode
```bash
# docker run --rm -p <HOST_PORT>:<DOCKER_APP_PORT> -rm chain-tx
$ docker run --rm \
-p 25933:25933 \
chain-tx
```

- Hardware Mode
```bash
# docker run --rm --device /dev/isgx -p <HOST_PORT>:<DOCKER_APP_PORT> chain-tx
$ docker run --rm \
--device /dev/isgx \
-p 25933:25933 \
chain-tx
```

### Run /bin/bash inside Docker instance

If you want to get your hands dirty, you can
```bash
$ docker run --rm \
chain-tx \
/bin/bash
```

## Build from Source Code

```bash
$ export SGX_MODE=<SW|HW>
$ export NETWORK_ID=<NETWORK_HEX_ID>
$ make
$ ./tx-validation/
```
