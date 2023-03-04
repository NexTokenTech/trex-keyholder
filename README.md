# TREX - Key-holder Service Node
The key-holder nodes for TREX network is a critical infra for decentralized-timed release encryption.

## Installation
It is necessary to have CPUs supporting Intel SGX technology for running key-holder service node.
### Enable SGX Supports on BIOS
Updated the BIOS on your machine to its latest version and enable the SGX supports on BIOS.

### Setup Intel SGX Driver and SDK
The SGX driver is embedded with Linux kernel for Ubuntu 22.04. It is suggested to build executables 
on Ubuntu 22.04. Use below link to install the build dependencies and SDK.

[SGX SDK & PSW installation for Ubuntu 22.04](https://medium.com/@yangfanghao/sgx-driver-and-sdk-installation-for-ubuntu-22-04-7db6c254e65c)

### Build
Clone the source code to your local disk and run Makefile to build all components.
```shell
git clone https://github.com/NexTokenTech/trex-keyholder.git
cd trex-keyholder
make
```

## Deployment
Once the executable and signed enclave library was build, they were copied to the "./bin" subdirectory.
Then, you may run the service giving the configuration file path. For example:
```shell
cd bin
RUST_LOG=info ./trex-keyholder -c ../service/src/config.yml
```
The default configuration file is included within the source code, and you may use other configuration 
based on the environment and requirements.

If you want to run the service without remote attestation verify,you can run:
```
cd bin
RUST_LOG=info ./trex-keyholder -c ../service/src/config.yml --skip-ra
```
### Build Docker Images
There is a docker file `/docker/builder.Dockerfile` to build a builder image for keyholder executables.
```shell
docker build -f docker/builder.Dockerfile -t trex-keyholder:builder .
```
Another docker file is to build the executables.
```shell
docker build -f docker/keyholder.Dockerfile -t trex-keyholder:latest .
```
For software-simulated test mode, you may use the test dockerfile to build a test image.
```shell
docker build -f docker/keyholder.Dockerfile -t trex-keyholder:test .
```
### Run in Docker
You may pull the latest image from a public container registry instead of building it by yourself. 
Use the following command to pull a pre-built image.

For development and base builder:
```shell
docker pull docker pull trexnode.azurecr.io/keyholder:builder
```
For deployment:
```shell
docker pull docker pull trexnode.azurecr.io/keyholder:latest
```
For test:
```shell
docker pull docker pull trexnode.azurecr.io/keyholder:test
```
Remember to sign out with docker logout from your existing login credentials if you have errors.

You may start a local network with SGX hardware supports:
```shell
docker compose up -d
```

## Unit Test
A number of unit tests cover the core functions around the enclave, the enclave runtime library needs to be built first 
before running the unit test. 

Since the makefile only build release binary, the cargo test shall use release mode. Use the following scripts to run unit tests.
```shell
make
cargo test --release
```

### Unit test in a container
For dev and test, we provide a docker image for run the unit test inside a docker image.
Build the docker image as mentioned above and use the following method to run the unit test.
You may pull a pre-built image "trexnode.azurecr.io/keyholder:test" from a public registry instead build it by yourself.
```shell
docker run -it trex-keyholder:test
root@xxxxxx:~# cd trex-keyholder/bin && cargo test
```

## Integration Test
There is a test CLI tool to test the integration between the keyholder node and TREX node. The CLI tool will simulate a client to send an encrypted message
to the keyholder and wait a couple of seconds until it decrypted. Then, get the decrypted message and compare with the
original one.

This test requires to deploy a local network and test the keyholder alongside a TREX node.
There is a docker compose file to get it setup and run. 
```shell
 docker compose -f docker-compose.test.yml up -d
```
Then, you need to use the CLI tool to test it.
```shell
docker attach cli
root@xxxxxx:~# cd trex-keyholder/bin && RUST_LOG=info ./cli -c ../service/src/config.yml -s ../service/src/seed.yml test
```
The integration test is successful if there is no panic or error on the screen.

## Keyholder CLI tool
A CLI tool is built to provide utilities for basic operations on the keyholder node.
### Runtime API Test
The dev test function uses a well-know account for testing purpose in runtime. The well-known seed is in the 
local yaml file "seed.yml" for testing and dev purposes.
Use below command to initialize and send a TREX data for test.
```shell
RUST_LOG=info ./cli -c ../service/src/config.yml -s ../service/src/seed.yml test
```
### Generate account ID for the key-holder node
The key-holder node needs an on-chain account to register the enclave and publish remote attestation
report. The account ID can be access by following commends.
```shell
RUST_LOG=info ./cli -c ../service/src/config.yml signing-pub-key
```
### Check account balance for the key-holder node
To put the RA report on chain, the key-holder needs tokens to pay for the fee. Use this command to make
sure that your key-holder node has enough balance. If the balance is not enough, your key-holder node
may not be able to register on the TREX network.
```shell
RUST_LOG=info ./cli -c ../service/src/config.yml get-free-balance
```

### Generate shielding key
You may generate the shielding key locally to communicate with the enclave. The shielding key is contained
in the TEE on-chain runtime data so that clients can request the shielding key.
```shell
RUST_LOG=info ./cli -c ../service/src/config.yml shielding-pub-key
```