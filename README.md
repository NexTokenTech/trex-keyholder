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

## Unit Test
A number of unit tests cover the core functions around the enclave, the enclave runtime library needs to be built first 
before running the unit test. 

Since the makefile only build release binary, the cargo test shall use release mode. Use the following scripts to run unit tests.
```shell
make
cargo test --release
```

## CLI tool
A CLI tool is built to provide utilities for testing and basic operations.
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