#!/bin/bash

# generate signing public key for keyholder
cd trex-keyholder
cd bin
RUST_LOG=info ./cli -c ../service/src/config.yml -s ../service/src/seed.yml signing-pub-key

# fetch recent metadata from trex-node
cd ../../trex-account-funds
subxt metadata -f bytes > metadata.scale --url http://trex-node:9933/

# transfer from Alice to keyholder and cli-user,this function is only for dev chain.
./target/release/trex-account-funds -n ws://trex-node:9944 -t ../trex-keyholder/bin/tee_account_id.txt
./target/release/trex-account-funds -n ws://trex-node:9944 -t ../trex-keyholder/bin/tx_account_id.txt

sleep 5

# start keyholder service
cd ../trex-keyholder/bin
RUST_LOG=info ./trex-keyholder -c ../service/src/config.yml --skip-ra
