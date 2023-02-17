#!/bin/bash
for parm in "$@"
do
   key=`echo ${parm%%=*}`
   value=`echo ${parm#*=}`
   if [ $key == "--node_ip" ];then
      export NODE_IP=$value
   fi
done
echo $NODE_IP

apt update
apt install clang
clang --version
curl -sSf https://sh.rustup.rs | sh -s -- --default-toolchain none -y
source "$HOME/.cargo/env"
rustup show
rustup default nightly
rustup --version

SGX_MODE=SW make
cd bin
RUST_LOG=info ./cli -c ../service/src/config.yml signing-pub-key

cd ../trex-account-funds
cargo install subxt-cli
subxt metadata -f bytes > metadata.scale --url http://$NODE_IP:9933/
./target/release/trex-account-funds -n ws://$NODE_IP:9944 -t ../trex-keyholder/bin/tee_account_id.txt
./target/release/trex-account-funds -n ws://$NODE_IP:9944 -t ../trex-keyholder/bin/tx_account_id.txt

# sleep 5s for waiting funds
sleep 5

cd ../trex-keyholder/bin
RUST_LOG=info ./trex-keyholder -c ../service/src/config.yml --skip-ra