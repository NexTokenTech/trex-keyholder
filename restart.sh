#!/bin/bash
for parm in "$@"
do
   key=`echo ${parm%%=*}`
   value=`echo ${parm#*=}`
   if [ $key == "--node_ip" ];then
      export NODE_IP=$value
   fi
done
echo NODE_IP

apt update
apt install clang
# start key holder service
cd /root/sgx/trex-keyholder/bin
RUST_LOG=info ./trex-keyholder -c ../service/src/config.yml --skip-ra