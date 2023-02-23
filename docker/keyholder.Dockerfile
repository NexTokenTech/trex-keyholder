# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

FROM trexnode.azurecr.io/keyholder:builder AS builder
ARG MODE=SW
ARG SGX_SDK=/opt/sgxsdk
ARG PROFILE=release
# UPDATE RUST DEPENDENCIES
ENV RUSTUP_HOME "/root/.rustup"
ENV CARGO_HOME "/root/.cargo"
ENV LD_LIBRARY_PATH "/opt/intel/sgx-aesm-service/aesm/"
COPY . /root/trex-keyholder
RUN . /opt/sgxsdk/environment
RUN . /$HOME/.cargo/env
RUN cd /root/trex-keyholder && PATH=$HOME/.cargo/bin:$PATH SGX_MODE=$MODE SGX_SDK=$SGX_SDK make
WORKDIR /root/trex-keyholder/bin