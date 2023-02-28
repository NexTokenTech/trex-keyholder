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
ARG PROFILE=release
# UPDATE RUST DEPENDENCIES
ARG MODE=SW
ARG PROFILE=release
# UPDATE RUST DEPENDENCIES
ENV RUSTUP_HOME "/root/.rustup"
ENV CARGO_HOME "/root/.cargo"
ENV LD_LIBRARY_PATH "/opt/sgxsdk/sdk_libs:/opt/intel/sgx-aesm-service/aesm/"
ENV PKG_CONFIG_PATH ":/opt/sgxsdk/pkgconfig"
ENV RUST_TOOLCHAIN "nightly-2022-11-10"
ENV SGX_LINUX_X64_SDK "sgx_linux_x64_sdk_2.18.101.1.bin"
ENV SGX_SDK "/opt/sgxsdk"
ENV SHLVL "1"
ENV VERSION "2.18.101.1-jammy1"
ENV PATH "/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/sgxsdk/bin:/opt/sgxsdk/bin/x64"
COPY . /root/trex-keyholder
RUN . /opt/sgxsdk/environment
RUN . /$HOME/.cargo/env
RUN mv /root/trex-keyholder/run.sh /root/run.sh
RUN cd /root/trex-keyholder && SGX_MODE=$MODE make
RUN git clone https://github.com/NexTokenTech/trex-account-funds.git /root/trex-account-funds
RUN cargo install subxt-cli
RUN cd /root/trex-account-funds && cargo build --$PROFILE
WORKDIR /root
