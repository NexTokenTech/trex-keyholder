### Builder Stage
##################################################
FROM integritee/integritee-dev:0.1.9 AS builder
LABEL maintainer="zoltan@integritee.network"

# set environment variables
ENV SGX_SDK /opt/sgxsdk
ENV PATH "$PATH:${SGX_SDK}/bin:${SGX_SDK}/bin/x64:/root/.cargo/bin"
ENV PKG_CONFIG_PATH "${PKG_CONFIG_PATH}:${SGX_SDK}/pkgconfig"
ENV LD_LIBRARY_PATH "${LD_LIBRARY_PATH}:${SGX_SDK}/sdk_libs"
ENV CARGO_NET_GIT_FETCH_WITH_CLI true
ENV SGX_MODE SW

# set current work dir
ENV HOME=/root/work
WORKDIR $HOME/worker
# copy project to builder context
COPY . .

# make
RUN make

### trex-keyholder Stage
##################################################
FROM integritee/integritee-dev:0.1.9
# set environment variables
ENV SGX_SDK /opt/sgxsdk
ENV LD_LIBRARY_PATH "${LD_LIBRARY_PATH}:${SGX_SDK}/lib64"
# copy bin/* from builder
COPY --from=builder /root/work/worker/bin/* /usr/local/bin/

RUN chmod +x /usr/local/bin/cli
# change work dir to /usr/local/bin
WORKDIR /usr/local/bin
# copy sgxsdk lib to current work dir
COPY --from=builder /opt/sgxsdk/lib64 /opt/sgxsdk/lib64

# if you want to build cli as the entrypoint
#ENTRYPOINT ["/usr/local/bin/cli"]
# if you want to build trex-keyholder as the entrypoint
ENTRYPOINT ["/usr/local/bin/trex-keyholder"]