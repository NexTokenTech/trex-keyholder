### Builder Stage
##################################################
FROM integritee/integritee-dev:0.1.9 AS builder
LABEL maintainer="zoltan@integritee.network"

# set environment variables
ENV SGX_SDK /opt/intel/sgxsdk
ENV PATH "$PATH:${SGX_SDK}/bin:${SGX_SDK}/bin/x64:/root/.cargo/bin"
ENV PKG_CONFIG_PATH "${PKG_CONFIG_PATH}:${SGX_SDK}/pkgconfig"
ENV LD_LIBRARY_PATH "${LD_LIBRARY_PATH}:${SGX_SDK}/sdk_libs"
ENV CARGO_NET_GIT_FETCH_WITH_CLI true
ENV SGX_MODE SW

ENV HOME=/root/work

ARG WORKER_MODE_ARG
ENV WORKER_MODE=$WORKER_MODE_ARG

ARG ADDITIONAL_FEATURES_ARG
ENV ADDITIONAL_FEATURES=$ADDITIONAL_FEATURES_ARG

WORKDIR $HOME/worker
COPY . .

RUN make


### Base Runner Stage
##################################################
FROM ubuntu:20.04 AS runner

RUN apt update && apt install -y libssl-dev iproute2

COPY --from=powerman/dockerize /usr/local/bin/dockerize /usr/local/bin/dockerize


### Deployed CLI client
##################################################
FROM runner AS deployed-client
LABEL maintainer="zoltan@integritee.network"

#ARG SCRIPT_DIR=/usr/local/worker-cli
#ARG LOG_DIR=/usr/local/log
#
#ENV SCRIPT_DIR ${SCRIPT_DIR}
#ENV LOG_DIR ${LOG_DIR}

COPY --from=builder /root/work/worker/bin/cli /usr/local/bin
#COPY ./cli/*.sh /usr/local/worker-cli/

#RUN chmod +x /usr/local/bin/integritee-cli ${SCRIPT_DIR}/*.sh
#RUN mkdir ${LOG_DIR}

RUN ldd /usr/local/bin/cli && \
	/usr/local/bin/cli --version

ENTRYPOINT ["/usr/local/bin/cli"]


### Deployed worker service
##################################################
FROM runner AS deployed-worker
LABEL maintainer="zoltan@integritee.network"

ENV SGX_SDK /opt/intel/sgxsdk
ENV LD_LIBRARY_PATH "${LD_LIBRARY_PATH}:${SGX_SDK}/lib64"

WORKDIR /usr/local/bin

COPY --from=builder /opt/intel/sgxsdk/lib64 /opt/intel/sgxsdk/lib64
COPY --from=builder /root/work/worker/bin/* ./

RUN touch spid.txt key.txt
RUN chmod +x /usr/local/bin/trex-keyholder
RUN ls -al /usr/local/bin

# checks
RUN ldd /usr/local/bin/trex-keyholder && \
	/usr/local/bin/trex-keyholder --version

ENTRYPOINT ["/usr/local/bin/trex-keyholder"]