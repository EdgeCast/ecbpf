ARG UBUNTU_VERSION=22.04
FROM ubuntu:$UBUNTU_VERSION
# ARG are reset after FROM
ARG UBUNTU_VERSION
ARG GO_VERSION=1.17.3
ARG PROTOC_VERSION=3.19.1
ARG PROTOC_GEN_GO_VERSION=1.27.1
ARG PROTOC_GEN_GO_GRPC_VERSION=1.1
# This might break protoc-gen-go but needs to be hard coded since docker doesn't allow to execute script
# and then store as ENV
ARG GO_ROOT_ENV_PATH="/root/go"

# Install reqs, and cleanup after
RUN apt-get update \
  && DEBIAN_FRONTEND="noninteractive" apt-get install -y apt-utils software-properties-common \
  && DEBIAN_FRONTEND="noninteractive" apt-get install -y lsb-release make build-essential git curl unzip wget\
  && apt-get update


## protoc
# Download proto zip: See https://stackoverflow.com/questions/65538591/run-protoc-command-into-docker-container
ARG PROTOC_ZIP="protoc-$PROTOC_VERSION-linux-x86_64.zip"
RUN curl -OL "https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOC_VERSION/$PROTOC_ZIP"
RUN unzip -o $PROTOC_ZIP -d /protocompiler
RUN rm $PROTOC_ZIP

##golang
ARG GO_TAR="go$GO_VERSION.linux-amd64.tar.gz"
RUN wget https://dl.google.com/go/$GO_TAR
RUN tar -C /usr/local -xzf $GO_TAR
RUN rm $GO_TAR

# Update the ENV PATH (for both go and proto compiler and protogen)
ENV PATH="$PATH:/protocompiler/bin:/usr/local/go/bin:$GO_ROOT_ENV_PATH/bin"

## grpc
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v$PROTOC_GEN_GO_VERSION
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v$PROTOC_GEN_GO_GRPC_VERSION
