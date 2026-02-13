# This Dockerfile performs a multi-stage build. BUILDER_IMAGE is the image used
# to compile the celestia-appd binary. RUNTIME_IMAGE is the image that will be
# returned with the final celestia-appd binary.
#
# Separating the builder and runtime image allows the runtime image to be
# considerably smaller because it doesn't need to have Golang installed.
ARG BUILDER_IMAGE=docker.io/golang:1.25-alpine
ARG RUNTIME_IMAGE=docker.io/alpine:3.19.1
ARG TARGETOS
ARG TARGETARCH

# Stage 1: Build the celestia-appd binary inside a builder image that will be discarded later.
# Ignore hadolint rule because hadolint can't parse the variable.
# See https://github.com/hadolint/hadolint/issues/339
# hadolint ignore=DL3006
FROM --platform=$BUILDPLATFORM ${BUILDER_IMAGE} AS builder
ENV CGO_ENABLED=1
ENV GO111MODULE=on
# hadolint ignore=DL3018
RUN apk update && apk add --no-cache \
    gcc \
    git \
    # linux-headers are needed for Ledger support
    linux-headers \
    make \
    musl-dev \
    build-base \
    libc-dev
COPY . /nitro-das-celestia
WORKDIR /nitro-das-celestia/cmd

RUN go clean -modcache && \
    go mod tidy && \
    uname -a && \
    CGO_ENABLED=1 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -o celestia-server

FROM ${RUNTIME_IMAGE} AS runtime
# Use UID 10,001 because UIDs below 10,000 are a security risk.
# Ref: https://github.com/hexops/dockerfile/blob/main/README.md#do-not-use-a-uid-below-10000
ARG UID=10001
ARG USER_NAME=celestia
ENV CELESTIA_HOME=/home/${USER_NAME}

ENV AUTH_TOKEN=""
ENV NAMESPACEID=""
ENV CELESTIA_NODE_ENDPOINT=""

# Switch to root to install packages and create user
USER root

# hadolint ignore=DL3018
RUN apk update && apk add --no-cache \
    bash \
    curl \
    jq \
    && adduser ${USER_NAME} \
    -D \
    -g ${USER_NAME} \
    -h ${CELESTIA_HOME} \
    -s /sbin/nologin \
    -u ${UID}

COPY --from=builder /nitro-das-celestia/cmd/celestia-server /bin/celestia-server

# Create a directory that the user can write to for keys when no volume is mounted
RUN mkdir -p ${CELESTIA_HOME}/keys && \
    chown -R ${USER_NAME}:${USER_NAME} ${CELESTIA_HOME}/keys

# Set the working directory
WORKDIR ${CELESTIA_HOME}

#Set the user
USER ${USER_NAME}

# Expose ports:
EXPOSE 1317 9090 26657 1095 8080 26658
ENTRYPOINT ["sh", "-c", "/bin/celestia-server --celestia.auth-token $AUTH_TOKEN --celestia.namespace-id $NAMESPACEID --celestia.rpc $CELESTIA_NODE_ENDPOINT"]
