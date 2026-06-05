ARG RUNTIME_IMAGE=docker.io/alpine:3.19.1

FROM ${RUNTIME_IMAGE}

ARG UID=10001
ARG USER_NAME=celestia
ENV CELESTIA_HOME=/home/${USER_NAME}

ENV AUTH_TOKEN=""
ENV NAMESPACEID=""
ENV CELESTIA_NODE_ENDPOINT=""

USER root

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

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/celestia-server /bin/celestia-server

RUN mkdir -p ${CELESTIA_HOME}/keys && \
    chown -R ${USER_NAME}:${USER_NAME} ${CELESTIA_HOME}/keys

WORKDIR ${CELESTIA_HOME}

USER ${USER_NAME}

EXPOSE 1317 9090 26657 1095 8080 26658
ENTRYPOINT ["sh", "-c", "/bin/celestia-server --celestia.auth-token $AUTH_TOKEN --celestia.namespace-id $NAMESPACEID --celestia.rpc $CELESTIA_NODE_ENDPOINT"]
