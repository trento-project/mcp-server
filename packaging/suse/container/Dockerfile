# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: Apache-2.0

# Note: This file should be the same as the one in the root of the repository

#!BuildTag: trento/mcp-server-trento:latest
#!BuildTag: trento/mcp-server-trento:%%VERSION%%
#!BuildTag: trento/mcp-server-trento:%%VERSION%%-build%RELEASE%
#!UseOBSRepositories
#!ExclusiveArch: x86_64

ARG GO_VERSION=1.25
ARG OS_VER=15.6

ARG GOARCH
ARG GOOS
ARG VERSION
ARG PORT=5000

# Base build image
FROM registry.suse.com/bci/golang:${GO_VERSION} AS builder

# Add the tarball as the build context root
ADD trento-mcp-server.tar.gz /build/
ADD vendor.tar.gz /build/trento-mcp-server/
WORKDIR /build/trento-mcp-server

ARG GOARCH
ARG GOOS
ARG VERSION

ENV GOARCH=${GOARCH}
ENV GOOS=${GOOS}
ENV VERSION=%%VERSION%%

# Build the binary using the Makefile
RUN make build

FROM registry.suse.com/bci/bci-micro:${OS_VER}

ARG GOARCH
ARG GOOS
ARG VERSION
ARG PORT

COPY --from=builder /build/trento-mcp-server/bin/${GOOS}-${GOARCH}/trento-mcp-server /trento-mcp-server
COPY --from=builder build/trento-mcp-server/api api

LABEL org.opencontainers.image.title="Trento MCP Server"
LABEL org.opencontainers.image.source="https://github.com/trento-project/mcp-server"
LABEL org.opencontainers.image.description="Model Context Protocol server wrapping Trento API"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.vendor="SUSE LLC"
LABEL org.opencontainers.image.url="https://github.com/trento-project/mcp-server"
LABEL org.opencontainers.image.authors="https://github.com/trento-project/mcp-server/graphs/contributors"

USER 1001

EXPOSE ${PORT}/tcp

ENTRYPOINT [ "/trento-mcp-server" ]
