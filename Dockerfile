# Copyright 2025-2026 SUSE LLC
# SPDX-License-Identifier: Apache-2.0

ARG GO_VERSION=1.25
ARG OS_VER=15.7

ARG GOARCH
ARG GOOS
ARG PORT=5000
ARG VERSION

# Base build image
FROM registry.suse.com/bci/golang:${GO_VERSION} AS builder

WORKDIR /go/src/github.com/trento-project/mcp-server

COPY go.mod go.sum main.go Makefile hack ./
COPY cmd cmd
COPY internal internal

ARG GOARCH
ARG GOOS
ARG VERSION

ENV GOARCH=${GOARCH}
ENV GOOS=${GOOS}
ENV VERSION=${VERSION}

# Build the binary using the Makefile
RUN go mod download

RUN make build

FROM registry.suse.com/bci/bci-micro:${OS_VER}

# See https://github.com/SUSE/BCI-dockerfile-generator/blob/main/src/bci_build/templates.py

ARG DATE
ARG GOARCH
ARG GOOS
ARG OS_VER
ARG PORT
ARG VERSION

COPY --from=builder /go/src/github.com/trento-project/mcp-server/bin/${GOOS}-${GOARCH}/mcp-server-trento /mcp-server-trento

# Define labels according to https://en.opensuse.org/Building_derived_containers
# labelprefix=com.suse.trento
LABEL org.opencontainers.image.authors="https://github.com/trento-project/mcp-server/graphs/contributors"
LABEL org.opencontainers.image.title="Trento MCP Server"
LABEL org.opencontainers.image.description="Model Context Protocol server wrapping Trento API"
LABEL org.opencontainers.image.documentation="https://www.trento-project.io/docs/mcp-server/README.html"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.url="https://github.com/trento-project/mcp-server"
LABEL org.opencontainers.image.created="${DATE}"
LABEL org.opencontainers.image.vendor="SUSE LLC"
LABEL org.opencontainers.image.source="https://github.com/trento-project/mcp-server"
LABEL org.opencontainers.image.ref.name="${OS_VER}-${VERSION}"
LABEL org.opensuse.reference="registry.suse.com/bci/bci-micro:${OS_VER}"
LABEL org.openbuildservice.disturl="https://github.com/trento-project/mcp-server/pkgs/container/mcp-server-trento"
# endlabelprefix
LABEL org.opencontainers.image.base.name="registry.suse.com/bci/bci-micro:${OS_VER}"
LABEL org.opencontainers.image.base.digest="latest"
LABEL io.artifacthub.package.logo-url="https://www.trento-project.io/images/trento-icon.svg"
LABEL io.artifacthub.package.readme-url="https://raw.githubusercontent.com/trento-project/mcp-server/refs/heads/main/packaging/suse/container/README.md"

USER 1001

EXPOSE ${PORT}/tcp

ENTRYPOINT [ "/mcp-server-trento" ]
