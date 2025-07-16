# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: Apache-2.0

ARG GO_VERSION=1.24
ARG OS_VER=15.6

ARG VERSION

# Base build image
FROM registry.suse.com/bci/golang:${GO_VERSION} AS builder

WORKDIR /go/src/github.com/trento-project/mcp-server

COPY go.mod go.sum main.go ./
COPY cmd cmd
COPY internal internal

# We are mounting the ssh auth sock in the GHA
# See: https://docs.docker.com/reference/cli/docker/buildx/build/#ssh
# Keep Go build cache between builds
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=ssh \
    go mod download

# Build the main grpc server, setting version via ldflags
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=ssh \
    go build \
    -ldflags "-X github.com/trento-project/mcp-server/cmd.version=$VERSION" \
    -o /go/src/github.com/trento-project/mcp-server/trento-mcp-server \
    ./main.go

FROM registry.suse.com/bci/bci-micro:${OS_VER}

COPY --from=builder /go/src/github.com/trento-project/mcp-server/trento-mcp-server /trento-mcp-server
COPY api api

USER 1001

ENTRYPOINT [ "/trento-mcp-server" ]
