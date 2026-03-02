# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: Apache-2.0

# Note: This file should be the same as the one in the root of the repository

#!BuildTag: trento/mcp-server-trento:latest
#!BuildTag: trento/mcp-server-trento:%%VERSION%%
#!BuildTag: trento/mcp-server-trento:%%VERSION%%-build%RELEASE%

#!BuildName: mcp-server-trento
#!BuildVersion: %%VERSION%%

#!UseOBSRepositories
#!ExclusiveArch: x86_64

ARG GO_VERSION=1.25
ARG OS_VER=15.6

ARG GOARCH
ARG GOOS
ARG PORT=5000

# Base build image
FROM registry.suse.com/bci/golang:${GO_VERSION} AS builder

# Add the tarball as the build context root
ADD mcp-server-trento.tar.gz /build/
ADD vendor.tar.gz /build/mcp-server-trento/
WORKDIR /build/mcp-server-trento

ARG GOARCH
ARG GOOS

ENV GOARCH=${GOARCH}
ENV GOOS=${GOOS}

# Build the binary using the Makefile
RUN make build

FROM registry.suse.com/bci/bci-micro:${OS_VER}

# See https://github.com/SUSE/BCI-dockerfile-generator/blob/main/src/bci_build/templates.py

ARG GOARCH
ARG GOOS
ARG OS_VER
ARG PORT

COPY --from=builder /build/mcp-server-trento/bin/${GOOS}-${GOARCH}/mcp-server-trento /mcp-server-trento

# labelprefix=com.suse.trento
LABEL org.opencontainers.image.authors="https://github.com/trento-project/mcp-server/graphs/contributors"
LABEL org.opencontainers.image.title="Trento MCP Server"
LABEL org.opencontainers.image.description="Model Context Protocol server wrapping Trento API"
LABEL org.opencontainers.image.documentation="https://documentation.suse.com/sles-sap/trento"
LABEL org.opencontainers.image.version="%%VERSION%%"
LABEL org.opencontainers.image.url="https://www.suse.com/products/base-container-images/"
LABEL org.opencontainers.image.created="%BUILDTIME%"
LABEL org.opencontainers.image.vendor="SUSE LLC"
LABEL org.opencontainers.image.source="%SOURCEURL%"
LABEL org.opencontainers.image.ref.name="%%VERSION%%-build%RELEASE%"
LABEL org.opensuse.reference="registry.suse.com/trento/mcp-server-trento:%%VERSION%%-build%RELEASE%"
LABEL org.openbuildservice.disturl="%DISTURL%"
LABEL com.suse.supportlevel="l3"
LABEL com.suse.supportlevel.until=""
LABEL com.suse.eula="sle-bci"
LABEL com.suse.lifecycle-url="https://www.suse.com/lifecycle#suse-linux-enterprise-server-for-sap-applications-15"
LABEL com.suse.release-stage="released"
# endlabelprefix
LABEL org.opencontainers.image.base.name="%BASE_REFNAME%"
LABEL org.opencontainers.image.base.digest="%BASE_DIGEST%"
LABEL io.artifacthub.package.logo-url="https://www.trento-project.io/images/trento-icon.svg"
LABEL io.artifacthub.package.readme-url="%SOURCEURL_WITH(README.md)%"

USER 1001

EXPOSE ${PORT}/tcp

ENTRYPOINT [ "/mcp-server-trento" ]
