<!--
  ~ Copyright 2025 SUSE LLC
  ~ SPDX-License-Identifier: Apache-2.0
-->

# Getting started with Trento MCP Server

This document provides a guide to get started with `Trento MCP Server` development. It covers the setup of the test environment, building, running and testing the project.

## Building the Project

To build the project binary, run:

```console
make build
```

The compiled binary will be located in the `bin/` directory.

## Running the Project Locally

To run the server locally (after building):

```console
make run
```

## Building the Container Image

To build the container image:

```console
make container-build
```

This will create a container image named `ghcr.io/trento-project/mcp-server`.

## Running the Container

To run the server in a container:

```console
make container-run
```

This will start the container using the built image.
