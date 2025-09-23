#!/usr/bin/env bash

# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

command -v yamllint >/dev/null 2>&1 || {
    echo "yamllint must be installed -> https://yamllint.readthedocs.io/en/stable/quickstart.html#installing-yamllint"
    exit 1
}

PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." >/dev/null && pwd)

[ -f "${PROJECT_DIR}/.yamllint.yaml" ] || exit 1

yamllint -c "${PROJECT_DIR}/.yamllint.yaml" "${PROJECT_DIR}"
