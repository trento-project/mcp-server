#!/usr/bin/env bash

# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

command -v shellcheck >/dev/null 2>&1 || {
    echo "shellcheck must be installed -> https://github.com/koalaman/shellcheck"
    exit 1
}

PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." >/dev/null && pwd)

find "${PROJECT_DIR}/" -path "./.git" -prune -o -type f -name "*.sh" -exec shellcheck {} \+
