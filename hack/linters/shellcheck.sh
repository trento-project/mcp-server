#!/usr/bin/env bash

# SPDX-FileCopyrightText: SUSE LLC
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

command -v shellcheck >/dev/null 2>&1 || {
    echo "shellcheck must be installed -> https://github.com/koalaman/shellcheck"
    exit 1
}

PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." >/dev/null && pwd)

find "${PROJECT_DIR}/" -path "./.git" -prune -o -type f -name "*.sh" -exec shellcheck {} \+
