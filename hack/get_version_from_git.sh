#!/usr/bin/env bash

# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
SEMVER_REGEX="^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"

TAG=$(git tag 2>/dev/null | grep -P "$SEMVER_REGEX" | sed '/-/!{s/$/_/}' | sort -V | sed 's/_$//' | tail -n1 || true)

if [ -z "${TAG}" ]; then
  echo "devel"
else
  COMMITS_SINCE_TAG=$(git rev-list "${TAG}".. --count)
  if [ "${COMMITS_SINCE_TAG}" -gt 0 ]; then
    COMMIT_INFO=$(git show -s --format=%ct.%h HEAD)
    SUFFIX="+git.${COMMITS_SINCE_TAG}.${COMMIT_INFO}"
  fi
  echo "${TAG}${SUFFIX}"
fi
