#!/bin/bash
# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: Apache-2.0


# A generic script to download and process documentation from a URL.
#
# This script downloads HTML documentation recursively from a given URL,
# converts the pages to Markdown using pandoc, and then cleans up the
# original HTML files.
#
# Usage: ./download_docs.sh <name> <url>
#   <name>: The name of the documentation (e.g., "trento", "suse").
#           This is used to create the output directory (rag/<name>_docs).
#   <url>:  The starting URL to download from.

set -e

# Check for required dependencies
if ! command -v wget &> /dev/null; then
    echo "Error: wget is not installed. Please install it to continue."
    exit 1
fi

if ! command -v pandoc &> /dev/null; then
    echo "Error: pandoc is not installed. Please install it to continue."
    echo "See: https://pandoc.org/installing.html"
    exit 1
fi

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <name> <url>"
    exit 1
fi

NAME=$1
URL=$2
DOCS_DIR="rag/${NAME}_docs"

echo "--- Downloading documentation for: ${NAME} ---"
echo "Source URL: ${URL}"
echo "Output directory: ./${DOCS_DIR}"

mkdir -p "$DOCS_DIR"
wget --recursive --no-clobber --page-requisites --html-extension --convert-links --restrict-file-names=windows --domains=documentation.suse.com --no-parent --timeout=1 --read-timeout=1 --accept=html,htm --level=2 "$URL" -P "$DOCS_DIR"

echo "Converting HTML to Markdown and cleaning up..."
find "$DOCS_DIR" -name "*.html" -print0 | xargs -0 -I {} sh -c 'pandoc "{}" -f html -t markdown -o "${0%.html}.md" && rm "{}"' {}

echo "✅ Documentation for ${NAME} downloaded and converted to Markdown in ./$DOCS_DIR"
