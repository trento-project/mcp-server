#!/usr/bin/env bash

# Copyright 2025 SUSE LLC
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Get the current year
current_year=$(date +%Y)

# Get the list of unique changed files since the specified year
changed_files_history=$(git log --name-only --pretty=format: --since="${current_year}-01-01" --until="${current_year}-12-31" --no-merges | sort -u) # files changed in this year
changed_files_current=$(git diff --cached --name-only | sort -u)                                                                                    # currently staged files
changed_files=$(echo -e "$changed_files_history\n$changed_files_current" | sort -u)                                                                 # concatenate and sort unique
# changed_files=$(git log --pretty=format: --name-only --diff-filter=A | sort -u) # all files
# changed_files=$(git ls-files . | sort -u) # every file

# Set the suffix to be used in the replacement
copyright_suffix="SUSE LLC"

# Function to perform the text replacement in a file
function replace_text_in_file() {
    local file="$1"
    local errors_log="errors.log"

    # first_year=$(git log --diff-filter=A --follow --format=%aI -- $file | tail -1 | cut -d '-' -f 1) # year when the file was created

    if [ -n "$file" ]; then
        echo "Processing ${file}"

        # Replace "Copyright YYYY-YYYY SUSE LLC" with "Copyright YYYY-CURRENT_YEAR SUSE LLC"
        sed -E -i "s/(Copyright\s+)([0-9]{4})-([0-9]{4})\s+$copyright_suffix/\1\2-$current_year $copyright_suffix/g" "$file" || echo error in "$file" >>$errors_log

        # Replace "Copyright YYYY SUSE LLC" with "Copyright YYYY-CURRENT_YEAR SUSE LLC"
        sed -E -i "s/(Copyright\s+[0-9]{4})\s+$copyright_suffix/\1-$current_year $copyright_suffix/g" "$file" || echo error in "$file" >>$errors_log

        # Replace "Copyright CURRENT_YEAR-CURRENT_YEAR SUSE LLC" with "Copyright CURRENT_YEAR SUSE LLC"
        sed -E -i "s/(Copyright\s+)($current_year)-($current_year)\s+$copyright_suffix/\1$current_year $copyright_suffix/g" "$file" || echo error in "$file" >>$errors_log

    else
        echo "No file passed to 'replace_text_in_file' function"
    fi
}

# Iterate over the list of changed files and perform text replacement
echo "Replacing copyright year in files changed since $current_year:"
while IFS= read -r file; do
    replace_text_in_file "$file"
done <<<"$changed_files"

# Display a message indicating the replacements are done
echo "Copyright year replacement completed."
