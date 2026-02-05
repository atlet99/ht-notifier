#!/bin/bash
# Copyright (c) 2025 Abdurakhman Rakhmankulov
#
# Licensed under the MIT License (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://opensource.org/licenses/MIT
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Script to update .release-version
#
# Usage:
#   ./update-version.sh [version]
#
#   If version is provided, updates to that specific version.
#   If not provided, prompts for new version or increments patch version.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION_FILE="${REPO_ROOT}/.release-version"

# Function to validate version format (SemVer: X.Y.Z)
validate_version() {
    local version="$1"
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Invalid version format. Expected SemVer format (X.Y.Z), got: $version" >&2
        return 1
    fi
    return 0
}

# Function to increment patch version
increment_patch() {
    local version="$1"
    local major=$(echo "$version" | cut -d. -f1)
    local minor=$(echo "$version" | cut -d. -f2)
    local patch=$(echo "$version" | cut -d. -f3)
    patch=$((patch + 1))
    echo "${major}.${minor}.${patch}"
}

# Function to increment minor version
increment_minor() {
    local version="$1"
    local major=$(echo "$version" | cut -d. -f1)
    local minor=$(echo "$version" | cut -d. -f2)
    minor=$((minor + 1))
    echo "${major}.${minor}.0"
}

# Function to increment major version
increment_major() {
    local version="$1"
    local major=$(echo "$version" | cut -d. -f1)
    major=$((major + 1))
    echo "${major}.0.0"
}

# Get current version
if [ -f "${VERSION_FILE}" ]; then
    CURRENT_VERSION=$(cat "${VERSION_FILE}" | tr -d '[:space:]')
    if [ -z "$CURRENT_VERSION" ]; then
        CURRENT_VERSION="0.1.0"
    fi
else
    CURRENT_VERSION="0.1.0"
fi

# If version is provided as argument, use it
if [ $# -ge 1 ]; then
    NEW_VERSION="$1"
    if ! validate_version "$NEW_VERSION"; then
        exit 1
    fi
    echo "${NEW_VERSION}" > "${VERSION_FILE}"
    echo "Updated .release-version to ${NEW_VERSION}"
    exit 0
fi

# Interactive mode
echo "Current version: ${CURRENT_VERSION}"
echo ""
echo "Options:"
echo "  1) Increment patch version ($(increment_patch "$CURRENT_VERSION"))"
echo "  2) Increment minor version ($(increment_minor "$CURRENT_VERSION"))"
echo "  3) Increment major version ($(increment_major "$CURRENT_VERSION"))"
echo "  4) Enter custom version"
echo ""
read -p "Select option (1-4): " choice

case "$choice" in
    1)
        NEW_VERSION=$(increment_patch "$CURRENT_VERSION")
        ;;
    2)
        NEW_VERSION=$(increment_minor "$CURRENT_VERSION")
        ;;
    3)
        NEW_VERSION=$(increment_major "$CURRENT_VERSION")
        ;;
    4)
        read -p "Enter new version (X.Y.Z): " NEW_VERSION
        if ! validate_version "$NEW_VERSION"; then
            exit 1
        fi
        ;;
    *)
        echo "Invalid option. Exiting."
        exit 1
        ;;
esac

# Update version file
echo "${NEW_VERSION}" > "${VERSION_FILE}"
echo "Updated .release-version to ${NEW_VERSION}"

