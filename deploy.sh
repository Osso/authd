#!/usr/bin/env bash
# Build the authd package and reinstall it
set -euo pipefail
cd "$(dirname "$0")"
authsudo arch install .
