#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; cd "$DIR"
make witness_server
exec ./witness_server "${1:-8765}" "${2:-witness_versions.db}"

