#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 5 ]]; then
  echo "usage: $0 HOST PORT CHECK|COMMIT VAULT_ID STATE_VERSION" >&2; exit 2
fi
DIR="$(cd "$(dirname "$0")" && pwd)"; cd "$DIR"
make witness_client
exec ./witness_client "$@"
