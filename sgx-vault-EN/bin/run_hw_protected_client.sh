#!/usr/bin/env bash
# 机器 A：HW ./app + 机器 B 版本见证的 fail-closed 对照实验。
set -euo pipefail
if [[ $# -lt 1 || $# -gt 3 ]]; then
    echo "usage: $0 WITNESS_HOST [PORT] [EXPERIMENT_VAULT_ID]" >&2; exit 2
fi
HOST="$1"; PORT="${2:-8765}"; VID="${3:-00112233445566778899aabbccddeeff}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; VAULT="$ROOT"; EXP="$(cd "$(dirname "$0")" && pwd)"
cd "$EXP"; make witness_client
CLIENT="$EXP/witness_client"
cd "$VAULT"
run_app() { printf '%s\n' "$@" | ./app 2>&1; }
state_of() { sed -n 's/.*State version: \([0-9][0-9]*\).*/\1/p' | tail -n 1; }

[[ -e /dev/sgx_enclave ]] || { echo '[FATAL] /dev/sgx_enclave does not exist.' >&2; exit 1; }
make clean
make SGX_MODE=HW SGX_DEBUG=1 SEAL_POLICY=MRENCLAVE
rm -f vault.sealed "$EXP/protected_v1.sealed" "$EXP/protected_v2.sealed"

run_app 1 1234 1234 3 github alice protected_password_v1 8 9 0 | tee "$EXP/protected_v1.log"
cp vault.sealed "$EXP/protected_v1.sealed"
V1="$(state_of <"$EXP/protected_v1.log")"

run_app 2 1234 5 github alice protected_password_v2 8 9 0 | tee "$EXP/protected_v2.log"
cp vault.sealed "$EXP/protected_v2.sealed"
V2="$(state_of <"$EXP/protected_v2.log")"
[[ -n "$V1" && -n "$V2" && "$V2" -gt "$V1" ]] || { echo '[FATAL] Failed to extract increasing versions.'; exit 1; }

"$CLIENT" "$HOST" "$PORT" COMMIT "$VID" "$V2"
cp "$EXP/protected_v1.sealed" vault.sealed

# 先只解封并读取版本；在见证通过前绝不执行 Get/List/Update。
run_app 2 1234 8 0 | tee "$EXP/protected_rollback_check.log"
LOADED="$(state_of <"$EXP/protected_rollback_check.log")"
set +e
REPLY="$("$CLIENT" "$HOST" "$PORT" CHECK "$VID" "$LOADED")"; RC=$?
set -e
echo "$REPLY" | tee -a "$EXP/protected_rollback_check.log"
if [[ $RC -eq 10 ]]; then
    echo "[PASS] The protected HW path rejected the rollback: local version=$LOADED, trusted version=$V2."
    echo '[PASS] Fail-closed: no password read was performed.'
    exit 0
fi
echo '[FAIL] The witness did not reject the old version.'; exit 1
