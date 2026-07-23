#!/usr/bin/env bash
# 机器 A：使用真实 SGX HW 模式复现“无防护回滚成功”。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VAULT="$ROOT"
EXP="$(cd "$(dirname "$0")" && pwd)"
cd "$VAULT"
run_app() { printf '%s\n' "$@" | ./app 2>&1; }

if [[ ! -e /dev/sgx_enclave ]]; then
    echo '[FATAL] /dev/sgx_enclave does not exist. Enable SGX in BIOS and install the driver.' >&2; exit 1
fi
make clean
make SGX_MODE=HW SGX_DEBUG=1 SEAL_POLICY=MRENCLAVE
rm -f vault.sealed "$EXP/hw_vault_v1.sealed" "$EXP/hw_vault_v2.sealed"

run_app 1 1234 1234 3 github alice hw_password_v1 8 9 0 | tee "$EXP/hw_v1.log"
cp vault.sealed "$EXP/hw_vault_v1.sealed"
run_app 2 1234 5 github alice hw_password_v2 8 9 0 | tee "$EXP/hw_v2.log"
cp vault.sealed "$EXP/hw_vault_v2.sealed"

cp "$EXP/hw_vault_v1.sealed" vault.sealed
run_app 2 1234 8 4 github 0 | tee "$EXP/hw_rollback.log"
if grep -q 'hw_password_v1' "$EXP/hw_rollback.log"; then
    echo '[PASS] Unprotected HW rollback succeeded: SGX accepted an old but valid sealed file.'
else
    echo '[FAIL] The old password was not observed.'; exit 1
fi
