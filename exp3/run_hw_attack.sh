#!/usr/bin/env bash
# 机器 A：使用真实 SGX HW 模式复现“无防护回滚成功”。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VAULT="$ROOT/sgx-vault-common"
EXP="$ROOT/exp3"
cd "$VAULT"
run_app() { printf '%s\n' "$@" | ./app 2>&1; }

if [[ ! -e /dev/sgx_enclave ]]; then
    echo '[FATAL] /dev/sgx_enclave 不存在；请启用 BIOS SGX 并安装驱动。' >&2; exit 1
fi
make clean
make SGX_MODE=HW SGX_DEBUG=1 SEAL_POLICY=MRENCLAVE
rm -f vault.sealed "$EXP/hw_vault_v1.sealed" "$EXP/hw_vault_v2.sealed"

run_app 1 3 github alice hw_password_v1 8 9 0 | tee "$EXP/hw_v1.log"
cp vault.sealed "$EXP/hw_vault_v1.sealed"
run_app 2 5 github alice hw_password_v2 8 9 0 | tee "$EXP/hw_v2.log"
cp vault.sealed "$EXP/hw_vault_v2.sealed"

cp "$EXP/hw_vault_v1.sealed" vault.sealed
run_app 2 8 4 github 0 | tee "$EXP/hw_rollback.log"
if grep -q 'hw_password_v1' "$EXP/hw_rollback.log"; then
    echo '[PASS] HW 无防护回滚成功：SGX 接受了旧但合法的密封文件。'
else
    echo '[FAIL] 未观察到旧密码。'; exit 1
fi

