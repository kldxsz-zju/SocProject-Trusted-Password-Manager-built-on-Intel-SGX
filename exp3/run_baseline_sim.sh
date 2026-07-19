#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VAULT="$ROOT/sgx-vault-common"
WORK="$ROOT/exp3"
cd "$VAULT"

run_app() { printf '%s\n' "$@" | ./app 2>&1; }
rm -f vault.sealed "$WORK/vault_v1.sealed" "$WORK/vault_v2.sealed"

make clean >/dev/null
make SGX_MODE=SIM SGX_DEBUG=1 SEAL_POLICY=MRENCLAVE

run_app 1 3 github alice password_v1 9 0 >"$WORK/v1.log"
cp vault.sealed "$WORK/vault_v1.sealed"
run_app 2 5 github alice password_v2 9 0 >"$WORK/v2.log"
cp vault.sealed "$WORK/vault_v2.sealed"

# 攻击者把当前状态替换为旧但合法的密封文件。
cp "$WORK/vault_v1.sealed" vault.sealed
OUTPUT="$(run_app 2 8 4 github 0)"
printf '%s\n' "$OUTPUT" >"$WORK/rollback.log"
if grep -q 'password_v1' "$WORK/rollback.log"; then
    echo '[PASS] 无防护回滚成功：旧文件可解封，旧密码重新出现。'
else
    echo '[FAIL] 未观察到预期的旧状态。'; exit 1
fi

