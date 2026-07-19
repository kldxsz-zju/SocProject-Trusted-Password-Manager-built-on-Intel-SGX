#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
make
rm -f witness_versions.db
./witness_server 8765 witness_versions.db >witness.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT
sleep 1

# 固定 ID 只用于测试见证逻辑；真实集成由 Enclave 输出随机 vault_id。
VID=00112233445566778899aabbccddeeff
./witness_client 127.0.0.1 8765 COMMIT "$VID" 3
set +e
OUT="$(./witness_client 127.0.0.1 8765 CHECK "$VID" 2)"; RC=$?
set -e
echo "$OUT"
if [[ $RC -eq 10 && "$OUT" == ROLLBACK\ 3* ]]; then
    echo '[PASS] 有防护路径拒绝 V2→V1 回滚。'
else
    echo '[FAIL] 见证服务未拒绝旧版本。'; exit 1
fi

