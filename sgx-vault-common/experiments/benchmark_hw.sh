#!/bin/bash
# ============================================================================
# 性能基准测试：测量 Seal/Unseal/CRUD 的耗时和文件大小
#
# 用法:
#   bash experiments/benchmark_hw.sh SIM [ROUNDS]
#   bash experiments/benchmark_hw.sh HW  [ROUNDS]
#
# 注意: 通过管道传输入，每次 run_app 启动新的 ./app 进程（新的 Enclave）。
#       因此测量的是"端到端"耗时（含 app 启动、菜单渲染、app 退出），
#       但 seal/unseal（~58KB AES-GCM）本身占绝对主导。
# ============================================================================
set -euo pipefail

MODE="${1:-HW}"
ROUNDS="${2:-5}"

if [ "$MODE" != "SIM" ] && [ "$MODE" != "HW" ]; then
    echo "用法: $0 SIM|HW [ROUNDS]"
    exit 1
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
INFO="${YELLOW}[INFO]${NC}"

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

# 工具
run_app() { printf '%s\n' "$@" | ./app 2>&1; }
now_ns() { date +%s%N; }
elapsed_ms() { echo $(( ($(now_ns) - $1) / 1000000 )); }
file_bytes() { stat --printf="%s" vault.sealed 2>/dev/null || echo "0"; }

# 清理陷阱
cleanup() { rm -f vault.sealed; }
trap cleanup EXIT

# 编译
echo -e "$INFO 编译: MODE=$MODE SEAL_POLICY=MRENCLAVE..."
make clean > /dev/null 2>&1 || true
if ! make SGX_MODE="$MODE" SGX_DEBUG=1 SEAL_POLICY=MRENCLAVE > /dev/null 2>&1; then
    echo -e "${RED}[FATAL]${NC} 编译失败"
    exit 1
fi
echo ""

# 累加器
SUM_CREATE=0; SUM_ADD=0; SUM_SEAL=0; SUM_SIZE=0
SUM_UNSEAL=0; SUM_GET=0; SUM_LIST=0

echo "============================================================"
echo "  Benchmark: MODE=$MODE  ROUNDS=$ROUNDS"
echo "============================================================"
echo ""

for (( r=1; r<=ROUNDS; r++ )); do
    echo "── Round $r/$ROUNDS ──"

    # === 密封阶段 ===

    # create
    T0=$(now_ns)
    run_app "1" "0" > /dev/null
    MS=$(elapsed_ms "$T0")
    SUM_CREATE=$((SUM_CREATE + MS))
    echo "  create          : ${MS} ms"

    # add
    T0=$(now_ns)
    run_app "1" "3" "bench" "user" "pass123_$r" "0" > /dev/null
    MS=$(elapsed_ms "$T0")
    SUM_ADD=$((SUM_ADD + MS))
    echo "  add             : ${MS} ms"

    # seal
    T0=$(now_ns)
    run_app "1" "9" "0" > /dev/null
    MS=$(elapsed_ms "$T0")
    SUM_SEAL=$((SUM_SEAL + MS))
    SIZE=$(file_bytes)
    SUM_SIZE=$((SUM_SIZE + SIZE))
    echo "  seal            : ${MS} ms  (file: ${SIZE} bytes)"

    # === 解封阶段 ===

    # unseal
    T0=$(now_ns)
    run_app "2" "0" > /dev/null
    MS=$(elapsed_ms "$T0")
    SUM_UNSEAL=$((SUM_UNSEAL + MS))
    echo "  unseal          : ${MS} ms"

    # get
    T0=$(now_ns)
    run_app "2" "4" "bench" "0" > /dev/null
    MS=$(elapsed_ms "$T0")
    SUM_GET=$((SUM_GET + MS))
    echo "  get             : ${MS} ms"

    # list
    T0=$(now_ns)
    run_app "2" "7" "0" > /dev/null
    MS=$(elapsed_ms "$T0")
    SUM_LIST=$((SUM_LIST + MS))
    echo "  list            : ${MS} ms"

    echo ""
done

# 平均
AVG_CREATE=$((SUM_CREATE / ROUNDS))
AVG_ADD=$((SUM_ADD / ROUNDS))
AVG_SEAL=$((SUM_SEAL / ROUNDS))
AVG_SIZE=$((SUM_SIZE / ROUNDS))
AVG_UNSEAL=$((SUM_UNSEAL / ROUNDS))
AVG_GET=$((SUM_GET / ROUNDS))
AVG_LIST=$((SUM_LIST / ROUNDS))

echo "============================================================"
echo "  Results (average over $ROUNDS rounds, includes app start/exit)"
echo "============================================================"
printf "  %-22s %8s ms\n"   "ecall_vault_create"   "$AVG_CREATE"
printf "  %-22s %8s ms\n"   "ecall_vault_add"      "$AVG_ADD"
printf "  %-22s %8s ms\n"   "ecall_vault_seal"     "$AVG_SEAL"
printf "  %-22s %8s bytes\n" "vault.sealed size"    "$AVG_SIZE"
printf "  %-22s %8s ms\n"   "ecall_vault_unseal"   "$AVG_UNSEAL"
printf "  %-22s %8s ms\n"   "ecall_vault_get"      "$AVG_GET"
printf "  %-22s %8s ms\n"   "ecall_vault_list"     "$AVG_LIST"
echo "------------------------------------------------------------"
echo "  Round-trip (seal + unseal):  $((AVG_SEAL + AVG_UNSEAL)) ms"
echo "  Throughput (seal):           $(( AVG_SIZE * 1000 / AVG_SEAL / 1024 )) KB/s"
echo "  Throughput (unseal):         $(( AVG_SIZE * 1000 / AVG_UNSEAL / 1024 )) KB/s"
echo "============================================================"
