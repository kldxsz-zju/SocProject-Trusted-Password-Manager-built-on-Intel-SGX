#!/bin/bash
# ============================================================================
# 实验二：MRENCLAVE vs MRSIGNER 对比
# 
# 用法:
#   chmod +x experiments/exp2_mrenclave_vs_mrsigner.sh
#   ./experiments/exp2_mrenclave_vs_mrsigner.sh SIM   # 仿真模式
#   ./experiments/exp2_mrenclave_vs_mrsigner.sh HW    # 硬件模式
# ============================================================================
set -euo pipefail

MODE="${1:-SIM}"
if [ "$MODE" != "SIM" ] && [ "$MODE" != "HW" ]; then
    echo "Usage: $0 SIM|HW"
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS="${GREEN}[PASS]${NC}"
FAIL="${RED}[FAIL]${NC}"
INFO="${YELLOW}[INFO]${NC}"

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

# ── 退出时自动清理 ──
cleanup() {
    if grep -q 'V2_EXPERIMENT_MARKER' Enclave/Enclave.cpp 2>/dev/null; then
        echo -e "$INFO [cleanup] Restoring Enclave.cpp to V1..."
        sed -i '/V2_EXPERIMENT_MARKER/d' Enclave/Enclave.cpp
        # 压缩连续空行（保留至多一个空行）
        sed -i '/^$/N;/^\n$/D' Enclave/Enclave.cpp
    fi
    rm -f vault_mrenclave_v1.sealed vault_mrsigner_v1.sealed vault.sealed
    rm -f /tmp/_exp2_mrenclave.txt /tmp/_exp2_mrsigner.txt
}
trap cleanup EXIT

# ============================================================================
# 工具函数
# ============================================================================
run_app() {
    printf '%s\n' "$@" | ./app 2>&1
}

make_v2_code() {
    if ! grep -q 'V2_EXPERIMENT_MARKER' Enclave/Enclave.cpp; then
        echo -e "$INFO Modifying Enclave.cpp -> V2 (changing the format_version value)..."
        # 将赋值语句替换为显式 2，并添加注释标记
        sed -i 's/g_vault.format_version = VAULT_FORMAT_VERSION;/g_vault.format_version = 2; \/\/ V2_EXPERIMENT_MARKER/' Enclave/Enclave.cpp
    fi
}

ensure_v1_code() {
    if grep -q 'V2_EXPERIMENT_MARKER' Enclave/Enclave.cpp; then
        echo -e "$INFO Restoring Enclave.cpp to V1..."
        # 将赋值恢复为原来的 VAULT_FORMAT_VERSION
        sed -i 's/g_vault.format_version = 2; \/\/ V2_EXPERIMENT_MARKER/g_vault.format_version = VAULT_FORMAT_VERSION;/' Enclave/Enclave.cpp
    fi
}

build() {
    local policy="$1"
    echo -e "$INFO Building: MODE=$MODE, SEAL_POLICY=$policy..."
    make clean > /dev/null 2>&1 || true
    if ! make SGX_MODE="$MODE" SGX_DEBUG=1 SEAL_POLICY="$policy" > /dev/null 2>&1; then
        echo -e "$FAIL Build failed"
        exit 1
    fi
    echo -e "  $PASS Build succeeded"
}

get_mrenclave() {
    /opt/intel/sgxsdk/bin/x64/sgx_sign dump -enclave enclave.signed.so -dumpfile /tmp/_exp2_mrenclave.txt > /dev/null 2>&1
    grep -A1 'enclave_hash.m:' /tmp/_exp2_mrenclave.txt | tail -1 | tr -d ' ' | sed 's/0x//g'
}

get_mrsigner() {
    /opt/intel/sgxsdk/bin/x64/sgx_sign dump -enclave enclave.signed.so -dumpfile /tmp/_exp2_mrsigner.txt > /dev/null 2>&1
    grep -A1 'mrsigner->value:' /tmp/_exp2_mrsigner.txt | tail -1 | tr -d ' ' | sed 's/0x//g'
}

# ============================================================================
# 实验开始
# ============================================================================
echo "============================================================"
echo "  Experiment 2: MRENCLAVE vs MRSIGNER Comparison"
echo "  Mode: $MODE"
echo "============================================================"
echo ""

ensure_v1_code

# ── 阶段一：V1 + MRENCLAVE ──
echo "────────────────────────────────────────────────────────────"
echo "  Phase 1: V1 + MRENCLAVE Sealing"
echo "────────────────────────────────────────────────────────────"

build MRENCLAVE
V1_MRENCLAVE_HASH=$(get_mrenclave)
V1_MRSIGNER_HASH=$(get_mrsigner)
echo -e "$INFO V1 MRENCLAVE = ${V1_MRENCLAVE_HASH:0:16}..."
echo -e "$INFO V1 MRSIGNER  = ${V1_MRSIGNER_HASH:0:16}..."

run_app "1" "1234" "1234" "3" "github" "alice" "test_mrenclave_pw" "9" "0" > /dev/null
cp vault.sealed vault_mrenclave_v1.sealed
echo -e "  $PASS Saved vault_mrenclave_v1.sealed"

# ── 阶段二：V1 + MRSIGNER ──
echo ""
echo "────────────────────────────────────────────────────────────"
echo "  Phase 2: V1 + MRSIGNER Sealing"
echo "────────────────────────────────────────────────────────────"

build MRSIGNER
echo -e "$INFO V1 MRENCLAVE = $(get_mrenclave | head -c16)..."
echo -e "$INFO V1 MRSIGNER  = $(get_mrsigner | head -c16)..."

run_app "1" "1234" "1234" "3" "github" "alice" "test_mrsigner_pw" "9" "0" > /dev/null
cp vault.sealed vault_mrsigner_v1.sealed
echo -e "  $PASS Saved vault_mrsigner_v1.sealed"

# ── 阶段三：修改代码 → V2 ──
echo ""
echo "────────────────────────────────────────────────────────────"
echo "  Phase 3: Modify Code -> V2"
echo "────────────────────────────────────────────────────────────"

make_v2_code
echo -e "  $PASS Enclave.cpp modified (format_version set to 2)"
echo -e "$INFO Code change:"
grep -n 'V2_EXPERIMENT_MARKER' Enclave/Enclave.cpp || true

# ── 阶段四：V2 解封 V1 MRENCLAVE ──
echo ""
echo "────────────────────────────────────────────────────────────"
echo "  Phase 4: V2 Unseals V1 MRENCLAVE Data"
echo "────────────────────────────────────────────────────────────"

build MRENCLAVE
V2_MRENCLAVE_HASH=$(get_mrenclave)
V2_MRSIGNER_HASH=$(get_mrsigner)
echo -e "$INFO V2 MRENCLAVE = ${V2_MRENCLAVE_HASH:0:16}..."
echo -e "$INFO V2 MRSIGNER  = ${V2_MRSIGNER_HASH:0:16}..."

if [ "$V1_MRENCLAVE_HASH" != "$V2_MRENCLAVE_HASH" ]; then
    echo -e "  $PASS MRENCLAVE changed (V1 != V2)"
else
    echo -e "  $FAIL MRENCLAVE did not change - the code modification had no effect"
fi

if [ "$V1_MRSIGNER_HASH" = "$V2_MRSIGNER_HASH" ]; then
    echo -e "  $PASS MRSIGNER remained unchanged (V1 = V2)"
else
    echo -e "  $FAIL MRSIGNER changed unexpectedly - the signing key may have been replaced"
fi

cp vault_mrenclave_v1.sealed vault.sealed
OUTPUT=$(run_app "2" "1234" "0")
if echo "$OUTPUT" | grep -q "Error.*[Uu]nseal\|Error.*corrupt\|VAULT_ERR_UNSEAL\|VAULT_ERR_CORRUPT"; then
    echo -e "  $PASS V2 rejected V1 MRENCLAVE data (expected behavior)"
else
    echo -e "  $FAIL V2 unexpectedly loaded V1 MRENCLAVE data!"
    echo "  Output: $OUTPUT"
fi

# ── 阶段五：V2 解封 V1 MRSIGNER ──
echo ""
echo "────────────────────────────────────────────────────────────"
echo "  Phase 5: V2 Unseals V1 MRSIGNER Data"
echo "────────────────────────────────────────────────────────────"

cp vault_mrsigner_v1.sealed vault.sealed
OUTPUT=$(run_app "2" "1234" "4" "github" "0")
if echo "$OUTPUT" | grep -q "test_mrsigner_pw"; then
    echo -e "  $PASS V2 loaded V1 MRSIGNER data (expected: same signer, unchanged key)"
elif echo "$OUTPUT" | grep -q "Error\|ERR"; then
    echo -e "  $FAIL V2 rejected V1 MRSIGNER data (unexpected!)"
    echo "  Output: $OUTPUT"
else
    echo -e "  $FAIL Unexpected output"
    echo "  Output: $OUTPUT"
fi

# ── 阶段六：还原代码 ──
echo ""
echo "────────────────────────────────────────────────────────────"
echo "  Phase 6: Restore Code"
echo "────────────────────────────────────────────────────────────"

ensure_v1_code
echo -e "  $PASS Enclave.cpp restored to V1"

echo ""
echo "============================================================"
echo -e "  ${GREEN}Experiment 2 Complete${NC}"
echo "============================================================"
echo ""
echo "Results Summary:"
echo "  MRENCLAVE: V2 cannot unseal V1 data -> securely bound to the code itself"
echo "  MRSIGNER : V2 can unseal V1 data    -> bound to signer identity, allowing upgrades"
echo ""
echo "Additional HW mode test (requires two SGX machines):"
echo "  Machine A: make SGX_MODE=HW SEAL_POLICY=MRENCLAVE -> seal -> vault.sealed"
echo "  Machine B: scp vault.sealed -> make SGX_MODE=HW -> ./app -> Load"
echo "  Expected: VAULT_ERR_UNSEAL (different platform root keys)"
echo ""
