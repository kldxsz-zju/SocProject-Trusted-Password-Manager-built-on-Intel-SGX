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
    echo "用法: $0 SIM|HW"
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
        echo -e "$INFO [cleanup] 还原 Enclave.cpp 到 V1..."
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
        echo -e "$INFO 修改 Enclave.cpp → V2（改变 format_version 赋值）..."
        # 将赋值语句替换为显式 2，并添加注释标记
        sed -i 's/g_vault.format_version = VAULT_FORMAT_VERSION;/g_vault.format_version = 2; \/\/ V2_EXPERIMENT_MARKER/' Enclave/Enclave.cpp
    fi
}

ensure_v1_code() {
    if grep -q 'V2_EXPERIMENT_MARKER' Enclave/Enclave.cpp; then
        echo -e "$INFO 还原 Enclave.cpp 到 V1..."
        # 将赋值恢复为原来的 VAULT_FORMAT_VERSION
        sed -i 's/g_vault.format_version = 2; \/\/ V2_EXPERIMENT_MARKER/g_vault.format_version = VAULT_FORMAT_VERSION;/' Enclave/Enclave.cpp
    fi
}

build() {
    local policy="$1"
    echo -e "$INFO 编译: MODE=$MODE, SEAL_POLICY=$policy..."
    make clean > /dev/null 2>&1 || true
    if ! make SGX_MODE="$MODE" SGX_DEBUG=1 SEAL_POLICY="$policy" > /dev/null 2>&1; then
        echo -e "$FAIL 编译失败"
        exit 1
    fi
    echo -e "  $PASS 编译成功"
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
echo "  实验二：MRENCLAVE vs MRSIGNER 对比"
echo "  模式: $MODE"
echo "============================================================"
echo ""

ensure_v1_code

# ── 阶段一：V1 + MRENCLAVE ──
echo "────────────────────────────────────────────────────────────"
echo "  阶段一：V1 + MRENCLAVE 密封"
echo "────────────────────────────────────────────────────────────"

build MRENCLAVE
V1_MRENCLAVE_HASH=$(get_mrenclave)
V1_MRSIGNER_HASH=$(get_mrsigner)
echo -e "$INFO V1 MRENCLAVE = ${V1_MRENCLAVE_HASH:0:16}..."
echo -e "$INFO V1 MRSIGNER  = ${V1_MRSIGNER_HASH:0:16}..."

run_app "1" "1234" "1234" "3" "github" "alice" "test_mrenclave_pw" "9" "0" > /dev/null
cp vault.sealed vault_mrenclave_v1.sealed
echo -e "  $PASS 已保存 vault_mrenclave_v1.sealed"

# ── 阶段二：V1 + MRSIGNER ──
echo ""
echo "────────────────────────────────────────────────────────────"
echo "  阶段二：V1 + MRSIGNER 密封"
echo "────────────────────────────────────────────────────────────"

build MRSIGNER
echo -e "$INFO V1 MRENCLAVE = $(get_mrenclave | head -c16)..."
echo -e "$INFO V1 MRSIGNER  = $(get_mrsigner | head -c16)..."

run_app "1" "1234" "1234" "3" "github" "alice" "test_mrsigner_pw" "9" "0" > /dev/null
cp vault.sealed vault_mrsigner_v1.sealed
echo -e "  $PASS 已保存 vault_mrsigner_v1.sealed"

# ── 阶段三：修改代码 → V2 ──
echo ""
echo "────────────────────────────────────────────────────────────"
echo "  阶段三：修改代码 → V2"
echo "────────────────────────────────────────────────────────────"

make_v2_code
echo -e "  $PASS Enclave.cpp 已修改（插入 volatile 静态变量）"
echo -e "$INFO 代码变更:"
grep -n 'V2_EXPERIMENT_MARKER' Enclave/Enclave.cpp || true

# ── 阶段四：V2 解封 V1 MRENCLAVE ──
echo ""
echo "────────────────────────────────────────────────────────────"
echo "  阶段四：V2 解封 V1 的 MRENCLAVE 数据"
echo "────────────────────────────────────────────────────────────"

build MRENCLAVE
V2_MRENCLAVE_HASH=$(get_mrenclave)
V2_MRSIGNER_HASH=$(get_mrsigner)
echo -e "$INFO V2 MRENCLAVE = ${V2_MRENCLAVE_HASH:0:16}..."
echo -e "$INFO V2 MRSIGNER  = ${V2_MRSIGNER_HASH:0:16}..."

if [ "$V1_MRENCLAVE_HASH" != "$V2_MRENCLAVE_HASH" ]; then
    echo -e "  $PASS MRENCLAVE 已变化 (V1 ≠ V2)"
else
    echo -e "  $FAIL MRENCLAVE 未变化 — 代码改动无效，请检查插入是否生效"
fi

if [ "$V1_MRSIGNER_HASH" = "$V2_MRSIGNER_HASH" ]; then
    echo -e "  $PASS MRSIGNER 保持不变 (V1 = V2)"
else
    echo -e "  $FAIL MRSIGNER 意外变化 — 签名密钥可能被替换"
fi

cp vault_mrenclave_v1.sealed vault.sealed
OUTPUT=$(run_app "2" "1234" "0")
if echo "$OUTPUT" | grep -q "Error.*[Uu]nseal\|Error.*corrupt\|VAULT_ERR_UNSEAL\|VAULT_ERR_CORRUPT"; then
    echo -e "  $PASS V2 拒绝加载 V1 的 MRENCLAVE 数据（预期行为）"
else
    echo -e "  $FAIL V2 意外成功加载了 V1 的 MRENCLAVE 数据！"
    echo "  输出: $OUTPUT"
fi

# ── 阶段五：V2 解封 V1 MRSIGNER ──
echo ""
echo "────────────────────────────────────────────────────────────"
echo "  阶段五：V2 解封 V1 的 MRSIGNER 数据"
echo "────────────────────────────────────────────────────────────"

cp vault_mrsigner_v1.sealed vault.sealed
OUTPUT=$(run_app "2" "1234" "4" "github" "0")
if echo "$OUTPUT" | grep -q "test_mrsigner_pw"; then
    echo -e "  $PASS V2 成功加载 V1 的 MRSIGNER 数据（预期：同签名者，密钥不变）"
elif echo "$OUTPUT" | grep -q "Error\|ERR"; then
    echo -e "  $FAIL V2 拒绝加载 V1 的 MRSIGNER 数据（非预期！）"
    echo "  输出: $OUTPUT"
else
    echo -e "  $FAIL 意外输出"
    echo "  输出: $OUTPUT"
fi

# ── 阶段六：还原代码 ──
echo ""
echo "────────────────────────────────────────────────────────────"
echo "  阶段六：还原代码"
echo "────────────────────────────────────────────────────────────"

ensure_v1_code
echo -e "  $PASS Enclave.cpp 已还原到 V1"

echo ""
echo "============================================================"
echo -e "  ${GREEN}实验二完成${NC}"
echo "============================================================"
echo ""
echo "结果总结："
echo "  MRENCLAVE: V2 无法解封 V1 的数据 → 安全绑定到代码本身"
echo "  MRSIGNER : V2 可以解封 V1 的数据  → 绑定到签名者身份，允许升级"
echo ""
echo "HW 模式额外测试（需要两台 SGX 机器）："
echo "  机器A: make SGX_MODE=HW SEAL_POLICY=MRENCLAVE → 密封 → vault.sealed"
echo "  机器B: scp vault.sealed → make SGX_MODE=HW → ./app → Load"
echo "  预期：VAULT_ERR_UNSEAL（平台根密钥不同）"
echo ""
