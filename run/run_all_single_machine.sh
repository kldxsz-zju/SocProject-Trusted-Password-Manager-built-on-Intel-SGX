#!/usr/bin/env bash
#
# Usage / 使用方法:
#   chmod +x run/*.sh
#   ./run/run_all_single_machine.sh
#
# Runs Test 1, Test 2, Test 3, Experiment 2, and the single-machine
# portion of Experiment 3.
# 运行 Test 1、Test 2、Test 3、实验 2，以及实验 3 的单机部分。
#
set -uo pipefail

RUN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$RUN_DIR/.." && pwd)"
VAULT_DIR="$PROJECT_ROOT/sgx-vault-EN"
SDK_ENV="/opt/intel/sgxsdk/environment"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="$RUN_DIR/logs/single-$TIMESTAMP"
MODE="${SGX_MODE:-}"
PASSED=0
FAILED=0
RESULTS=()

if [[ ! -d "$VAULT_DIR" ]]; then
    echo "[致命错误/FATAL] 找不到项目目录 / Project directory not found: $VAULT_DIR" >&2
    exit 1
fi

if [[ -f "$SDK_ENV" ]]; then
    # shellcheck disable=SC1091
    source "$SDK_ENV"
else
    echo "[致命错误/FATAL] 找不到 Intel SGX SDK 环境 / SDK environment not found: $SDK_ENV" >&2
    exit 1
fi

for command_name in make python3 tee; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "[致命错误/FATAL] 缺少命令 / Required command not found: $command_name" >&2
        exit 1
    fi
done

if ! python3 -c 'import pexpect' >/dev/null 2>&1; then
    echo "[致命错误/FATAL] test2.py 和 test3.py 需要 Python pexpect 包。" >&2
    echo "[FATAL] test2.py and test3.py require the Python pexpect package." >&2
    echo "        python3 -m pip install pexpect" >&2
    exit 1
fi

if [[ -z "$MODE" ]]; then
    if [[ -e /dev/sgx_enclave ]]; then
        MODE="HW"
    else
        MODE="SIM"
    fi
fi

if [[ "$MODE" != "SIM" && "$MODE" != "HW" ]]; then
    echo "[致命错误/FATAL] SGX_MODE 必须是 SIM 或 HW / must be SIM or HW." >&2
    exit 1
fi

mkdir -p "$LOG_DIR"

run_step() {
    local name="$1"
    local log_name="$2"
    local description_zh="$3"
    local description_en="$4"
    shift 4

    echo
    echo "================================================================"
    echo "[运行/RUN] $name"
    echo "[说明] $description_zh"
    echo "[INFO] $description_en"
    echo "================================================================"

    set +e
    "$@" 2>&1 | tee "$LOG_DIR/$log_name"
    local rc=${PIPESTATUS[0]}
    set -e

    if [[ $rc -eq 0 ]]; then
        echo "[通过/PASS] $name"
        RESULTS+=("PASS|$name")
        PASSED=$((PASSED + 1))
    else
        echo "[失败/FAIL] $name (exit code: $rc)"
        RESULTS+=("FAIL|$name")
        FAILED=$((FAILED + 1))
    fi
}

echo "SGX 密码库单机一键测试 / SGX Vault One-click Single-machine Test"
echo "主机/Host       : $(hostname)"
echo "模式/Mode       : $MODE"
echo "项目/Project    : $VAULT_DIR"
echo "日志/Log folder : $LOG_DIR"

cd "$VAULT_DIR"
run_step "Build SGX Vault ($MODE)" "00-build.log" \
    "编译密码库程序和 SGX Enclave，为后续测试准备可执行文件。" \
    "Build the vault application and SGX enclave for the following tests." \
    make --no-print-directory clean all SGX_MODE="$MODE" SGX_DEBUG=1 SEAL_POLICY=MRENCLAVE

if [[ -x "$VAULT_DIR/app" ]]; then
    run_step "Test 1 - Sealed-data confidentiality and integrity" "01-test1.log" \
        "检查密封文件是否泄露明文，并通过篡改密封数据验证完整性防御。" \
        "Check for plaintext leakage and verify integrity protection by tampering with sealed data." \
        python3 "$VAULT_DIR/test1.py"

    run_step "Test 2 - Brute-force and rollback attacks" "02-test2.log" \
        "执行 PIN 暴力破解和旧版密封文件回滚攻击，观察系统的攻击面。" \
        "Run PIN brute-force and old sealed-file rollback attacks to observe the attack surface." \
        python3 "$VAULT_DIR/test2.py"

    rm -f "$VAULT_DIR/vault.sealed"
    run_step "Test 3 - Timing side-channel attack" "03-test3.log" \
        "测量不同 PIN 的登录响应时间，判断是否存在可区分的时间侧信道。" \
        "Measure login times for different PINs to detect a distinguishable timing side channel." \
        python3 "$VAULT_DIR/test3.py"
else
    echo "[失败/FAIL] app 未成功构建，跳过 Test 1、Test 2 和 Test 3。"
    echo "[FAIL] app was not built; Test 1, Test 2, and Test 3 were skipped."
    RESULTS+=("FAIL|Test 1 - app unavailable")
    RESULTS+=("FAIL|Test 2 - app unavailable")
    RESULTS+=("FAIL|Test 3 - app unavailable")
    FAILED=$((FAILED + 3))
fi

run_step "Experiment 2 - MRENCLAVE vs MRSIGNER ($MODE)" "04-exp2.log" \
    "对比 MRENCLAVE 与 MRSIGNER 密封策略在代码升级后的数据解封行为。" \
    "Compare how MRENCLAVE and MRSIGNER sealing policies behave after a code upgrade." \
    bash "$VAULT_DIR/bin/exp2_mrenclave_vs_mrsigner copy.sh" "$MODE"

if [[ -e /dev/sgx_enclave ]]; then
    run_step "Experiment 3 - Single-machine unprotected HW rollback" "05-exp3-single.log" \
        "在真实 SGX 硬件上回放合法旧密封文件，演示无远程见证时的回滚攻击。" \
        "Replay a valid old sealed file on real SGX hardware to demonstrate rollback without a remote witness." \
        bash "$VAULT_DIR/bin/run_hw_attack.sh"
else
    echo
    echo "[失败/FAIL] 实验 3 需要 /dev/sgx_enclave，不能在 SIM 模式运行。"
    echo "[FAIL] Experiment 3 requires /dev/sgx_enclave and cannot run in SIM mode."
    RESULTS+=("FAIL|Experiment 3 - SGX hardware unavailable")
    FAILED=$((FAILED + 1))
fi

echo
echo "================================================================"
echo "测试汇总 / Test Summary"
echo "================================================================"
for result in "${RESULTS[@]}"; do
    printf '[%s] %s\n' "${result%%|*}" "${result#*|}"
done
echo "通过/Passed: $PASSED"
echo "失败/Failed: $FAILED"
echo "日志/Logs  : $LOG_DIR"

if [[ $FAILED -ne 0 ]]; then
    exit 1
fi

