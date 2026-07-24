#!/usr/bin/env bash
#
# Usage / 使用方法:
#   chmod +x run/*.sh
#   ./run/run_all_single_machine.sh
#
# Select one test or the web frontend from the bilingual menu. After a test
# finishes, press Enter to return to the menu and select another item.
# 从双语菜单中选择测试或 Web 前端。每项测试完成后按 Enter 返回菜单。
#
set -uo pipefail

RUN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$RUN_DIR/.." && pwd)"
VAULT_DIR="$PROJECT_ROOT/sgx-vault-EN"
SDK_ENV="/opt/intel/sgxsdk/environment"
SESSION_TIME="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="$RUN_DIR/logs/single-$SESSION_TIME"
MODE="${SGX_MODE:-}"
LOCAL_WITNESS_PORT="${LOCAL_WITNESS_PORT:-18765}"

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
NC='\033[0m'

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
cd "$VAULT_DIR"

show_stage() {
    local color="$1"
    local category="$2"
    local title="$3"
    local description_zh="$4"
    local description_en="$5"

    echo
    printf "${color}========================================================================${NC}\n"
    printf "${color}[%s] %s${NC}\n" "$category" "$title"
    printf "${color}[说明] %s${NC}\n" "$description_zh"
    printf "${color}[INFO] %s${NC}\n" "$description_en"
    printf "${color}========================================================================${NC}\n"
    echo
}

run_logged() {
    local log_name="$1"
    shift

    set +e
    "$@" 2>&1 | tee "$LOG_DIR/$(date +%H%M%S)-$log_name"
    local rc=${PIPESTATUS[0]}
    set -e

    echo
    if [[ $rc -eq 0 ]]; then
        printf "${GREEN}[通过/PASS] Completed successfully.${NC}\n"
    else
        printf "${RED}[失败/FAIL] Exit code: %s${NC}\n" "$rc"
    fi
    return 0
}

build_for_python_test() {
    echo "[BUILD] SGX_MODE=$MODE, SEAL_POLICY=MRENCLAVE"
    make --no-print-directory clean >/dev/null 2>&1 || true
    make --no-print-directory all SGX_MODE="$MODE" SGX_DEBUG=1 SEAL_POLICY=MRENCLAVE
}

run_python_test() {
    local script_name="$1"
    local log_name="$2"

    if ! build_for_python_test; then
        printf "${RED}[失败/FAIL] Build failed; the test was not started.${NC}\n"
        return
    fi
    if [[ "$script_name" == "test3.py" ]]; then
        rm -f "$VAULT_DIR/vault.sealed"
    fi
    run_logged "$log_name" python3 "$VAULT_DIR/$script_name"
}

run_local_rollback_defense() {
    local server_log="$LOG_DIR/local-witness-server.log"
    local witness_db="$LOG_DIR/local-witness-versions.db"
    local server_pid
    local client_rc
    local vault_id
    local ready=0

    rm -f "$witness_db" "$witness_db.tmp"
    bash "$VAULT_DIR/bin/run_hw_server.sh" \
        "$LOCAL_WITNESS_PORT" "$witness_db" >"$server_log" 2>&1 &
    server_pid=$!

    for _ in $(seq 1 30); do
        if ! kill -0 "$server_pid" 2>/dev/null; then
            echo "[FAIL] The local witness server exited before becoming ready."
            cat "$server_log"
            wait "$server_pid" 2>/dev/null || true
            return 1
        fi
        if python3 -c \
            "import socket; s=socket.create_connection(('127.0.0.1', $LOCAL_WITNESS_PORT), 0.2); s.close()" \
            >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 1
    done

    if [[ $ready -ne 1 ]]; then
        echo "[FAIL] Timed out while waiting for the local witness server."
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
        cat "$server_log"
        return 1
    fi

    echo "[INFO] Local witness server is ready at 127.0.0.1:$LOCAL_WITNESS_PORT."
    vault_id="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
    echo "[INFO] Experiment vault ID: $vault_id"

    bash "$VAULT_DIR/bin/run_hw_protected_client.sh" \
        "127.0.0.1" "$LOCAL_WITNESS_PORT" "$vault_id"
    client_rc=$?

    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    echo "[INFO] Local witness server log:"
    cat "$server_log"
    return "$client_rc"
}

pause_for_menu() {
    echo
    read -r -p "按 Enter 返回菜单 / Press Enter to return to the menu... " _
}

show_menu() {
    clear 2>/dev/null || true
    printf "${WHITE}SGX 密码库单机测试菜单 / SGX Vault Single-machine Test Menu${NC}\n"
    echo "主机/Host       : $(hostname)"
    echo "模式/Mode       : $MODE"
    echo "日志/Logs       : $LOG_DIR"
    echo
    printf "${GREEN}  1) Test 1 - 密封数据机密性与完整性防御 / Sealed-data confidentiality and integrity defense${NC}\n"
    printf "${RED}  2) Test 2 - PIN 暴力破解与回滚攻击 / PIN brute-force and rollback attacks${NC}\n"
    printf "${RED}  3) Test 3 - 时间侧信道攻击 / Timing side-channel attack${NC}\n"
    printf "${GREEN}  4) 侧信道防护测试 / Side-channel defense test${NC}\n"
    printf "${GREEN}  5) Exp2   - MRENCLAVE 与 MRSIGNER 密封策略防御对比 / Sealing-policy defense comparison${NC}\n"
    printf "${RED}  6) Exp3   - 单机无防护硬件回滚攻击 / Single-machine unprotected HW rollback attack${NC}\n"
    printf "${GREEN}  7) Exp3   - 单机远程见证回滚防护 / Single-machine witness rollback defense${NC}\n"
    printf "${CYAN}  8) 展示 Web 前端 / Show the web frontend${NC}\n"
    printf "${YELLOW}  0) 退出 / Exit${NC}\n"
    echo
}

while true; do
    show_menu
    read -r -p "请选择 / Select an option: " choice

    case "$choice" in
        1)
            show_stage "$GREEN" "防御测试/DEFENSE TEST" \
                "Test 1 - Sealed-data confidentiality and integrity" \
                "检查密封文件是否泄露明文，并通过篡改密封数据验证完整性防御。" \
                "Check for plaintext leakage and verify integrity protection by tampering with sealed data."
            run_python_test "test1.py" "test1.log"
            pause_for_menu
            ;;
        2)
            show_stage "$RED" "攻击测试/ATTACK TEST" \
                "Test 2 - Brute-force and rollback attacks" \
                "执行 PIN 暴力破解和旧版密封文件回滚攻击，观察系统的攻击面。" \
                "Run PIN brute-force and old sealed-file rollback attacks to observe the attack surface."
            run_python_test "test2.py" "test2.log"
            pause_for_menu
            ;;
        3)
            show_stage "$RED" "攻击测试/ATTACK TEST" \
                "Test 3 - Timing side-channel attack" \
                "测量不同 PIN 的登录响应时间，判断是否存在可区分的时间侧信道。" \
                "Measure login times for different PINs to detect a distinguishable timing side channel."
            run_python_test "test3.py" "test3.log"
            pause_for_menu
            ;;
        4)
            show_stage "$GREEN" "防御测试/DEFENSE TEST" \
                "Side-channel Defense - Oblivious Access Core" \
                "测试防护核心的固定槽位扫描和一致逻辑访问次数，验证数据无关访问防护。" \
                "Test fixed-slot scanning and identical logical access counts in the oblivious-access defense core."
            run_logged "side-channel-defense.log" \
                make --no-print-directory -C "$VAULT_DIR/side_channel_defense" clean test
            pause_for_menu
            ;;
        5)
            show_stage "$GREEN" "防御测试/DEFENSE TEST" \
                "Experiment 2 - MRENCLAVE vs MRSIGNER ($MODE)" \
                "对比 MRENCLAVE 与 MRSIGNER 密封策略在代码升级后的数据解封行为。" \
                "Compare how MRENCLAVE and MRSIGNER sealing policies behave after a code upgrade."
            run_logged "exp2.log" \
                bash "$VAULT_DIR/bin/exp2_mrenclave_vs_mrsigner copy.sh" "$MODE"
            pause_for_menu
            ;;
        6)
            show_stage "$RED" "攻击测试/ATTACK TEST" \
                "Experiment 3 - Single-machine unprotected HW rollback" \
                "在真实 SGX 硬件上回放合法旧密封文件，演示无远程见证时的回滚攻击。" \
                "Replay a valid old sealed file on real SGX hardware to demonstrate rollback without a remote witness."
            if [[ -e /dev/sgx_enclave ]]; then
                run_logged "exp3-single.log" bash "$VAULT_DIR/bin/run_hw_attack.sh"
            else
                printf "${RED}[失败/FAIL] Exp3 需要真实 SGX 硬件和 /dev/sgx_enclave。${NC}\n"
                printf "${RED}[FAIL] Exp3 requires real SGX hardware and /dev/sgx_enclave.${NC}\n"
            fi
            pause_for_menu
            ;;
        7)
            show_stage "$GREEN" "防御测试/DEFENSE TEST" \
                "Experiment 3 - Local Witness Rollback Defense" \
                "在本机启动独立版本见证服务，回放旧密封文件并验证读取密码前拒绝回滚。" \
                "Start a local version witness, replay an old sealed file, and verify rollback rejection before password access."
            if [[ -e /dev/sgx_enclave ]]; then
                run_logged "exp3-local-defense.log" run_local_rollback_defense
            else
                printf "${RED}[失败/FAIL] 回滚防护实验需要真实 SGX 硬件和 /dev/sgx_enclave。${NC}\n"
                printf "${RED}[FAIL] The rollback-defense experiment requires real SGX hardware and /dev/sgx_enclave.${NC}\n"
            fi
            pause_for_menu
            ;;
        8)
            show_stage "$CYAN" "前端展示/FRONTEND" \
                "SGX Vault Web Frontend" \
                "启动后端并在默认浏览器中打开 Web 前端；在终端按 Ctrl+C 停止后返回菜单。" \
                "Start the backend and open the web frontend; press Ctrl+C in the terminal to stop it and return."
            set +e
            bash "$VAULT_DIR/front/start.sh" --browser
            set -e
            pause_for_menu
            ;;
        0)
            echo
            echo "已退出。日志保存在 / Exited. Logs are stored in: $LOG_DIR"
            exit 0
            ;;
        *)
            printf "${YELLOW}无效选项，请重新选择。/ Invalid option; please try again.${NC}\n"
            sleep 1
            ;;
    esac
done
