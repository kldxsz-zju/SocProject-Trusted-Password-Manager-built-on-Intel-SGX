#!/usr/bin/env bash
#
# Usage / 使用方法:
#   chmod +x run/*.sh
#   ./run/run_exp3_two_machines.sh
#
# Run this script on both Ubuntu machines. Select B on the witness-server
# machine first, then select A on the SGX client machine.
# 在两台 Ubuntu 机器上运行本脚本。先在见证服务器上选择 B，再在 SGX
# 客户端机器上选择 A。
#
set -euo pipefail

RUN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$RUN_DIR/.." && pwd)"
VAULT_DIR="$PROJECT_ROOT/sgx-vault-EN"
BIN_DIR="$VAULT_DIR/bin"
SDK_ENV="/opt/intel/sgxsdk/environment"
WITNESS_PORT="${WITNESS_PORT:-8765}"
DISCOVERY_PORT="${DISCOVERY_PORT:-48765}"
DISCOVERY_MAGIC="SGX_VAULT_EXP3_WITNESS_V1"
DISCOVERY_TIMEOUT="${DISCOVERY_TIMEOUT:-180}"
HOST_NAME="$(hostname)"

if [[ ! -d "$VAULT_DIR" ]]; then
    echo "[致命错误/FATAL] 找不到项目目录 / Project directory not found: $VAULT_DIR" >&2
    exit 1
fi

for command_name in python3 hostname; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "[致命错误/FATAL] 缺少命令 / Required command not found: $command_name" >&2
        exit 1
    fi
done

read -r -p "选择本机角色 / Select role (A = SGX client, B = witness server): " ROLE
ROLE="${ROLE^^}"
LOCAL_IPS="$(hostname -I 2>/dev/null | xargs || true)"

case "$ROLE" in
    A)
        echo
        echo "SGX 回滚攻击与远程见证防护 / SGX Rollback Attack and Remote-witness Defense"
        echo "[身份/ROLE] 机器 A：SGX 客户端 / Machine A: SGX client"
        echo "[主机/HOST] $HOST_NAME"
        echo "[本机 IP/LOCAL IP] ${LOCAL_IPS:-unavailable}"

        if [[ ! -e /dev/sgx_enclave ]]; then
            echo "[致命错误/FATAL] 角色 A 需要 /dev/sgx_enclave / Role A requires SGX hardware." >&2
            exit 1
        fi
        if [[ ! -f "$SDK_ENV" ]]; then
            echo "[致命错误/FATAL] 找不到 Intel SGX SDK 环境 / SDK environment not found: $SDK_ENV" >&2
            exit 1
        fi
        # shellcheck disable=SC1091
        source "$SDK_ENV"

        echo
        echo "[说明] 正在通过局域网自动发现机器 B 的远程见证服务。"
        echo "[INFO] Automatically discovering machine B's remote witness service on the LAN."
        DISCOVERY_RESULT="$(
            DISCOVERY_MAGIC="$DISCOVERY_MAGIC" \
            DISCOVERY_PORT="$DISCOVERY_PORT" \
            DISCOVERY_TIMEOUT="$DISCOVERY_TIMEOUT" \
            python3 - <<'PY'
import os
import socket
import sys
import time

magic = os.environ["DISCOVERY_MAGIC"]
port = int(os.environ["DISCOVERY_PORT"])
deadline = time.monotonic() + int(os.environ["DISCOVERY_TIMEOUT"])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("", port))
sock.settimeout(1.0)

while time.monotonic() < deadline:
    try:
        payload, address = sock.recvfrom(1024)
    except socket.timeout:
        continue
    message = payload.decode("utf-8", errors="replace").strip().split("|")
    if len(message) == 4 and message[0] == magic:
        print(f"{address[0]}|{message[1]}|{message[3]}")
        sys.exit(0)
sys.exit(1)
PY
        )" || {
            echo "[致命错误/FATAL] 未发现机器 B / Machine B was not discovered." >&2
            echo "请确认两台机器位于同一局域网且 UDP $DISCOVERY_PORT 已放行。" >&2
            echo "Ensure both machines are on the same LAN and UDP $DISCOVERY_PORT is allowed." >&2
            exit 1
        }

        IFS='|' read -r WITNESS_HOST WITNESS_NAME WITNESS_PORT <<<"$DISCOVERY_RESULT"
        echo "[信息/INFO] 已发现机器 B / Discovered B: $WITNESS_NAME ($WITNESS_HOST:$WITNESS_PORT)"

        echo
        echo "[说明] 正在回放合法的旧版 SGX 密封文件，演示没有远程见证时回滚攻击能够成功。"
        echo "[INFO] Replaying a valid old SGX sealed file to demonstrate that rollback succeeds without a remote witness."
        bash "$BIN_DIR/run_hw_attack.sh"

        VAULT_ID="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
        )"
        echo
        echo "[说明] 正在启用远程版本见证并再次回放旧文件，验证系统会在读取密码前拒绝回滚。"
        echo "[INFO] Enabling the remote witness and replaying the old file to verify fail-closed rollback defense."
        echo "[信息/INFO] 密码库 ID / Vault ID: $VAULT_ID"
        bash "$BIN_DIR/run_hw_protected_client.sh" \
            "$WITNESS_HOST" "$WITNESS_PORT" "$VAULT_ID"

        echo
        echo "[通过/PASS] 机器 A 已完成无防护攻击和远程见证防御测试。"
        echo "[PASS] Machine A completed the unprotected attack and remote-witness defense tests."
        ;;

    B)
        echo
        echo "远程见证回滚防护服务器 / Remote-witness Rollback-defense Server"
        echo "[身份/ROLE] 机器 B：见证服务器 / Machine B: witness server"
        echo "[主机/HOST] $HOST_NAME"
        echo "[本机 IP/LOCAL IP] ${LOCAL_IPS:-unavailable}"

        BROADCAST_PID=""
        cleanup() {
            if [[ -n "$BROADCAST_PID" ]]; then
                kill "$BROADCAST_PID" 2>/dev/null || true
                wait "$BROADCAST_PID" 2>/dev/null || true
            fi
        }
        trap cleanup EXIT INT TERM

        echo
        echo "[说明] 正在广播本机 hostname 和见证端口，供机器 A 自动发现。"
        echo "[INFO] Broadcasting this hostname and witness port so machine A can discover it automatically."
        DISCOVERY_MAGIC="$DISCOVERY_MAGIC" \
        DISCOVERY_PORT="$DISCOVERY_PORT" \
        WITNESS_PORT="$WITNESS_PORT" \
        HOST_NAME="$HOST_NAME" \
        python3 - <<'PY' &
import os
import socket
import time

magic = os.environ["DISCOVERY_MAGIC"]
discovery_port = int(os.environ["DISCOVERY_PORT"])
witness_port = os.environ["WITNESS_PORT"]
hostname = os.environ["HOST_NAME"]
payload = f"{magic}|{hostname}|auto|{witness_port}".encode()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

while True:
    sock.sendto(payload, ("255.255.255.255", discovery_port))
    time.sleep(1)
PY
        BROADCAST_PID=$!

        echo
        echo "[说明] 正在启动远程版本见证服务器，保存最新可信版本并为机器 A 检测回滚。"
        echo "[INFO] Starting the remote witness to store trusted versions and detect rollback for machine A."
        echo "[信息/INFO] TCP 端口 / TCP port: $WITNESS_PORT"
        echo "[提示/NOTICE] 请保持脚本运行；机器 A 完成后按 Ctrl+C 停止。"
        echo "[NOTICE] Keep this script running; press Ctrl+C after machine A finishes."
        cd "$BIN_DIR"
        bash "$BIN_DIR/run_hw_server.sh" "$WITNESS_PORT" "$BIN_DIR/witness_versions.db"
        ;;

    *)
        echo "[致命错误/FATAL] 角色无效，请重新运行并输入 A 或 B。" >&2
        echo "[FATAL] Invalid role. Run the script again and enter A or B." >&2
        exit 2
        ;;
esac
