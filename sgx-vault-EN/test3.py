#!/usr/bin/env python3
"""
侧信道时间攻击测试脚本 (SGX 密码库)
测量 ecall_vault_login 的响应时间，利用 memcmp 非恒定时间特性区分 PIN。
"""

import pexpect
import time
import os
import sys
import statistics
import shutil

# 配置
PROG = "./app"                  # 编译后的宿主程序
SEALED_FILE = "vault.sealed"    # 密封文件存储路径
CORRECT_PIN = "12345678"            # 创建密码库时使用的 PIN
# 候选 PIN：正确 PIN、仅最后一位不同、首字符不同、完全不同的 PIN
CANDIDATE_PINS = [CORRECT_PIN, "12356789", "02345678", "99999999"]
NUM_MEASUREMENTS = 10           # 每个候选 PIN 的测量次数
TIMEOUT = 10                    # pexpect 超时（秒）


def create_vault_and_save():
    """创建密码库并保存为密封文件（使用 CORRECT_PIN）"""
    if os.path.exists(SEALED_FILE):
        os.remove(SEALED_FILE)

    child = pexpect.spawn(PROG, timeout=TIMEOUT, encoding='utf-8')
    try:
        child.expect("Choice: ")
        child.sendline("1")
        child.expect("Set a PIN for the vault .*: ")
        child.sendline(CORRECT_PIN)
        child.expect("Confirm PIN: ")
        child.sendline(CORRECT_PIN)
        child.expect("Choice: ")
        child.sendline("9")          # 保存
        child.expect("Choice: ")
        child.sendline("0")          # 退出
        child.expect(pexpect.EOF)
    except Exception as e:
        print(f"Failed to create the vault: {e}")
        sys.exit(1)
    finally:
        child.close()
    print(f"[+] Vault created with PIN = {CORRECT_PIN}; sealed file saved as {SEALED_FILE}")


def measure_login(pin):
    """
    测量加载密码库并尝试登录指定 PIN 的耗时（秒）
    返回从发送 PIN 到收到登录结果的时间。
    """
    child = pexpect.spawn(PROG, timeout=TIMEOUT, encoding='utf-8')
    try:
        # 等待主菜单
        child.expect("Choice: ")
        child.sendline("2")                     # 加载
        # 等待 PIN 输入提示
        child.expect("PIN: ")
        # 开始计时
        t0 = time.perf_counter()
        child.sendline(pin)
        # 等待登录结果（成功或失败）
        idx = child.expect(["Login successful", "Invalid PIN"], timeout=TIMEOUT)
        t1 = time.perf_counter()
        elapsed = t1 - t0
        return elapsed
    except Exception as e:
        print(f"An error occurred while measuring PIN '{pin}': {e}")
        return None
    finally:
        # 强制终止进程（避免后续交互干扰）
        child.terminate(force=True)


def main():
    # 确保密封文件存在（首次运行创建）
    if not os.path.exists(SEALED_FILE):
        create_vault_and_save()
    else:
        print(f"[+] Using the existing sealed file: {SEALED_FILE}")

    results = {pin: [] for pin in CANDIDATE_PINS}

    for pin in CANDIDATE_PINS:
        print(f"\n[*] Measuring PIN: {pin}")
        for i in range(NUM_MEASUREMENTS):
            t = measure_login(pin)
            if t is not None:
                results[pin].append(t)
                print(f"    Run {i+1}: {t*1000:.3f} ms")
            else:
                print(f"    Run {i+1}: failed")
        # 统计
        times = results[pin]
        if times:
            avg = statistics.mean(times)
            stdev = statistics.stdev(times) if len(times) > 1 else 0.0
            print(f"    Avg: {avg*1000:.3f} ms, Std: {stdev*1000:.3f} ms")
        else:
            print("    No valid measurements")

    # 输出汇总
    print("\n[=] Summary (average response time):")
    for pin, times in results.items():
        if times:
            avg = statistics.mean(times)
            print(f"    PIN '{pin}': {avg*1000:.3f} ms")
        else:
            print(f"    PIN '{pin}': N/A")

    # 简单判断是否可区分
    correct_avg = statistics.mean(results[CORRECT_PIN]) if results[CORRECT_PIN] else None
    if correct_avg:
        wrong_avgs = [statistics.mean(times) for pin, times in results.items()
                      if pin != CORRECT_PIN and times]
        if wrong_avgs and all(correct_avg > w for w in wrong_avgs):
            print("\n[!] The correct PIN took significantly longer than the incorrect PINs, indicating a timing side-channel vulnerability!")
        else:
            print("\n[?] No clear difference was observed. Try increasing the number of measurements or adjusting the candidate PINs.")
    else:
        print("\n[?] The correct PIN measurement failed, so no conclusion can be made.")


if __name__ == "__main__":
    main()
