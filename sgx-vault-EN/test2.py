#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SGX Password Vault - Attack Tests
包括：暴力破解、回滚、克隆、侧信道
"""

import os
import sys
import subprocess
import select
import time
import shutil
import random
import threading
import queue
import pexpect
import time
from collections import Counter

APP_PATH = "./app"
SEALED_FILE = "vault.sealed"
BACKUP_FILE = "vault.sealed.backup"
TIMEOUT = 0.02
SERVICE = "testservice"
USERNAME = "testuser"
PASSWORD = "testpass123"
SERVICE_1 = "testservice1"
USERNAME_1 = "testuser1"
PASSWORD_1 = "testpass123"
VAULTPASSWORD = "1234"

def send_commands(commands, timeout=TIMEOUT):
    """
    启动应用程序，依次发送命令（列表），并捕获所有输出。
    每个命令应包含换行符。
    返回程序的标准输出字符串。
    """
    proc = subprocess.Popen(
        [APP_PATH],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    output = ""
    # 发送所有命令
    proc.stdin.flush()
    while True:
        ready, _, _ = select.select([proc.stdout], [], [], timeout)
        if not ready:
            break
        chunk = proc.stdout.read(1)
        if not chunk:
            break
    # print(output);
    # print("\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n")
    for cmd in commands:
        start_pos = len(output)
        # 读取输出直到出现 "Choice:" 提示（或程序退出）
        proc.stdin.write(cmd)
        proc.stdin.flush()
        # print(output);
        # print(cmd);
        # print("\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n")
        while True:
            ready, _, _ = select.select([proc.stdout], [], [], timeout)
            if not ready:
                break
            chunk = proc.stdout.read(1)
            if not chunk:
                break
            output += chunk
            if 'Login successful.' in output:
                break
        if 'Login successful.' in output:
            break;
    # print(output);
    # print("\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n")
    print(commands)
    proc.stdin.write('0\n')
    proc.stdin.flush()
    proc.wait(timeout=timeout)
    return output

def load_vault(pin, attempts=1):
    """加载vault并尝试PIN（自动尝试3次）"""
    cmds = ['2\n', pin + '\n']
    output = send_commands(cmds)
    return output

def add_credential(service, username, password):
    """添加凭据（需先加载解锁）"""
    cmds = [
        '3',
        service,
        username,
        password,
        '0'
    ]
    output = send_commands(cmds)
    return output

def get_credential(service):
    """获取凭据"""
    cmds = ['4', service, '0']
    output = send_commands(cmds)
    return output

def save_vault():
    cmds = ['9', '0']
    output = send_commands(cmds)
    return output

def test_bruteforce():
    """暴力破解测试：启动app → load vault → 输错三次锁定 → 使用L登录暴力枚举"""
    print("[*] Brute-force attack test (manual workflow simulation)")
    
    brute_commands = ['2\n'];
    found = False
    common_pins = [f"{i:04d}" for i in range(1000,2000)]

    attempts = 0
    for guess in common_pins:
        attempts += 1
        brute_commands.append(f'{int(guess)}\n')
        brute_commands.append('0\n')
        brute_commands.append('0\n')
        output = send_commands(brute_commands)
        brute_commands.pop()
        brute_commands.pop()
        brute_commands.pop()
        if "Login successful." in output:
            found  = True
            break
    
    if not found:
        print("\n[-] Brute-force attack failed after {} attempts".format(attempts))


def test_rollback():
    """回滚攻击测试"""
    print("[*] Rollback attack test")
    shutil.copy(SEALED_FILE, BACKUP_FILE)
    # 创建vault，添加记录A，保存
    roll_commands = [
            '2\n', 
            f'{VAULTPASSWORD}\n',
            '3\n',
            f'{SERVICE_1}\n',
            f'{USERNAME_1}\n',
            f'{PASSWORD_1}\n',
            '9\n'
            ]
    send_commands(roll_commands)
    # 现在用备份覆盖
    shutil.copy(BACKUP_FILE, SEALED_FILE)
    # 加载解锁
    roll_commands = [
            '2\n',
            f'{VAULTPASSWORD}\n',
            '7\n'
    ]
    out = send_commands(roll_commands)
    if "OK" in out:
        # 列出服务
        if "testservice" in out and "testservice1" not in out:
            print("[+] Rollback attack succeeded: the old state was restored")
        else:
            print("[-] Rollback attack failed")
    else:
        print("[-] Rollback attack failed due to a load error")

# def test_clone():
#     """克隆攻击：启动两个实例加载同一密封文件"""
#     print("[*] 克隆攻击测试")
#     # 先创建vault并保存
#     if not create_vault_with_pin("1234"):
#         return
#     add_credential("service1", "user1", "pass1")
#     save_vault()
#     # 启动两个进程
#     def run_instance(instance_id):
#         proc = subprocess.Popen(
#             [APP_PATH],
#             stdin=subprocess.PIPE,
#             stdout=subprocess.PIPE,
#             stderr=subprocess.STDOUT,
#             text=True,
#             bufsize=1
#         )
#         # 加载
#         proc.stdin.write('2\n1234\n')
#         proc.stdin.flush()
#         # 等待输出
#         time.sleep(2)
#         # 添加一条记录
#         proc.stdin.write('3\nclone{0}\nuser{0}\npass{0}\n'.format(instance_id))
#         proc.stdin.flush()
#         time.sleep(1)
#         proc.stdin.write('9\n0\n')
#         proc.stdin.flush()
#         proc.wait(timeout=5)
#         return proc.stdout.read()
#     threads = []
#     outputs = []
#     for i in range(2):
#         t = threading.Thread(target=lambda: outputs.append(run_instance(i)))
#         t.start()
#         threads.append(t)
#     for t in threads:
#         t.join()
#     # 检查两个实例是否都成功操作
#     for out in outputs:
#         if "OK" not in out:
#             print("[-] 克隆攻击：实例操作失败")
#         else:
#             print("[+] 克隆攻击：实例成功操作，可能存在竞争条件")
#     # 清理
#     os.remove(SEALED_FILE)

# def test_sidechannel_pagefault():
#     """侧信道：页错误模式分析"""
#     print("[*] 侧信道（页错误）测试")
#     # 创建vault，添加多个服务
#     if not create_vault_with_pin("1234"):
#         return
#     services = ["s1", "s2", "s3", "s4"]
#     for s in services:
#         add_credential(s, s+"user", s+"pass")
#     save_vault()
#     # 加载并解锁
#     out = load_vault("1234")
#     if "OK" not in out:
#         print("加载失败")
#         return
#     # 依次获取每个服务，统计页错误增量
#     # 使用getrusage获取页错误
#     # 由于我们无法在Python中直接获取子进程的页错误，我们可以通过解析/proc/pid/stat
#     # 或者通过app自身输出页错误（需要修改app）
#     # 这里我们简单演示思路：我们可以在app中埋点，输出页错误，或者使用系统工具
#     # 我们直接调用app并利用get_page_faults函数（之前App中有，但未输出）
#     # 可以修改app，在do_get前后输出页错误差异
#     # 下面代码假设app已修改，会输出"Page faults: X"
#     # 我们捕获输出并分析
#     proc = subprocess.Popen(
#         [APP_PATH],
#         stdin=subprocess.PIPE,
#         stdout=subprocess.PIPE,
#         stderr=subprocess.STDOUT,
#         text=True,
#         bufsize=1
#     )
#     # 加载
#     proc.stdin.write('2\n1234\n')
#     time.sleep(1)
#     # 获取每个服务
#     for s in services:
#         proc.stdin.write('4\n' + s + '\n')
#         time.sleep(0.5)
#     proc.stdin.write('0\n')
#     proc.stdin.flush()
#     output, _ = proc.communicate(timeout=5)
#     # 解析页故障输出（假设app打印了）
#     # 简单查找
#     if "Page faults" in output:
#         print("[*] 页错误数据:", output)
#     else:
#         print("[-] 未获取到页错误数据，需修改app打印")

def main():
    print("=== SGX Password Vault Attack Tests ===")
    if not os.path.exists(APP_PATH):
        print("Error: app not found")
        return
    # 清理旧文件
    for f in [SEALED_FILE, BACKUP_FILE, "vault_initial.sealed"]:
        if os.path.exists(f):
            os.remove(f)
    # 运行测试
    init_commands = [
            '1\n',                # Create vault
            f'{VAULTPASSWORD}\n', #Set password
            f'{VAULTPASSWORD}\n', #Confirm password
            '3\n',                # Add credential
            f'{SERVICE}\n',
            f'{USERNAME}\n',
            f'{PASSWORD}\n',
            '9\n',                # Save
        ]
    output = send_commands(init_commands)
    if "Error" in output or not os.path.exists(SEALED_FILE):
        print("Initialization failed. Please check the application.")
        print(output)
        sys.exit(1)
    print("✓ Password vault created and saved successfully.\n")
    #创建密码库
    test_bruteforce()
    test_rollback()
    # test_clone()
    # test_sidechannel_pagefault()

if __name__ == "__main__":
    main()
