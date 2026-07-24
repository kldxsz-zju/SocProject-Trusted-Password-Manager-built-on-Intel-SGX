#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SGX Password Vault - Attack Tests
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

def send_commands(proc, commands, timeout=TIMEOUT):
    """
    启动应用程序，依次发送命令（列表），并捕获所有输出。
    每个命令应包含换行符。
    返回程序的标准输出字符串。
    """
    output = ""
    # 发送所有命令
    for cmd in commands:
        # 读取输出直到出现 "Choice:" 提示（或程序退出）
        # print("\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n")
        while True:
            ready, _, _ = select.select([proc.stdout], [], [], timeout)
            if not ready:
                break
            chunk = proc.stdout.read(1)
            if not chunk:
                break
            output += chunk
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
    proc.stdin.flush()
    # print(output);
    # print("\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n")
    return output

def test_bruteforce():
    """暴力破解测试：启动app → load vault → 输错三次锁定 → 使用L登录暴力枚举"""
    print("[*] 暴力破解测试（手动流程模拟）")
    
    proc = subprocess.Popen(
        [APP_PATH],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    brute_commands = ['2\n'];
    found = False
    common_pins = [f"{i:04d}" for i in range(1000,2000)]

    attempts = 0
    for guess in common_pins:
        attempts += 1
        brute_commands.append(f'{int(guess)}\n')
        brute_commands.append('a\n')
        brute_commands.append('a\n')
        # print(brute_commands)
        output = send_commands(proc,brute_commands)
        brute_commands.pop()
        brute_commands.pop()
        brute_commands.pop()
        if "Login successful." in output:
            found  = True
            break
    send_commands(proc,'0\n')
    if not found:
        print("\n[-] 暴力破解失败，共尝试 {} 次".format(attempts))
    else:
        print("\n[+] 暴力破解成功，密码为 {}".format(guess))


def test_sidechannel_pagefault():
    """侧信道：页错误模式分析"""
    print("[*] 侧信道（页错误）测试")
    # 创建vault，添加多个服务

    proc1 = subprocess.Popen(
        [APP_PATH],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    commands = [
            '2\n',
            '1234\n'
        ]

    send_commands(proc1,commands)
    # if"Error:" in out:
    #     print("加载失败")
    # else:
    #     print("加载成功！")
    
    services = ["s1", "s2", "s3", "s4"]
    for s in services:
        commands = [
                '3\n',
                s, 
                s+"user", 
                s+"pass"
            ]
        out = send_commands(proc1,commands)
        # if"Error:" in out:
        #     print("添加密码失败")
        # if'OK' in out:
        #     print("添加成功")   

    commands = ['9\n', '0\n']
    out = send_commands(proc1,commands)
    proc1.wait(timeout=TIMEOUT)
    # if"Error:" in out:
    #     print("保存失败")
    # 加载并解锁
    # proc2 = subprocess.Popen(
    #     [APP_PATH],
    #     stdin=subprocess.PIPE,
    #     stdout=subprocess.PIPE,
    #     stderr=subprocess.STDOUT,
    #     text=True,
    #     bufsize=1
    # )
    # commands = [
    #     '2\n',
    #     '1234\n'
    # ]
    # out = send_commands(proc2,commands)
    # if "Error:" in out:
    #     print("加载失败")
    #     return
    # time.sleep(1)
    # # 获取每个服务
    # for s in services:
    #     result1 = subprocess.run(["perf probe 'sgx_encl_page_alloc%return ret=$retval'"], capture_output=True, text=True)
    #     proc2.stdin.write('4\n' + s + '\n')
    #     result2 = subprocess.run(["perf probe 'sgx_encl_page_alloc%return ret=$retval'"], capture_output=True, text=True)
    #     pagefault_count = result2 - result1
    #     print("[*] 页错误数据:", pagefault_count)
    #     time.sleep(0.5)
    # proc2.stdin.write('0\n')
    # proc2.stdin.flush()

def main():
    print("=== SGX密码库攻击测试 ===")
    if not os.path.exists(APP_PATH):
        print("错误：找不到app")
        return
    # 清理旧文件
    for f in [SEALED_FILE, BACKUP_FILE, "vault_initial.sealed"]:
        if os.path.exists(f):
            os.remove(f)
    # 运行测试

    proc = subprocess.Popen(
        [APP_PATH],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    init_commands = [
            '1\n',                # Create vault
            f'{VAULTPASSWORD}\n', #Set password
            f'{VAULTPASSWORD}\n', #Confirm password
            '3\n',                # Add credential
            f'{SERVICE}\n',
            f'{USERNAME}\n',
            f'{PASSWORD}\n',
            '9\n',                # Save
            '0\n'
        ]
    output = send_commands(proc,init_commands)
    proc.wait(timeout=TIMEOUT)
    if "Error" in output or not os.path.exists(SEALED_FILE):
        print("初始化失败，请检查应用程序。")
        print(output)
        sys.exit(1)
    print("✓ 密码库创建并保存成功。\n")

    proc = subprocess.Popen(
        [APP_PATH],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    commands = [
            '2\n',
            '1234\n',
            '0\n'
        ]
    send_commands(proc,commands)

    #创建密码库
    test_bruteforce()
    # test_sidechannel_pagefault()

if __name__ == "__main__":
    main()
