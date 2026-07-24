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
import re
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

def send_commands(proc, commands, output, timeout=TIMEOUT):
    """
    启动应用程序，依次发送命令（列表），并捕获所有输出。
    每个命令应包含换行符。
    返回程序的标准输出字符串。
    """
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
    # print(output);
    # print("\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n")
    return output

def test_bruteforce():
    """暴力破解测试：启动app → load vault → 输错三次锁定 → 使用L登录暴力枚举"""
    print("[*] Brute-force attack test (manual workflow simulation)")
    
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
    output = ""
    attempts = 0
    for guess in common_pins:
        attempts += 1
        brute_commands.append(f'{int(guess)}\n')
        brute_commands.append('a\n')
        brute_commands.append('a\n')
        # print(brute_commands)
        output = send_commands(proc,brute_commands,output)
        brute_commands.pop()
        brute_commands.pop()
        brute_commands.pop()
        if "Login successful." in output:
            found  = True
            break
    send_commands(proc,'0\n',output)
    if not found:
        print("\n[-] Brute-force attack failed after {} attempts".format(attempts))
    else:
        print("\n[+] Brute-force attack succeeded; the password is {}".format(guess))


def main():
    print("=== SGX Password Vault Attack Test ===")
    if not os.path.exists(APP_PATH):
        print("Error: app not found")
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
    output = ""
    output = send_commands(proc,init_commands,output)
    proc.wait(timeout=TIMEOUT)
    if "Error" in output or not os.path.exists(SEALED_FILE):
        print("Initialization failed. Please check the application.")
        print(output)
        sys.exit(1)
    print("✓ Password vault created and saved successfully.\n")
    output = ""
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
    output = send_commands(proc,commands,output)

    #创建密码库
    test_bruteforce()

if __name__ == "__main__":
    main()
