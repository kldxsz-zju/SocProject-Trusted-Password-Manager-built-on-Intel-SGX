#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
实验一：密封数据的机密性与完整性
自动测试脚本
"""

import os
import sys
import shutil
import random
import subprocess
import select
import time
import re

# 配置
APP_PATH = "./app"                # SGX 应用程序
SEALED_FILE = "vault.sealed"      # 密封数据文件
ORIG_FILE = "vault.sealed.orig"   # 原始密封文件备份
TIMEOUT = 0.3                       # 读取输出超时（秒）

# 测试凭据
SERVICE = "testservice"
USERNAME = "testuser"
PASSWORD = "testpass123"
VAULTPASSWORD = "test1234"


def run_commands(commands, timeout=TIMEOUT):
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
    # print(output);
    # print("\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n")
    proc.stdin.write('0\n')
    proc.stdin.flush()
    proc.wait(timeout=timeout)
    return output


def check_plaintext(file_path, strings_list):
    """检查文件中是否包含任意给定字符串（明文）"""
    with open(file_path, 'rb') as f:
        data = f.read()
    for s in strings_list:
        if s.encode() in data:
            return True
    return False


def test_load(file_path):
    """
    复制 file_path 到 SEALED_FILE，然后执行加载操作（命令 '2'），
    返回加载操作的输出字符串。
    """
    # 执行加载
    output = run_commands(['2\n', VAULTPASSWORD + '\n'])
    return output


def modify_byte(file_path, offset, new_byte):
    """修改指定偏移量处的一个字节"""
    with open(file_path, 'r+b') as f:
        f.seek(offset)
        f.write(bytes([new_byte]))


def random_overwrite(file_path, num_bytes):
    """随机覆盖 num_bytes 个字节"""
    size = os.path.getsize(file_path)
    with open(file_path, 'r+b') as f:
        for _ in range(num_bytes):
            offset = random.randint(0, size - 1)
            f.seek(offset)
            f.write(bytes([random.randint(0, 255)]))


def truncate_file(file_path, new_size):
    """截断文件到 new_size 字节"""
    with open(file_path, 'r+b') as f:
        f.truncate(new_size)


def modify_header(file_path, num_bytes):
    """随机修改文件头 num_bytes 个字节"""
    with open(file_path, 'r+b') as f:
        for i in range(num_bytes):
            f.seek(i)
            f.write(bytes([random.randint(0, 255)]))


def modify_tail(file_path, num_bytes):
    """随机修改文件尾 num_bytes 个字节"""
    size = os.path.getsize(file_path)
    with open(file_path, 'r+b') as f:
        for i in range(size - num_bytes, size):
            f.seek(i)
            f.write(bytes([random.randint(0, 255)]))


def append_data(file_path, extra_data):
    """在文件末尾追加额外数据"""
    with open(file_path, 'ab') as f:
        f.write(extra_data)


def extract_error(output):
    """从输出中提取错误类型"""
    # 查找 "Error:" 行
    error_line = re.search(r'Error:.*', output)
    if error_line:
        return error_line.group().strip()
    # 如果输出中有 "OK." 则成功
    if "OK." in output:
        return "OK"
    # 未识别
    return "Unknown"


def run_tests():
    """主测试流程"""
    print("=== Experiment 1: Sealed Data Confidentiality and Integrity Test ===\n")

    # ---- 1. 初始化数据 ----
    print("Initializing the password vault and saving the sealed file...")
    # 创建vault，添加凭据，保存
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
    output = run_commands(init_commands)
    if "Error" in output or not os.path.exists(SEALED_FILE):
        print("Initialization failed. Please check the application.")
        print(output)
        sys.exit(1)
    print("✓ Password vault created and saved successfully.\n")

    # 备份原始密封文件
    shutil.copy(SEALED_FILE, ORIG_FILE)

    # ---- 2. 检查明文 ----
    print("Checking the sealed file for plaintext credentials...")
    plaintext_found = check_plaintext(SEALED_FILE, [SERVICE, USERNAME, PASSWORD])
    if plaintext_found:
        print("✗ The sealed file contains plaintext credentials. Confidentiality verification failed.")
    else:
        print("✓ No plaintext credentials found. Confidentiality verification passed.")
    print()

    # ---- 3. 测试用例定义 ----
    tests = []

    # 3.1 修改单个字节（偏移量100处，翻转一个比特）
    tests.append({
        "name": "Modify a single byte",
        "func": lambda f: modify_byte(f, 100, 0xFF)  # 将偏移100字节设为0xFF
    })

    # 3.2 随机覆盖10个字节
    tests.append({
        "name": "Randomly overwrite 10 bytes",
        "func": lambda f: random_overwrite(f, 10)
    })

    # 3.3 截断文件（保留一半）
    size = os.path.getsize(ORIG_FILE)
    tests.append({
        "name": "Truncate the file to half its size",
        "func": lambda f: truncate_file(f, size // 2)
    })

    # 3.4 修改文件头（前8字节）
    tests.append({
        "name": "Modify the file header (8 bytes)",
        "func": lambda f: modify_header(f, 8)
    })

    # 3.5 修改文件尾（最后8字节）
    tests.append({
        "name": "Modify the file tail (8 bytes)",
        "func": lambda f: modify_tail(f, 8)
    })

    # 3.6 追加随机数据（100字节）
    tests.append({
        "name": "Append 100 bytes of random data",
        "func": lambda f: append_data(f, bytes([random.randint(0, 255) for _ in range(100)]))
    })

    # ---- 4. 执行测试 ----
    print("Starting integrity tampering tests...\n")
    results = []
    for test in tests:
        # 恢复原始密封文件
        shutil.copy(ORIG_FILE, SEALED_FILE)
        # 应用篡改
        test["func"](SEALED_FILE)
        # 执行加载操作
        output = test_load(SEALED_FILE)
        error = extract_error(output)
        # 记录
        results.append({
            "name": test["name"],
            "error": error,
            "output": output
        })
        print(f"[{test['name']}] Error type: {error}")

    # ---- 5. 输出报告 ----
    print("\n=== Test Report ===")
    for r in results:
        print(f"{r['name']}: {r['error']}")
        # 可选：打印详细输出
        # print(r['output'])

    # # 清理
    # if os.path.exists(ORIG_FILE):
    #     os.remove(ORIG_FILE)
    # if os.path.exists(SEALED_FILE):
    #     os.remove(SEALED_FILE)

    print("\nTesting complete.")


if __name__ == "__main__":
    # 检查应用程序是否存在
    if not os.path.exists(APP_PATH):
        print(f"Error: application '{APP_PATH}' not found. Please build it first.")
        sys.exit(1)
    run_tests()
