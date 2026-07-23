# Exp3：两台电脑上的 SGX 回滚攻击与远程见证防护实验

本文说明如何使用 `sgx-vault-common-new` 在两台 Ubuntu 电脑上完成 Exp3：

1. 在机器 A 上回放旧的 SGX 密封文件，复现无防护回滚攻击。
2. 在机器 B 上运行远程版本见证服务。
3. 再次回放旧密封文件，验证机器 A 能在读取密码前发现并拒绝回滚。

> 本实验使用真实 SGX 硬件模式（`SGX_MODE=HW`）。见证协议是实验用明文 TCP 协议，只应在可信局域网中使用，不要暴露到公网。

## 1. 两台机器的角色

| 机器 | 作用 | 是否需要 SGX |
| --- | --- | --- |
| 机器 A（SGX 客户端） | 运行密码库、备份和回放密封文件、查询见证服务 | 是 |
| 机器 B（见证服务器） | 保存每个密码库 ID 的最新可信版本 | 否 |

两台机器都准备同一份项目代码。本文假设项目位于：

```text
~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/
└── sgx-vault-common-new/
    ├── App/
    ├── Enclave/
    ├── Include/
    ├── Makefile
    └── bin/
        ├── run_hw_attack.sh
        ├── run_hw_protected_client.sh
        ├── run_hw_server.sh
        ├── witness_client.cpp
        └── witness_server.cpp
```

以下命令都在 Linux 终端中执行。不要在旧的 `sgx-vault-common` 目录中运行实验脚本。

## 2. 实验前准备

### 2.1 两台机器：检查代码并安装编译工具

在机器 A 和机器 B 上分别执行：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/sgx-vault-common-new
ls bin/run_hw_*.sh
chmod +x bin/run_hw_attack.sh bin/run_hw_protected_client.sh bin/run_hw_server.sh

sudo apt update
sudo apt install -y build-essential
```

### 2.2 机器 A：检查 SGX 硬件环境

机器 A 需要 Intel SGX SDK、运行库和可用的 SGX 设备：

```bash
source /opt/intel/sgxsdk/environment
echo "$SGX_SDK"
ls -l /dev/sgx_enclave
```

预期 `SGX_SDK` 指向 `/opt/intel/sgxsdk`，并且 `/dev/sgx_enclave` 存在。如果设备不存在，应检查：

- CPU 是否支持 Intel SGX；
- BIOS/UEFI 是否启用 SGX；
- Linux SGX 驱动和运行库是否安装；
- 当前用户是否有访问 SGX 设备的权限。

本实验不能用 `SGX_MODE=SIM` 代替硬件模式。

### 2.3 机器 B：确定 IP 和开放端口

在机器 B 上查看局域网 IP：

```bash
hostname -I
```

本文以 `192.168.1.20` 为例，实际操作时必须替换为机器 B 的真实 IP。默认见证端口是 TCP `8765`。

如果机器 B 启用了 UFW，只允许机器 A 的 IP 访问该端口。例如机器 A 的 IP 为 `192.168.1.10`：

```bash
sudo ufw allow from 192.168.1.10 to any port 8765 proto tcp
```

## 3. 实验一：复现无防护回滚攻击

这一部分只在机器 A 上运行，机器 B 暂时不需要启动。

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/sgx-vault-common-new
source /opt/intel/sgxsdk/environment
./bin/run_hw_attack.sh
```

脚本会自动：

1. 以 `SGX_MODE=HW`、`SEAL_POLICY=MRENCLAVE` 编译程序；
2. 创建第一版密码库，保存 `hw_password_v1`；
3. 将密码更新为 `hw_password_v2`；
4. 用第一版密封文件覆盖当前 `vault.sealed`，模拟攻击者回放合法旧文件；
5. 加载回放后的文件并检查旧密码是否重新出现。

成功复现时，最后应出现一条 `[PASS]`，语义如下：

```text
[PASS] HW 无防护回滚成功：SGX 接受了旧但合法的密封文件。
```

实验产物位于机器 A 的 `sgx-vault-common-new/bin/`：

```text
hw_vault_v1.sealed
hw_vault_v2.sealed
hw_v1.log
hw_v2.log
hw_rollback.log
```

可进一步核对回滚日志：

```bash
grep -n "hw_password_v1" bin/hw_rollback.log
```

能读到 `hw_password_v1` 表明攻击成功。原因是 SGX Sealing 能检测密封数据是否被篡改，但不能单独判断一个完整、合法的密封文件是否为旧版本。

## 4. 实验二：使用远程见证防止回滚

先在机器 B 启动见证服务器并保持运行，再在机器 A 运行受保护客户端。

### 4.1 机器 B：启动见证服务器

在机器 B 的终端执行：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/sgx-vault-common-new
./bin/run_hw_server.sh 8765 bin/witness_versions.db
```

首次运行时，`make` 会按隐式 C++ 编译规则从 `witness_server.cpp` 构建 `witness_server`。启动成功后应显示：

```text
Witness listening on 0.0.0.0:8765, db=bin/witness_versions.db
```

保持该终端运行。可在机器 B 的另一个终端确认端口：

```bash
ss -ltn | grep 8765
```

`bin/witness_versions.db` 保存“32 位十六进制密码库 ID → 最新可信版本”的映射，服务器重启后记录仍然存在。

### 4.2 机器 A：测试网络连通性

将示例 IP 换成机器 B 的真实 IP：

```bash
nc -vz 192.168.1.20 8765
```

如果没有 `nc`：

```bash
sudo apt install -y netcat-openbsd
```

### 4.3 机器 A：运行受保护实验

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/sgx-vault-common-new
source /opt/intel/sgxsdk/environment
./bin/run_hw_protected_client.sh 192.168.1.20 8765
```

参数格式为：

```text
run_hw_protected_client.sh WITNESS_HOST [PORT] [EXPERIMENT_VAULT_ID]
```

第三个参数可选，必须是 32 位十六进制字符串。省略时使用脚本内置 ID `00112233445566778899aabbccddeeff`。例如：

```bash
./bin/run_hw_protected_client.sh \
  192.168.1.20 8765 11112222333344445555666677778888
```

脚本会自动：

1. 编译见证客户端和 SGX 硬件版密码库；
2. 创建包含 `protected_password_v1` 的第一版密封文件；
3. 更新为 `protected_password_v2` 并生成第二版密封文件；
4. 向机器 B 提交第二版的状态版本；
5. 在机器 A 上回放第一版密封文件；
6. 只加载旧文件并提取其状态版本，不读取密码内容；
7. 向机器 B 发起 `CHECK`；
8. 收到 `ROLLBACK <可信版本>` 后终止操作，实现 fail-closed。

防护成功时，关键输出应包含：

```text
ROLLBACK <可信版本>
[PASS] ...拒绝回滚...
[PASS] fail-closed...
```

版本数字由实际状态增长过程决定。判断成功的关键是出现 `ROLLBACK` 和两条 `[PASS]`，并且没有在检查后读取旧密码。

机器 A 的证据文件位于：

```text
sgx-vault-common-new/bin/protected_v1.sealed
sgx-vault-common-new/bin/protected_v2.sealed
sgx-vault-common-new/bin/protected_v1.log
sgx-vault-common-new/bin/protected_v2.log
sgx-vault-common-new/bin/protected_rollback_check.log
```

机器 B 的可信版本记录位于：

```text
sgx-vault-common-new/bin/witness_versions.db
```

## 5. 建议记录的实验结果

为便于对照和写实验报告，至少保存以下证据：

| 场景 | 操作 | 预期结果 | 证据 |
| --- | --- | --- | --- |
| 无防护 | 回放 V1 密封文件 | V1 被 SGX 正常加载，旧密码重新出现 | `bin/hw_rollback.log` |
| 有防护 | B 已记录 V2，再回放 V1 | B 返回 `ROLLBACK`，A 在读取密码前终止 | `bin/protected_rollback_check.log` |
| 远程状态 | 查看见证数据库 | 同一密码库 ID 保存最新可信版本 | B 上的 `bin/witness_versions.db` |

建议同时记录：

```bash
# 机器 A
date
hostname
grep -E "model name|sgx" /proc/cpuinfo | head
sha256sum bin/hw_vault_v1.sealed bin/hw_vault_v2.sealed
sha256sum bin/protected_v1.sealed bin/protected_v2.sealed

# 机器 B
date
hostname
cat bin/witness_versions.db
```

## 6. 重新进行一轮干净实验

见证数据库会跨进程重启保留。推荐每轮使用新的 32 位十六进制密码库 ID，这样不必删除旧记录：

```bash
./bin/run_hw_protected_client.sh \
  192.168.1.20 8765 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

如果必须复用同一个 ID：

1. 在机器 B 的服务器终端按 `Ctrl+C` 停止服务；
2. 备份或删除 `bin/witness_versions.db` 和可能存在的 `.tmp` 文件；
3. 重新启动服务器。

例如：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/sgx-vault-common-new
cp -a bin/witness_versions.db "bin/witness_versions.db.$(date +%Y%m%d-%H%M%S).bak"
rm -f bin/witness_versions.db bin/witness_versions.db.tmp
./bin/run_hw_server.sh 8765 bin/witness_versions.db
```

## 7. 可选：手工验证见证协议

机器 B 的服务启动后，在机器 A 编译并调用客户端：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/sgx-vault-common-new/bin
make witness_client

./witness_client \
  192.168.1.20 8765 COMMIT aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 5

./witness_client \
  192.168.1.20 8765 CHECK aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 4
```

第一次应返回：

```text
OK 5
```

第二次应返回：

```text
ROLLBACK 5
```

`witness_client` 收到 `ROLLBACK` 时退出码为 `10`，这是预期行为，并非程序崩溃。可用以下命令检查：

```bash
echo $?
```

## 8. 常见问题

### `/dev/sgx_enclave` 不存在

机器 A 没有可用的 SGX 硬件设备。检查 CPU、BIOS/UEFI、SGX 驱动、运行库和设备权限。

### 编译时找不到 SGX SDK

在机器 A 重新加载环境：

```bash
source /opt/intel/sgxsdk/environment
```

然后确认：

```bash
echo "$SGX_SDK"
```

### 机器 A 无法连接机器 B

检查：

- 使用的是机器 B 的局域网 IP，而不是 `127.0.0.1`；
- 机器 B 的见证服务器终端仍在运行；
- TCP 端口 `8765` 已放行；
- 两台机器可互相路由，且未被访客 Wi-Fi 隔离；
- 启动服务器时使用的端口与客户端参数一致。

### 返回 `UNREGISTERED 0`

机器 B 尚未保存该密码库 ID。必须先用同一个 ID 执行 `COMMIT`。正常情况下，受保护实验脚本会自动提交。

### 返回 `UNCOMMITTED <版本>`

客户端检查的本地版本高于服务器记录，说明新版本尚未提交，或使用了错误的密码库 ID。不要直接信任该状态；先核对实验 ID 和提交步骤。

### 第二轮立即得到异常版本结果

通常是复用了密码库 ID，而机器 B 仍保存上一轮记录。改用新 ID，或按“重新进行一轮干净实验”清理数据库。

### `make witness_server` 或 `make witness_client` 失败

确认机器上已安装 `build-essential`，并且当前目录为 `sgx-vault-common-new/bin`。这里使用 GNU Make 的内置 C++ 编译规则直接编译同名 `.cpp` 文件。

## 9. 实验结论

- 无防护时，旧密封文件仍具有合法的 SGX 完整性保护，因此能够被成功加载；SGX Sealing 本身不提供新鲜性保证。
- 有防护时，机器 B 独立保存最新可信版本。攻击者即使回放合法旧文件，也不能同时回滚远程见证记录。
- 机器 A 在读取密码前查询机器 B，并在发现旧版本时 fail-closed，因此阻止了旧密码内容被继续使用。

当前实现用于演示远程版本见证原理。见证协议本身没有 TLS、客户端认证、服务器签名或防重放会话保护；生产系统还需要双向认证、传输加密、见证存储保护、高可用及可信身份绑定。
