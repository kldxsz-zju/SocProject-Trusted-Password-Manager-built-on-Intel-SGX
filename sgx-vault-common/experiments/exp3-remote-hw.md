# exp3-remote-hw

本文说明如何在两台 Ubuntu 电脑之间运行实验三：先在机器 A 上复现**没有回滚防护时的攻击**，再由机器 B 运行远程版本见证服务，验证机器 A 能否识别并拒绝旧的 SGX 密封文件。

## 1. 实验结构

两台电脑上的代码目录均与本项目相同：

```text
~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/
└── sgx-vault-common/
    ├── App/
    ├── Enclave/
    ├── Include/
    ├── Makefile
    └── experiments/
        ├── run_hw_attack.sh
        ├── run_hw_client.sh
        ├── run_hw_protected_client.sh
        ├── run_hw_server.sh
        ├── witness_client.cpp
        └── witness_server.cpp
```

两台电脑的角色如下：

- **机器 A（SGX 机器）**：运行密码库、制造旧密封文件回放，并向机器 B 查询可信版本。
- **机器 B（见证机器）**：保存密码库的最新可信版本，收到查询后判断机器 A 加载的版本是否已经回滚。

机器 A 必须支持 Intel SGX 硬件模式。机器 B 只运行普通 C++ TCP 服务，不要求支持 SGX。

## 2. 准备两台电脑

### 2.1 确认代码路径

在机器 A 和机器 B 上分别执行：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/sgx-vault-common
pwd
ls experiments
```

`experiments` 中应至少能看到上面列出的六个文件。

给四个脚本增加执行权限：

```bash
chmod +x experiments/run_hw_attack.sh \
         experiments/run_hw_client.sh \
         experiments/run_hw_protected_client.sh \
         experiments/run_hw_server.sh
```

### 2.2 安装编译工具

两台电脑都需要 `g++` 和 `make`：

```bash
sudo apt update
sudo apt install -y build-essential
```

机器 A 还必须安装 Intel SGX SDK 和运行库。加载 SDK 环境并检查 SGX 设备：

```bash
source /opt/intel/sgxsdk/environment
echo "$SGX_SDK"
ls -l /dev/sgx_enclave
```

如果 `/dev/sgx_enclave` 不存在，应先检查 CPU、BIOS/UEFI 中的 SGX 设置、Linux SGX 驱动和当前用户的设备权限。这里必须使用真实硬件模式，不能用 `SGX_MODE=SIM` 代替。

### 2.3 确认机器 B 的地址和端口

在机器 B 上查看局域网 IP：

```bash
hostname -I
```

以下示例假设机器 B 的 IP 是 `192.168.1.20`，见证服务端口使用默认值 `8765`。实际运行时请替换成机器 B 的真实 IP。

如果机器 B 启用了 UFW，需要允许机器 A 访问该端口：

```bash
sudo ufw allow 8765/tcp
```

只在可信局域网内运行本实验。见证协议是实验用明文 TCP 协议，不应直接暴露到公网。

## 3. 实验一：复现无防护回滚攻击

这一部分只在机器 A 上运行，不需要启动机器 B。

在机器 A 上执行：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/sgx-vault-common
source /opt/intel/sgxsdk/environment
./experiments/run_hw_attack.sh
```

脚本会自动完成以下过程：

1. 使用 `SGX_MODE=HW` 和 `SEAL_POLICY=MRENCLAVE` 重新编译密码库。
2. 创建第一版密码库，保存密码 `hw_password_v1`，并备份第一版密封文件。
3. 将密码修改成 `hw_password_v2`，再备份第二版密封文件。
4. 用第一版密封文件覆盖当前的 `vault.sealed`，模拟攻击者回放合法的旧文件。
5. 重新加载密码库并检查旧密码是否重新出现。

成功复现攻击时，最后应出现类似结果：

```text
[PASS] HW 无防护回滚成功：SGX 接受了旧但合法的密封文件。
```

实验文件和日志保存在：

```text
sgx-vault-common/experiments/hw_vault_v1.sealed
sgx-vault-common/experiments/hw_vault_v2.sealed
sgx-vault-common/experiments/hw_v1.log
sgx-vault-common/experiments/hw_v2.log
sgx-vault-common/experiments/hw_rollback.log
```

该结果说明 SGX Sealing 可以发现文件被篡改，但单独使用 Sealing 无法判断一个密码正确、签名有效的密封文件是不是旧版本。

## 4. 实验二：两台电脑进行远程回滚防护

先启动机器 B 的见证服务，再运行机器 A 的受保护客户端。实验期间应保持机器 B 的终端和服务一直运行。

### 4.1 在机器 B 上启动见证服务器

打开机器 B 的终端，执行：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/sgx-vault-common
./experiments/run_hw_server.sh 8765 experiments/witness_versions.db
```

第一次运行时，`make` 会根据 `witness_server.cpp` 编译 `witness_server`。服务器成功启动后应显示：

```text
Witness listening on 0.0.0.0:8765, db=experiments/witness_versions.db
```

这个终端会一直被服务器占用，不要关闭。`experiments/witness_versions.db` 用于保存各密码库 ID 对应的最新可信版本。

如需确认端口确实正在监听，可在机器 B 的另一个终端执行：

```bash
ss -ltn | grep 8765
```

### 4.2 可选：从机器 A 测试网络连通性

机器 B 服务启动后，在机器 A 上执行：

```bash
nc -vz 192.168.1.20 8765
```

如果系统没有 `nc`：

```bash
sudo apt install -y netcat-openbsd
```

连接失败时，检查机器 B 的 IP、两台电脑是否在可互通的网络、UFW/其他防火墙，以及见证服务器是否仍在运行。

### 4.3 在机器 A 上运行受保护实验

在机器 A 的另一个终端执行：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/sgx-vault-common
source /opt/intel/sgxsdk/environment
./experiments/run_hw_protected_client.sh 192.168.1.20 8765
```

将 `192.168.1.20` 替换为机器 B 的真实 IP。第三个参数可以指定 32 位十六进制实验密码库 ID；省略时使用脚本内置的默认 ID。例如：

```bash
./experiments/run_hw_protected_client.sh \
  192.168.1.20 8765 11112222333344445555666677778888
```

同一轮实验应始终使用同一个 ID。并行运行多个独立实验时，应为每个实验使用不同的 32 位十六进制 ID。

受保护脚本会自动完成以下过程：

1. 编译见证客户端以及 SGX 硬件版密码库。
2. 创建第一版密码库并保存 `protected_password_v1`。
3. 更新为第二版并保存 `protected_password_v2`。
4. 将第二版的状态版本提交给机器 B，机器 B 将其记录为最新可信版本。
5. 在机器 A 上回放第一版密封文件。
6. 机器 A 先从旧文件读取状态版本，再向机器 B 查询该版本是否可信。
7. 机器 B 发现本地版本小于已提交版本，返回 `ROLLBACK`；机器 A 在读取密码内容前终止操作。

防护成功时，机器 A 最后应看到类似输出：

```text
ROLLBACK 3
[PASS] HW 有防护路径拒绝回滚：本地版本=2，可信版本=3。
[PASS] fail-closed：没有执行密码读取。
```

具体数字取决于密码库的版本增长过程，但关键是出现 `ROLLBACK` 和两条 `[PASS]`。

相关文件和日志保存在机器 A 的：

```text
sgx-vault-common/experiments/protected_v1.sealed
sgx-vault-common/experiments/protected_v2.sealed
sgx-vault-common/experiments/protected_v1.log
sgx-vault-common/experiments/protected_v2.log
sgx-vault-common/experiments/protected_rollback_check.log
```

机器 B 的可信版本记录保存在：

```text
sgx-vault-common/experiments/witness_versions.db
```

## 5. 重新进行一轮干净实验

见证数据库会跨进程重启保留。若要使用相同的密码库 ID 从头重做实验，应先停止机器 B 的服务器（在服务器终端按 `Ctrl+C`），然后在机器 B 上删除旧实验数据库，再重新启动服务：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/sgx-vault-common
rm -f experiments/witness_versions.db experiments/witness_versions.db.tmp
./experiments/run_hw_server.sh 8765 experiments/witness_versions.db
```

也可以保留数据库并在机器 A 上为新一轮实验传入一个新的 32 位十六进制密码库 ID。

## 6. 手工测试见证服务（可选）

机器 B 服务启动后，可在机器 A 上直接调用见证客户端。以下命令使用一个测试 ID：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/sgx-vault-common

./experiments/run_hw_client.sh \
  192.168.1.20 8765 COMMIT aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 5

./experiments/run_hw_client.sh \
  192.168.1.20 8765 CHECK aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 4
```

第一次提交应返回 `OK 5`；随后用版本 4 查询应返回 `ROLLBACK 5`。`run_hw_client.sh` 在收到 `ROLLBACK` 时会以退出码 `10` 结束，这是预期行为，不表示网络或程序崩溃。

## 7. 常见问题

### 机器 A 报 `/dev/sgx_enclave` 不存在

当前电脑没有可用的 SGX 硬件设备。检查 CPU 是否支持 SGX、BIOS/UEFI 是否启用 SGX、Linux SGX 驱动以及设备权限。

### 编译时找不到 SGX SDK

先执行：

```bash
source /opt/intel/sgxsdk/environment
```

并确认 `SGX_SDK` 指向 `/opt/intel/sgxsdk`。

### 机器 A 无法连接机器 B

确认以下事项：

- 使用的是机器 B 的局域网 IP，而不是 `127.0.0.1`。
- 机器 B 的 `run_hw_server.sh` 仍在运行。
- 机器 B 的 TCP 端口 `8765` 已放行。
- 两台电脑之间没有路由、访客 Wi-Fi隔离或单位网络访问控制。

### 返回 `UNREGISTERED 0`

表示机器 B 的数据库中还没有这个密码库 ID。必须先对同一 ID 执行 `COMMIT`；正常情况下 `run_hw_protected_client.sh` 会自动完成提交。

### 第二次实验立即得到与预期不同的版本结果

通常是因为机器 B 保留了上一轮的 `witness_versions.db`。使用新的实验 ID，或者按“重新进行一轮干净实验”一节停止服务器并清理数据库。

## 8. 实验结论

- 无防护实验中，旧密封文件仍然具有合法的 SGX 完整性保护，因此可以被成功加载，回滚攻击成立。
- 有防护实验中，机器 B 保存独立于密封文件的最新版本。攻击者即使回放合法旧文件，也无法同步回滚远程见证记录。
- 机器 A 在读取密码前查询机器 B，并在发现旧版本时 fail-closed，因此阻止了旧密码内容被使用。

当前实现用于演示远程版本见证的基本原理。见证协议本身没有 TLS、客户端认证或服务器签名，因此生产系统还需要增加双向认证、传输加密、见证服务持久化保护和高可用设计。
