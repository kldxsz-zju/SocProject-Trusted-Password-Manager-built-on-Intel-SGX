# 实验三：回滚攻击与防护

本目录只放实验三代码和脚本，直接调用仓库根目录的
`../sgx-vault-common`，不复制或重新实现密码库。

## 文件

```text
Makefile                 C++ 实验工具构建
witness_server.cpp       第二台电脑上的可信版本记录服务
witness_client.cpp       第一台电脑上的版本检查客户端
run_baseline_sim.sh      用真实密封文件复现无防护回滚
run_witness_sim.sh       单机验证可信版本记录拒绝旧版本
run_hw_server.sh         双机实验：机器 B 启动服务
run_hw_client.sh         双机实验：机器 A 发起检查
```

## Ubuntu 单机 SIM

以下命令均在 Ubuntu 24.04 终端中执行。假设仓库位于当前用户主目录；如果
实际路径不同，只需替换第一条 `cd` 命令。

```bash
sudo apt update
sudo apt install -y build-essential
source /opt/intel/sgxsdk/environment
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX
chmod +x exp3/*.sh
```

确认 SGX SDK 已正确加载：

```bash
echo "$SGX_SDK"
which sgx_edger8r
which sgx_sign
```

复现 SGX Sealing 无法防回滚：

```bash
./exp3/run_baseline_sim.sh
```

预期输出：

```text
[PASS] 无防护回滚成功：旧文件可解封，旧密码重新出现。
```

验证可信版本记录拒绝旧版本：

```bash
./exp3/run_witness_sim.sh
```

预期包含：

```text
OK 3
ROLLBACK 3
[PASS] 有防护路径拒绝 V2→V1 回滚。
```

## 两台电脑的 HW 实验

### 1. 机器 A：先确认硬件模式的 `./app` 可以运行

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX
source /opt/intel/sgxsdk/environment
ls -l /dev/sgx_enclave /dev/sgx_provision

cd sgx-vault-common
make clean
make SGX_MODE=HW SGX_DEBUG=1 SEAL_POLICY=MRENCLAVE
./app
```

第一次进入 `./app` 后，按以下顺序输入（每行输入后按 Enter）：

```text
1
3
github
alice
hw_password_v1
8
9
0
```

含义是：创建密码库、添加 V1 密码、显示版本、保存 `vault.sealed`、退出。
保存 V1 快照：

```bash
cp vault.sealed ../exp3/manual_hw_v1.sealed
```

再次运行：

```bash
./app
```

依次输入：

```text
2
5
github
alice
hw_password_v2
8
9
0
```

含义是：加载 V1、更新密码、显示递增后的版本、保存 V2、退出。保存快照：

```bash
cp vault.sealed ../exp3/manual_hw_v2.sealed
```

模拟攻击者回放 V1：

```bash
cp ../exp3/manual_hw_v1.sealed vault.sealed
./app
```

依次输入：

```text
2
8
4
github
0
```

如果程序重新显示 `hw_password_v1`，就证明 HW 模式下单独使用 SGX Sealing
仍不能防止回滚。

以上全过程也可以自动执行：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX
chmod +x exp3/*.sh
./exp3/run_hw_attack.sh
```

### 2. 机器 B：启动独立版本见证服务

机器 B（独立可信见证机）：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/exp3
./run_hw_server.sh 8765 witness_versions.db
```

保持该终端运行。若机器 B 启用了防火墙：

```bash
sudo ufw allow 8765/tcp
```

### 3. 机器 A：执行有版本见证的 HW 对照实验

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX
source /opt/intel/sgxsdk/environment
chmod +x exp3/*.sh
./exp3/run_hw_protected_client.sh <机器B的IP> 8765
```

该脚本会从头执行以下过程：

1. 以 `SGX_MODE=HW` 编译现有密码库；
2. 运行 `./app` 创建 V1 并读取 `state_version`；
3. 再运行 `./app` 更新为 V2；
4. 向机器 B 提交 V2 的可信版本；
5. 用 V1 密封文件替换当前文件；
6. 运行 `./app` 解封 V1，但不读取密码；
7. 把解封得到的旧版本发给机器 B 检查；
8. 收到 `ROLLBACK` 后停止，不执行 Get/List/Update。

预期输出包含：

```text
ROLLBACK 3
[PASS] HW 有防护路径拒绝回滚
[PASS] fail-closed：没有执行密码读取
```

## 从零开始的推荐运行顺序

在一台电脑上先完成 SIM 验证：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX
source /opt/intel/sgxsdk/environment
chmod +x exp3/*.sh

# 实验 3A：真实密封文件回滚攻击
./exp3/run_baseline_sim.sh

# 实验 3B：单机启动 C++ 见证服务并验证旧版本被拒绝
./exp3/run_witness_sim.sh
```

实验输出和中间证据保存在 `exp3`：

```text
vault_v1.sealed       更新前的旧密封状态
vault_v2.sealed       更新后的新密封状态
v1.log                创建 V1 的程序输出
v2.log                创建 V2 的程序输出
rollback.log          用 V1 替换当前文件后的程序输出
witness.log           可信版本见证服务日志
witness_versions.db   见证机保存的最大版本记录
```

重新运行前可清理实验产物：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX
make -C exp3 clean
rm -f sgx-vault-common/vault.sealed
```

若只想手工编译 C++ 见证程序：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/exp3
make clean
make
./witness_server 8765 witness_versions.db
```

服务启动后，在另一个终端测试：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/exp3
./witness_client 127.0.0.1 8765 COMMIT 00112233445566778899aabbccddeeff 3
./witness_client 127.0.0.1 8765 CHECK  00112233445566778899aabbccddeeff 2
```

## 实验结论与安全边界

`run_baseline_sim.sh` 使用的是真实 SGX SIM 密封文件；
`run_witness_sim.sh` 验证的是 C++ 版本见证服务的持久化和拒绝逻辑。

在“客户端操作系统也不可信”的完整威胁模型下，不能把外部客户端检查冒充成
Enclave 内防护。最终双机安全版本需要进一步满足：

1. Enclave 生成随机 `vault_id` 和一次性 nonce；
2. 见证机返回 `vault_id + state_version + nonce` 的 ECDSA-P256 签名；
3. Enclave 内用固定公钥验证签名，验证前禁止 CRUD；
4. 密封版本小于见证版本时返回回滚错误；
5. 保存采用“见证提交后原子替换密封文件”的 fail-closed 顺序。

当前公共密码库尚无这些 ECALL，所以现阶段代码完整覆盖“回滚复现”和“独立版本
检测实验”，但不虚假宣称已经抵抗控制宿主机的攻击者。加入上述 Enclave 接口后，
才能进行最终的双机有防护 HW 安全实验。
