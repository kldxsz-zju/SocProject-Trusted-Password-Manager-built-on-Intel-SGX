# 实验三：SGX 硬件模式回滚实验

本目录只保留真实 Intel SGX 硬件模式代码。

## 文件

```text
run_hw_attack.sh            复现无防护回滚攻击
run_hw_server.sh            在机器 B 启动版本见证服务
run_hw_client.sh            手工调用见证客户端
run_hw_protected_client.sh  在机器 A 运行版本检测实验
witness_server.cpp          版本见证服务器
witness_client.cpp          版本见证客户端
Makefile                    编译见证程序
```

## 1. 无防护回滚攻击

在支持 SGX 的机器上运行：

```bash
source /opt/intel/sgxsdk/environment
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX
chmod +x exp3/*.sh
./exp3/run_hw_attack.sh
```

脚本会创建旧、新两份密封文件，然后用旧文件覆盖当前状态。如果旧密码重新出现，
说明 SGX Sealing 能防篡改，但不能单独防止合法旧文件回滚。

## 2. 双机版本检测

机器 B 启动见证服务：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX/exp3
./run_hw_server.sh 8765 witness_versions.db
```

机器 A 运行硬件实验：

```bash
cd ~/SocProject-Trusted-Password-Manager-built-on-Intel-SGX
source /opt/intel/sgxsdk/environment
./exp3/run_hw_protected_client.sh <机器B的IP> 8765
```

回放旧密封文件后，预期输出：

```text
ROLLBACK 3
[PASS] HW 有防护路径拒绝回滚
[PASS] fail-closed：没有执行密码读取
```

## 安全边界

当前实现是在外部客户端中检查版本，适合验证实验原理。若宿主系统也不可信，
还需要在 Enclave 内验证见证机签名，并在验证通过前禁止密码读写操作。

## 清理

```bash
make -C exp3 clean
rm -f sgx-vault-common/vault.sealed
```
