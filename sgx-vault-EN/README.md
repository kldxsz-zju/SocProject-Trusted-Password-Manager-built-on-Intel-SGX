# SGX 密码库公共平台

运行环境：Ubuntu 24.04、Intel SGX SDK 2.29。默认 SDK 路径为 `/opt/intel/sgxsdk`。

## 仿真模式

```bash
source /opt/intel/sgxsdk/environment
cd sgx-vault-common
make clean
make SGX_MODE=SIM SGX_DEBUG=1
./app
```

## 硬件模式

```bash
source /opt/intel/sgxsdk/environment
cd sgx-vault-common
make clean
make SGX_MODE=HW SGX_DEBUG=1
./app
```

## 测试步骤

第一次运行：

1. 输入 `1` 创建密码库。
2. 输入 `3` 添加密码条目。
3. 输入 `4` 查询密码条目。
4. 输入 `5` 修改密码条目。
5. 输入 `6` 删除密码条目。
6. 输入 `7` 列出服务名称。
7. 输入 `8` 查看版本。
8. 输入 `9` 保存为 `vault.sealed`。
9. 输入 `0` 退出。

重新运行 `./app`：

1. 输入 `2` 加载 `vault.sealed`。
2. 输入 `4` 查询之前保存的密码条目。

## 切换密封策略

默认使用 `MRENCLAVE`：

```bash
make clean
make SGX_MODE=HW SGX_DEBUG=1 SEAL_POLICY=MRENCLAVE
```

使用 `MRSIGNER`：

```bash
make clean
make SGX_MODE=HW SGX_DEBUG=1 SEAL_POLICY=MRSIGNER
```

## 自动生成接口文件

执行 `make` 后会根据 `Enclave/Enclave.edl` 自动生成：

```text
App/Enclave_u.c
App/Enclave_u.h
Enclave/Enclave_t.c
Enclave/Enclave_t.h
```

## 清理

```bash
make clean
```
