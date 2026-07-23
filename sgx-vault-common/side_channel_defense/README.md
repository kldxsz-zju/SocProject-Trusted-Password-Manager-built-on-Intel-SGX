# SGX 密码库缺页侧信道防护核心

本目录与 `experiments/` 同级，保存针对当前 SGX 密码库的防护版本核心代码。
它不会覆盖原来的 `Enclave/Enclave.cpp`，便于保留“无防护基线”和攻击结果。

## 防护范围

当前实现保护密码条目的 `add/get/update/delete` 数据访问：

- 每次固定扫描全部 128 个槽位；
- 服务名始终比较完整的 65 字节，不调用 `strcmp`；
- 找到目标后不会直接通过秘密索引访问记录；
- `get` 再次遍历全部记录并用掩码提取结果；
- `update/delete/add` 对全部槽位执行相同大小的条件写回；
- 固定长度用户名和密码缓冲区避免按秘密字符串长度复制。

这主要抵抗由恶意 OS 观察数据页缺页轨迹而推断目标记录位置的攻击。

## 文件

- `ProtectedVaultCore.h`：与原密码库兼容的数据布局和接口。
- `ProtectedVaultCore.cpp`：数据无关 CRUD 实现。
- `test_oblivious_core.cpp`：功能测试和逻辑访问次数一致性测试。
- `Makefile`：不依赖 SGX SDK 的核心测试构建。

## 测试

在 Ubuntu 上：

```bash
cd sgx-vault-common/side_channel_defense
make test
```

测试会比较读取第一条、第二条和不存在条目时的逻辑访问计数。三者必须一致。
这个计数测试只能发现实现中的明显错误，最终仍需使用现有缺页攻击工具比较真实页面轨迹。

## 接入 Enclave 的方式

`ProtectedVaultWire` 的字段顺序、大小和原 `VaultWire` 一致。接入时：

1. 在 `Enclave/Enclave.cpp` 中包含 `ProtectedVaultCore.h`；
2. 将原来的 `VaultWire` 换成 `ProtectedVaultWire`；
3. ECALL 收到字符串后，先编码到完整清零的固定大小输入结构；
4. 用本目录的四个 `protected_vault_*` 函数替换原 CRUD 主体；
5. 将 `ProtectedAccessStats` 传 `nullptr`，生产路径不要输出调试计数；
6. 使用 `SGX_MODE=HW` 重新运行缺页轨迹实验。

## 威胁模型边界

当前代码没有隐藏：

- 调用的是哪一种 ECALL；
- ECALL 的调用时刻和次数；
- 返回状态码；
- `list` 主动输出的服务列表；
- `seal/unseal` 的格式校验控制流；
- EDL `[string]` 参数封送时可能暴露的输入长度。

如果实验目标要求连字符串长度也隐藏，应把 EDL 参数改成固定大小数组，例如
`[in, size=VAULT_SERVICE_MAX + 1]`，App 每次传完整清零的缓冲区。

## 编译器检查

无分支 C++ 写法仍可能被编译器改变。用于论文或最终报告时，应对 Enclave 优化后的
反汇编进行检查，确认比较和掩码选择没有被重新编译成依赖秘密值的提前跳转。同时用
真实受控缺页攻击验证轨迹，而不能只根据源代码判断安全。
