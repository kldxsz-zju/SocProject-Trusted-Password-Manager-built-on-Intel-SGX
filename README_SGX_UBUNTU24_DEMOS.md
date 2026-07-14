# Intel SGX：Ubuntu 24.04 环境与官方 Demo

适用环境：Ubuntu 24.04 LTS、x86_64。以下命令均在 Ubuntu 终端执行。

官方资源：

- SGX SDK/PSW：[intel/confidential-computing.sgx](https://github.com/intel/confidential-computing.sgx)
- SDK 示例：[SampleCode](https://github.com/intel/confidential-computing.sgx/tree/main/SampleCode)
- DCAP：[intel/confidential-computing.tee.dcap](https://github.com/intel/confidential-computing.tee.dcap)
- 官方安装指南：[Intel SGX Software Installation Guide](https://cc-enabling.trustedservices.intel.com/intel-sgx-sw-installation-guide-linux/)

## 1. 检查硬件和内核

```bash
uname -r
lscpu | grep -i sgx || true
grep -m1 -oE 'sgx|sgx_lc' /proc/cpuinfo || true
ls -l /dev/sgx* 2>/dev/null || true
sudo dmesg | grep -i sgx || true
```

Ubuntu 24.04 的内核已包含主线 SGX 驱动，不需要我们安装旧版 out-of-tree 驱动。硬件模式应存在：

```text
/dev/sgx_enclave
/dev/sgx_provision
```

没有设备节点时，检查 CPU 是否支持 SGX，并在 BIOS/UEFI 中启用 `Intel SGX`。硬件不可用时仍可运行 `SGX_MODE=SIM`，但不能证明真实 SGX 可用。

可选的 CPUID 检查：

```bash
sudo apt update
sudo apt install -y cpuid
cpuid -1 -l 0x12
```

## 2. 安装基础依赖

```bash
sudo apt update
sudo apt install -y \
  build-essential python-is-python3 git curl cmake pkg-config \
  libssl-dev libcurl4-openssl-dev libprotobuf-dev
```

## 3. 添加 Intel SGX 软件源

```bash
sudo install -d -m 0755 /etc/apt/keyrings

curl -fsSLo intel-sgx-keyring.asc \
  https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key

sudo mv intel-sgx-keyring.asc /etc/apt/keyrings/intel-sgx-keyring.asc

echo 'deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' \
  | sudo tee /etc/apt/sources.list.d/intel-sgx.list

sudo apt update
```

## 4. 安装 SGX 运行库和开发包

```bash
sudo apt install -y \
  libsgx-enclave-common \
  libsgx-enclave-common-dev \
  libsgx-urts \
  libsgx-quote-ex \
  libsgx-quote-ex-dev \
  libsgx-dcap-ql \
  libsgx-dcap-ql-dev \
  libsgx-dcap-quote-verify \
  libsgx-dcap-quote-verify-dev \
  libsgx-dcap-default-qpl
```

## 5. 安装 Intel SGX SDK

假设我们固定使用 Intel SGX SDK 2.29.100.1：

```bash
mkdir -p ~/sgx-install
cd ~/sgx-install

curl -fsSLo sgx_linux_x64_sdk.bin \
  https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu24.04-server/sgx_linux_x64_sdk_2.29.100.1.bin

chmod +x sgx_linux_x64_sdk.bin
sudo ./sgx_linux_x64_sdk.bin --prefix /opt/intel
```

加载 SDK 环境：

```bash
echo 'source /opt/intel/sgxsdk/environment' >> ~/.bashrc
source /opt/intel/sgxsdk/environment

echo "$SGX_SDK"
which sgx_edger8r
which sgx_sign
which sgx-gdb
```

## 6. 配置设备权限

```bash
sudo usermod -aG sgx "$USER"
sudo usermod -aG sgx_prv "$USER"
```

注销并重新登录，然后检查：

```bash
id
ls -l /dev/sgx*
```

`sgx` 用于访问 Enclave 设备；`sgx_prv` 用于需要 Provision Key 的 DCAP Quote 生成。

## 7. 官方 Demo 1：SampleEnclave

先验证 SDK 和编译环境：

```bash
source /opt/intel/sgxsdk/environment
cd /opt/intel/sgxsdk/SampleCode/SampleEnclave

make clean
make SGX_MODE=SIM SGX_DEBUG=1
./app
```

再验证真实硬件：

```bash
make clean
make SGX_MODE=HW SGX_DEBUG=1
./app
```

SIM 成功、HW 失败时，优先检查 BIOS、`/dev/sgx_enclave` 和用户组权限。

## 8. 官方 Demo 2：SealUnseal

```bash
source /opt/intel/sgxsdk/environment
cd /opt/intel/sgxsdk/SampleCode/SealUnseal

make clean
make SGX_MODE=SIM SGX_DEBUG=1
./app

make clean
make SGX_MODE=HW SGX_DEBUG=1
./app
```

## 9. 官方 Demo 3：LocalAttestation

仿真模式：

```bash
source /opt/intel/sgxsdk/environment
cd /opt/intel/sgxsdk/SampleCode/LocalAttestation

make clean
make SGX_MODE=SIM SGX_DEBUG=1
cd bin
./app
```

硬件模式：

```bash
cd /opt/intel/sgxsdk/SampleCode/LocalAttestation
make clean
make SGX_MODE=HW SGX_DEBUG=1
cd bin
./app
```

## 10. 官方 DCAP 代码

基础 Demo 全部成功后再做 Quote 生成和验证：

```bash
cd ~/projects
git clone https://github.com/intel/confidential-computing.tee.dcap.git
cd confidential-computing.tee.dcap
```

主要目录：

```text
QuoteGeneration/    Quote 生成
QuoteVerification/  Quote 验证
SampleCode/         官方示例
```

DCAP 联网认证还需要配置 QPL/PCCS；不属于第一轮本机 SGX 验证。

## 11. 新项目启动

原生 Intel SGX SDK 推荐使用 C/C++。Enclave 可信端使用 C/C++，边界接口写在 EDL 文件中；其他语言需要通过 C ABI、JNI 或 FFI 调用。

直接复制官方 SampleEnclave：

```bash
mkdir -p ~/projects
cp -a /opt/intel/sgxsdk/SampleCode/SampleEnclave ~/projects/my-sgx-project
cd ~/projects/my-sgx-project
git init
```

开发构建：

```bash
source /opt/intel/sgxsdk/environment

make clean
make SGX_MODE=SIM SGX_DEBUG=1
./app

make clean
make SGX_MODE=HW SGX_DEBUG=1
./app
```

调试：

```bash
sgx-gdb ./app
```