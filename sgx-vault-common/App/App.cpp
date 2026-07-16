#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include <iostream>
#include <vector>

#include "sgx_urts.h"
#include "Enclave_u.h"
#include "VaultTypes.h"

#define ENCLAVE_FILE "enclave.signed.so"
#define SEALED_FILE  "vault.sealed"

sgx_enclave_id_t g_eid = 0;

/* ── 工具函数：文件读写 ── */

static std::vector<uint8_t> read_file(const char *filename) {
    std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
    if (!ifs.good()) return {};
    size_t size = static_cast<size_t>(ifs.tellg());
    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(size);
    ifs.read(reinterpret_cast<char *>(buf.data()), size);
    return buf;
}

static bool write_file(const char *filename, const uint8_t *data, size_t size) {
    std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
    if (!ofs.good()) return false;
    ofs.write(reinterpret_cast<const char *>(data), size);
    return ofs.good();
}

/* ── OCALL 实现 ── */

void ocall_print(const char *str) {
    printf("%s", str);
}

/* ── 命令行交互函数 ── */

static int do_create() {
    int ret = 0;
    sgx_status_t st = ecall_vault_create(g_eid, &ret);
    if (st != SGX_SUCCESS) { printf("ECALL failed: 0x%x\n", st); return -1; }
    return ret;
}

static int do_load() {
    auto buf = read_file(SEALED_FILE);
    if (buf.empty()) {
        printf("File '%s' not found or empty.\n", SEALED_FILE);
        return VAULT_ERR_NOT_FOUND;
    }
    int ret = 0;
    sgx_status_t st = ecall_vault_unseal(g_eid, &ret, buf.data(), static_cast<uint32_t>(buf.size()));
    if (st != SGX_SUCCESS) { printf("ECALL failed: 0x%x\n", st); return -1; }
    return ret;
}

static int do_add() {
    std::string service, username, password;
    printf("Service name: ");  std::getline(std::cin, service);
    printf("Username: ");      std::getline(std::cin, username);
    printf("Password: ");      std::getline(std::cin, password);
    int ret = 0;
    sgx_status_t st = ecall_vault_add(g_eid, &ret, service.c_str(), username.c_str(), password.c_str());
    if (st != SGX_SUCCESS) { printf("ECALL failed: 0x%x\n", st); return -1; }
    return ret;
}

static int do_get() {
    std::string service;
    printf("Service name: "); std::getline(std::cin, service);

    std::vector<char> username(VAULT_USERNAME_MAX + 1);
    std::vector<char> password(VAULT_PASSWORD_MAX + 1);
    int ret = 0;
    sgx_status_t st = ecall_vault_get(g_eid, &ret,
        service.c_str(),
        username.data(), username.size(),
        password.data(), password.size());
    if (st != SGX_SUCCESS) { printf("ECALL failed: 0x%x\n", st); return -1; }
    if (ret == VAULT_OK)
        printf("Username: %s\nPassword: %s\n", username.data(), password.data());
    return ret;
}

static int do_update() {
    std::string service, username, password;
    printf("Service name: ");  std::getline(std::cin, service);
    printf("New username: ");  std::getline(std::cin, username);
    printf("New password: ");  std::getline(std::cin, password);
    int ret = 0;
    sgx_status_t st = ecall_vault_update(g_eid, &ret, service.c_str(), username.c_str(), password.c_str());
    if (st != SGX_SUCCESS) { printf("ECALL failed: 0x%x\n", st); return -1; }
    return ret;
}

static int do_delete() {
    std::string service;
    printf("Service name: "); std::getline(std::cin, service);
    int ret = 0;
    sgx_status_t st = ecall_vault_delete(g_eid, &ret, service.c_str());
    if (st != SGX_SUCCESS) { printf("ECALL failed: 0x%x\n", st); return -1; }
    return ret;
}

static int do_list() {
    size_t required = 0;
    int ret = 0;
    // 先查询需要多大缓冲区
    sgx_status_t st = ecall_vault_list(g_eid, &ret, nullptr, 0, &required);
    if (st != SGX_SUCCESS) { printf("ECALL failed: 0x%x\n", st); return -1; }
    if (ret != VAULT_ERR_BUFFER_TOO_SMALL && ret != VAULT_OK) return ret;

    std::vector<char> buf(required + 1);
    st = ecall_vault_list(g_eid, &ret, buf.data(), buf.size(), &required);
    if (st != SGX_SUCCESS) { printf("ECALL failed: 0x%x\n", st); return -1; }
    if (ret == VAULT_OK) printf("%s", buf.data());
    return ret;
}

static int do_versions() {
    uint32_t fmt = 0;
    uint64_t state = 0;
    int ret = 0;
    sgx_status_t st = ecall_vault_get_versions(g_eid, &ret, &fmt, &state);
    if (st != SGX_SUCCESS) { printf("ECALL failed: 0x%x\n", st); return -1; }
    if (ret == VAULT_OK)
        printf("Format version: %u, State version: %lu\n", fmt, state);
    return ret;
}

static int do_save() {
    uint32_t sealed_size = 0;
    int ret = 0;
    sgx_status_t st = ecall_vault_sealed_size(g_eid, &ret, &sealed_size);
    if (st != SGX_SUCCESS) { printf("ECALL failed: 0x%x\n", st); return -1; }
    if (ret != VAULT_OK) return ret;

    std::vector<uint8_t> buf(sealed_size);
    uint32_t actual = 0;
    st = ecall_vault_seal(g_eid, &ret, buf.data(), sealed_size, &actual);
    if (st != SGX_SUCCESS) { printf("ECALL failed: 0x%x\n", st); return -1; }
    if (ret != VAULT_OK) return ret;

    if (!write_file(SEALED_FILE, buf.data(), actual)) {
        printf("Failed to write '%s'.\n", SEALED_FILE);
        return -1;
    }
    printf("Vault saved to '%s' (%u bytes).\n", SEALED_FILE, actual);
    return VAULT_OK;
}

/* ── 错误码转可读信息 ── */

static void print_error(int code) {
    switch (code) {
        case VAULT_OK:                      printf("OK.\n"); break;
        case VAULT_ERR_INVALID_PARAMETER:   printf("Error: Invalid parameter.\n"); break;
        case VAULT_ERR_NOT_INITIALIZED:     printf("Error: Vault not initialized. Create or load first.\n"); break;
        case VAULT_ERR_ALREADY_INITIALIZED: printf("Error: Vault already initialized.\n"); break;
        case VAULT_ERR_DUPLICATE_SERVICE:   printf("Error: Service name already exists.\n"); break;
        case VAULT_ERR_NOT_FOUND:           printf("Error: Service not found.\n"); break;
        case VAULT_ERR_FULL:                printf("Error: Vault is full.\n"); break;
        case VAULT_ERR_BUFFER_TOO_SMALL:    printf("Error: Buffer too small.\n"); break;
        case VAULT_ERR_SEAL:                printf("Error: Seal operation failed.\n"); break;
        case VAULT_ERR_UNSEAL:              printf("Error: Unseal operation failed (wrong platform/enclave or corrupted file).\n"); break;
        case VAULT_ERR_FORMAT:              printf("Error: Unexpected sealed data format.\n"); break;
        case VAULT_ERR_CORRUPT:             printf("Error: Sealed data is corrupted or tampered.\n"); break;
        case VAULT_ERR_INTERNAL:            printf("Error: Internal error.\n"); break;
        default:                            printf("Error: Unknown (%d).\n", code); break;
    }
}

/* ── 主函数 ── */

int main() {
    // 加载 Enclave
    sgx_status_t st = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, nullptr, nullptr, &g_eid, nullptr);
    if (st != SGX_SUCCESS) {
        printf("Failed to load enclave: 0x%x\n", st);
        printf("Make sure '%s' exists and SGX environment is set up.\n", ENCLAVE_FILE);
        return 1;
    }
    printf("Enclave loaded successfully.\n\n");

    while (true) {
        printf("========================================\n");
        printf("  SGX Password Vault\n");
        printf("========================================\n");
        printf("  [1] Create vault\n");
        printf("  [2] Load vault from '%s'\n", SEALED_FILE);
        printf("  [3] Add credential\n");
        printf("  [4] Get credential\n");
        printf("  [5] Update credential\n");
        printf("  [6] Delete credential\n");
        printf("  [7] List services\n");
        printf("  [8] Show versions\n");
        printf("  [9] Save vault to '%s'\n", SEALED_FILE);
        printf("  [0] Exit\n");
        printf("----------------------------------------\n");
        printf("Choice: ");

        std::string line;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        int result = 0;
        switch (line[0]) {
            case '1': result = do_create(); break;
            case '2': result = do_load();   break;
            case '3': result = do_add();    break;
            case '4': result = do_get();    break;
            case '5': result = do_update(); break;
            case '6': result = do_delete(); break;
            case '7': result = do_list();   break;
            case '8': result = do_versions(); break;
            case '9': result = do_save();   break;
            case '0':
                sgx_destroy_enclave(g_eid);
                printf("Goodbye.\n");
                return 0;
            default:
                printf("Invalid choice.\n");
                continue;
        }
        print_error(result);
        printf("\n");
    }

    sgx_destroy_enclave(g_eid);
    return 0;
}
