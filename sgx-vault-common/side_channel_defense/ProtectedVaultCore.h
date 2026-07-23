#ifndef PROTECTED_VAULT_CORE_H
#define PROTECTED_VAULT_CORE_H

#include <stddef.h>
#include <stdint.h>

#include "../Include/VaultTypes.h"

/*
 * 与原 Enclave.cpp 保持相同的密封载荷布局，因此接入后不需要改变
 * vault.sealed 的业务数据格式。
 */
struct ProtectedCredentialWire {
    uint8_t in_use;
    char service[VAULT_SERVICE_MAX + 1];
    char username[VAULT_USERNAME_MAX + 1];
    char password[VAULT_PASSWORD_MAX + 1];
};

struct ProtectedVaultWire {
    uint32_t format_version;
    uint32_t credential_count;
    uint64_t state_version;
    uint8_t vault_id[16];
    uint8_t master_key[32];
    ProtectedCredentialWire credentials[VAULT_MAX_CREDENTIALS];
};

/* 固定大小的 Enclave 内部输入，调用前必须完整清零并填充。 */
struct ProtectedServiceInput {
    char bytes[VAULT_SERVICE_MAX + 1];
};

struct ProtectedUsernameInput {
    char bytes[VAULT_USERNAME_MAX + 1];
};

struct ProtectedPasswordInput {
    char bytes[VAULT_PASSWORD_MAX + 1];
};

/*
 * 调试计数器只用于验证所有目标槽位的触碰次数一致。
 * 它不是安全边界，也不能替代真实的缺页轨迹实验。
 */
struct ProtectedAccessStats {
    uint64_t slots_scanned;
    uint64_t service_bytes_read;
    uint64_t username_bytes_read;
    uint64_t password_bytes_read;
    uint64_t slots_written;
};

void protected_stats_reset(ProtectedAccessStats *stats);
void protected_secure_zero(void *ptr, size_t length);

bool protected_encode_service(const char *src, ProtectedServiceInput *dst);
bool protected_encode_username(const char *src, ProtectedUsernameInput *dst);
bool protected_encode_password(const char *src, ProtectedPasswordInput *dst);

int protected_vault_add(ProtectedVaultWire *vault,
                        const ProtectedServiceInput *service,
                        const ProtectedUsernameInput *username,
                        const ProtectedPasswordInput *password,
                        ProtectedAccessStats *stats);

int protected_vault_get(const ProtectedVaultWire *vault,
                        const ProtectedServiceInput *service,
                        ProtectedUsernameInput *username,
                        ProtectedPasswordInput *password,
                        ProtectedAccessStats *stats);

int protected_vault_update(ProtectedVaultWire *vault,
                           const ProtectedServiceInput *service,
                           const ProtectedUsernameInput *username,
                           const ProtectedPasswordInput *password,
                           ProtectedAccessStats *stats);

int protected_vault_delete(ProtectedVaultWire *vault,
                           const ProtectedServiceInput *service,
                           ProtectedAccessStats *stats);

#endif
