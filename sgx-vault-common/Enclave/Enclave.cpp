#include "Enclave_t.h"
#include "VaultTypes.h"

#include <sgx_tseal.h>
#include <sgx_trts.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace {

/* 磁盘明文布局永远不会直接写盘；整个 VaultWire 都是 sealing 的加密载荷。 */
struct CredentialWire {
    uint8_t in_use;
    char service[VAULT_SERVICE_MAX + 1];
    char username[VAULT_USERNAME_MAX + 1];
    char password[VAULT_PASSWORD_MAX + 1];
};

struct VaultWire {
    uint32_t format_version;
    uint32_t credential_count;
    uint64_t state_version;
    uint8_t vault_id[16];
    /* 密码库级随机主密钥只存在于可信内存与 sealing 加密载荷中，不跨 ECALL 暴露。 */
    uint8_t master_key[32];
    CredentialWire credentials[VAULT_MAX_CREDENTIALS];
};

static VaultWire g_vault;
static bool g_initialized = false;

/* volatile 写避免清理被优化器删除；所有临时明文均经此函数销毁。 */
static void secure_zero(void *ptr, size_t length) {
    volatile uint8_t *p = static_cast<volatile uint8_t *>(ptr);
    while (length-- != 0) *p++ = 0;
}

static bool valid_c_string(const char *s, size_t max_len, bool allow_empty) {
    if (s == nullptr) return false;
    const size_t n = strnlen(s, max_len + 1);
    return n <= max_len && (allow_empty || n != 0);
}

static int find_service(const char *service) {
    for (uint32_t i = 0; i < VAULT_MAX_CREDENTIALS; ++i) {
        if (g_vault.credentials[i].in_use != 0 &&
            strcmp(g_vault.credentials[i].service, service) == 0) return static_cast<int>(i);
    }
    return -1;
}

static void copy_string(char *dst, size_t capacity, const char *src) {
    const size_t n = strnlen(src, capacity - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static bool terminated(const char *s, size_t capacity) {
    return memchr(s, '\0', capacity) != nullptr;
}

/* 不信任解封后的业务字段：即使 SGX 已验证 MAC，也要防旧格式和逻辑损坏。 */
static bool validate_wire(const VaultWire &candidate) {
    if (candidate.format_version != VAULT_FORMAT_VERSION ||
        candidate.credential_count > VAULT_MAX_CREDENTIALS ||
        candidate.state_version == 0) return false;

    uint32_t seen = 0;
    for (uint32_t i = 0; i < VAULT_MAX_CREDENTIALS; ++i) {
        const CredentialWire &c = candidate.credentials[i];
        if (c.in_use > 1) return false;
        if (c.in_use == 0) continue;
        ++seen;
        if (!terminated(c.service, sizeof(c.service)) || c.service[0] == '\0' ||
            !terminated(c.username, sizeof(c.username)) ||
            !terminated(c.password, sizeof(c.password))) return false;
        for (uint32_t j = i + 1; j < VAULT_MAX_CREDENTIALS; ++j) {
            const CredentialWire &other = candidate.credentials[j];
            if (other.in_use == 1 && terminated(other.service, sizeof(other.service)) &&
                strcmp(c.service, other.service) == 0) return false;
        }
    }
    return seen == candidate.credential_count;
}

}  // namespace

int ecall_vault_create() {
    if (g_initialized) return VAULT_ERR_ALREADY_INITIALIZED;
    secure_zero(&g_vault, sizeof(g_vault));
    g_vault.format_version = VAULT_FORMAT_VERSION;
    g_vault.state_version = 1;
    if (sgx_read_rand(g_vault.vault_id, sizeof(g_vault.vault_id)) != SGX_SUCCESS ||
        sgx_read_rand(g_vault.master_key, sizeof(g_vault.master_key)) != SGX_SUCCESS) {
        secure_zero(&g_vault, sizeof(g_vault));
        return VAULT_ERR_INTERNAL;
    }
    g_initialized = true;
    return VAULT_OK;
}

int ecall_vault_clear() {
    secure_zero(&g_vault, sizeof(g_vault));
    g_initialized = false;
    return VAULT_OK;
}

int ecall_vault_add(const char *service, const char *username, const char *password) {
    if (!g_initialized) return VAULT_ERR_NOT_INITIALIZED;
    if (!valid_c_string(service, VAULT_SERVICE_MAX, false) ||
        !valid_c_string(username, VAULT_USERNAME_MAX, true) ||
        !valid_c_string(password, VAULT_PASSWORD_MAX, true)) return VAULT_ERR_INVALID_PARAMETER;
    if (find_service(service) >= 0) return VAULT_ERR_DUPLICATE_SERVICE;
    if (g_vault.credential_count == VAULT_MAX_CREDENTIALS) return VAULT_ERR_FULL;
    if (g_vault.state_version == UINT64_MAX) return VAULT_ERR_INTERNAL;
    for (uint32_t i = 0; i < VAULT_MAX_CREDENTIALS; ++i) {
        CredentialWire &c = g_vault.credentials[i];
        if (c.in_use == 0) {
            secure_zero(&c, sizeof(c));
            copy_string(c.service, sizeof(c.service), service);
            copy_string(c.username, sizeof(c.username), username);
            copy_string(c.password, sizeof(c.password), password);
            c.in_use = 1;
            ++g_vault.credential_count;
            ++g_vault.state_version;
            return VAULT_OK;
        }
    }
    return VAULT_ERR_INTERNAL;
}

int ecall_vault_get(const char *service, char *username, size_t username_capacity,
                    char *password, size_t password_capacity) {
    if (username != nullptr && username_capacity != 0) secure_zero(username, username_capacity);
    if (password != nullptr && password_capacity != 0) secure_zero(password, password_capacity);
    if (!g_initialized) return VAULT_ERR_NOT_INITIALIZED;
    if (!valid_c_string(service, VAULT_SERVICE_MAX, false) || username == nullptr ||
        password == nullptr || username_capacity == 0 || password_capacity == 0)
        return VAULT_ERR_INVALID_PARAMETER;
    const int index = find_service(service);
    if (index < 0) return VAULT_ERR_NOT_FOUND;
    const CredentialWire &c = g_vault.credentials[index];
    if (username_capacity <= strnlen(c.username, sizeof(c.username)) ||
        password_capacity <= strnlen(c.password, sizeof(c.password))) return VAULT_ERR_BUFFER_TOO_SMALL;
    copy_string(username, username_capacity, c.username);
    copy_string(password, password_capacity, c.password);
    return VAULT_OK;
}

int ecall_vault_update(const char *service, const char *username, const char *password) {
    if (!g_initialized) return VAULT_ERR_NOT_INITIALIZED;
    if (!valid_c_string(service, VAULT_SERVICE_MAX, false) ||
        !valid_c_string(username, VAULT_USERNAME_MAX, true) ||
        !valid_c_string(password, VAULT_PASSWORD_MAX, true)) return VAULT_ERR_INVALID_PARAMETER;
    const int index = find_service(service);
    if (index < 0) return VAULT_ERR_NOT_FOUND;
    if (g_vault.state_version == UINT64_MAX) return VAULT_ERR_INTERNAL;
    CredentialWire &c = g_vault.credentials[index];
    secure_zero(c.username, sizeof(c.username));
    secure_zero(c.password, sizeof(c.password));
    copy_string(c.username, sizeof(c.username), username);
    copy_string(c.password, sizeof(c.password), password);
    ++g_vault.state_version;
    return VAULT_OK;
}

int ecall_vault_delete(const char *service) {
    if (!g_initialized) return VAULT_ERR_NOT_INITIALIZED;
    if (!valid_c_string(service, VAULT_SERVICE_MAX, false)) return VAULT_ERR_INVALID_PARAMETER;
    const int index = find_service(service);
    if (index < 0) return VAULT_ERR_NOT_FOUND;
    if (g_vault.state_version == UINT64_MAX) return VAULT_ERR_INTERNAL;
    secure_zero(&g_vault.credentials[index], sizeof(CredentialWire));
    --g_vault.credential_count;
    ++g_vault.state_version;
    return VAULT_OK;
}

int ecall_vault_list(char *output, size_t output_capacity, size_t *required_size) {
    if (required_size == nullptr) return VAULT_ERR_INVALID_PARAMETER;
    *required_size = 1;
    if (!g_initialized) return VAULT_ERR_NOT_INITIALIZED;
    for (uint32_t i = 0; i < VAULT_MAX_CREDENTIALS; ++i)
        if (g_vault.credentials[i].in_use) *required_size += strlen(g_vault.credentials[i].service) + 1;
    if (output == nullptr || output_capacity < *required_size) return VAULT_ERR_BUFFER_TOO_SMALL;
    size_t offset = 0;
    for (uint32_t i = 0; i < VAULT_MAX_CREDENTIALS; ++i) {
        if (!g_vault.credentials[i].in_use) continue;
        const size_t n = strlen(g_vault.credentials[i].service);
        memcpy(output + offset, g_vault.credentials[i].service, n);
        offset += n;
        output[offset++] = '\n';
    }
    output[offset] = '\0';
    return VAULT_OK;
}

int ecall_vault_get_versions(uint32_t *format_version, uint64_t *state_version) {
    if (!g_initialized) return VAULT_ERR_NOT_INITIALIZED;
    if (format_version == nullptr || state_version == nullptr) return VAULT_ERR_INVALID_PARAMETER;
    *format_version = g_vault.format_version;
    *state_version = g_vault.state_version;
    return VAULT_OK;
}

int ecall_vault_sealed_size(uint32_t *sealed_size) {
    if (!g_initialized) return VAULT_ERR_NOT_INITIALIZED;
    if (sealed_size == nullptr) return VAULT_ERR_INVALID_PARAMETER;
    const uint32_t n = sgx_calc_sealed_data_size(0, static_cast<uint32_t>(sizeof(VaultWire)));
    if (n == UINT32_MAX) return VAULT_ERR_SEAL;
    *sealed_size = n;
    return VAULT_OK;
}

int ecall_vault_seal(uint8_t *sealed, uint32_t sealed_capacity, uint32_t *actual_size) {
    if (!g_initialized) return VAULT_ERR_NOT_INITIALIZED;
    if (sealed == nullptr || actual_size == nullptr) return VAULT_ERR_INVALID_PARAMETER;
    const uint32_t needed = sgx_calc_sealed_data_size(0, static_cast<uint32_t>(sizeof(VaultWire)));
    if (needed == UINT32_MAX) return VAULT_ERR_SEAL;
    *actual_size = needed;
    if (sealed_capacity < needed) return VAULT_ERR_BUFFER_TOO_SMALL;

    /* 默认 MRENCLAVE；实验二可用 make SEAL_POLICY=MRSIGNER 切换，而无需改业务代码。 */
#ifdef VAULT_POLICY_MRSIGNER
    const sgx_key_policy_t policy = SGX_KEYPOLICY_MRSIGNER;
#else
    const sgx_key_policy_t policy = SGX_KEYPOLICY_MRENCLAVE;
#endif
    sgx_attributes_t attribute_mask = {};
    attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
    attribute_mask.xfrm = 0;
    const sgx_status_t status = sgx_seal_data_ex(
        policy, attribute_mask, TSEAL_DEFAULT_MISCMASK, 0, nullptr,
        static_cast<uint32_t>(sizeof(VaultWire)),
        reinterpret_cast<const uint8_t *>(&g_vault), needed,
        reinterpret_cast<sgx_sealed_data_t *>(sealed));
    return status == SGX_SUCCESS ? VAULT_OK : VAULT_ERR_SEAL;
}

int ecall_vault_unseal(const uint8_t *sealed, uint32_t sealed_size) {
    if (sealed == nullptr || sealed_size < sizeof(sgx_sealed_data_t)) return VAULT_ERR_INVALID_PARAMETER;
    const sgx_sealed_data_t *blob = reinterpret_cast<const sgx_sealed_data_t *>(sealed);
    const uint32_t encrypted_size = sgx_get_encrypt_txt_len(blob);
    const uint32_t aad_size = sgx_get_add_mac_txt_len(blob);
    if (encrypted_size != sizeof(VaultWire) || aad_size != 0 ||
        sgx_calc_sealed_data_size(aad_size, encrypted_size) != sealed_size) return VAULT_ERR_FORMAT;

    VaultWire candidate;
    secure_zero(&candidate, sizeof(candidate));
    uint32_t plaintext_size = sizeof(candidate);
    const sgx_status_t status = sgx_unseal_data(
        blob, nullptr, nullptr, reinterpret_cast<uint8_t *>(&candidate), &plaintext_size);
    if (status != SGX_SUCCESS) {
        secure_zero(&candidate, sizeof(candidate));
        return VAULT_ERR_UNSEAL;
    }
    if (plaintext_size != sizeof(candidate) || !validate_wire(candidate)) {
        secure_zero(&candidate, sizeof(candidate));
        return VAULT_ERR_CORRUPT;
    }
    secure_zero(&g_vault, sizeof(g_vault));
    memcpy(&g_vault, &candidate, sizeof(g_vault));
    secure_zero(&candidate, sizeof(candidate));
    g_initialized = true;
    return VAULT_OK;
}
