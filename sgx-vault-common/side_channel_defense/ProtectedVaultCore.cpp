#include "ProtectedVaultCore.h"

#include <string.h>

namespace {

static uint32_t ct_is_zero_u32(uint32_t value) {
    /* 1 当且仅当 value == 0；不使用秘密相关跳转。 */
    return ((value | (0u - value)) >> 31) ^ 1u;
}

static uint32_t ct_eq_u32(uint32_t left, uint32_t right) {
    return ct_is_zero_u32(left ^ right);
}

static uint8_t ct_mask_u8(uint32_t bit) {
    return static_cast<uint8_t>(0u - (bit & 1u));
}

static uint32_t ct_select_u32(uint32_t bit, uint32_t when_true, uint32_t when_false) {
    const uint32_t mask = 0u - (bit & 1u);
    return (when_true & mask) | (when_false & ~mask);
}

static uint8_t ct_select_u8(uint8_t mask, uint8_t when_true, uint8_t when_false) {
    return static_cast<uint8_t>((when_true & mask) | (when_false & static_cast<uint8_t>(~mask)));
}

static uint32_t ct_equal_bytes(const char *left, const char *right, size_t length,
                               ProtectedAccessStats *stats) {
    uint32_t difference = 0;
    for (size_t i = 0; i < length; ++i) {
        difference |= static_cast<uint8_t>(left[i]) ^ static_cast<uint8_t>(right[i]);
        if (stats != nullptr) ++stats->service_bytes_read;
    }
    return ct_is_zero_u32(difference);
}

static uint32_t find_match_masked(const ProtectedVaultWire *vault,
                                  const ProtectedServiceInput *service,
                                  uint32_t *selected_index,
                                  ProtectedAccessStats *stats) {
    uint32_t found = 0;
    uint32_t selected = 0;

    for (uint32_t i = 0; i < VAULT_MAX_CREDENTIALS; ++i) {
        const ProtectedCredentialWire &slot = vault->credentials[i];
        const uint32_t equal = ct_equal_bytes(
            slot.service, service->bytes, sizeof(slot.service), stats);
        const uint32_t match = (static_cast<uint32_t>(slot.in_use) & 1u) & equal;
        const uint32_t take = match & (found ^ 1u);
        selected = ct_select_u32(take, i, selected);
        found |= match;
        if (stats != nullptr) ++stats->slots_scanned;
    }

    *selected_index = selected;
    return found & 1u;
}

template <size_t N>
static void masked_copy_out(char (&destination)[N], const char (&source)[N],
                            uint8_t mask, uint64_t *counter) {
    for (size_t i = 0; i < N; ++i) {
        const uint8_t old_value = static_cast<uint8_t>(destination[i]);
        const uint8_t new_value = static_cast<uint8_t>(source[i]);
        destination[i] = static_cast<char>(
            old_value | (new_value & mask));
        if (counter != nullptr) ++*counter;
    }
}

template <size_t N>
static void masked_assign(char (&destination)[N], const char (&source)[N],
                          uint8_t mask, uint64_t *counter) {
    for (size_t i = 0; i < N; ++i) {
        destination[i] = static_cast<char>(ct_select_u8(
            mask, static_cast<uint8_t>(source[i]),
            static_cast<uint8_t>(destination[i])));
        if (counter != nullptr) ++*counter;
    }
}

template <size_t N>
static bool encode_fixed(const char *src, char (&dst)[N], bool allow_empty) {
    if (src == nullptr) return false;
    size_t length = 0;
    while (length < N && src[length] != '\0') ++length;
    if (length == N || (!allow_empty && length == 0)) return false;
    protected_secure_zero(dst, N);
    memcpy(dst, src, length);
    return true;
}

}  // namespace

void protected_stats_reset(ProtectedAccessStats *stats) {
    if (stats != nullptr) protected_secure_zero(stats, sizeof(*stats));
}

void protected_secure_zero(void *ptr, size_t length) {
    volatile uint8_t *bytes = static_cast<volatile uint8_t *>(ptr);
    while (length-- != 0) *bytes++ = 0;
}

bool protected_encode_service(const char *src, ProtectedServiceInput *dst) {
    return dst != nullptr && encode_fixed(src, dst->bytes, false);
}

bool protected_encode_username(const char *src, ProtectedUsernameInput *dst) {
    return dst != nullptr && encode_fixed(src, dst->bytes, true);
}

bool protected_encode_password(const char *src, ProtectedPasswordInput *dst) {
    return dst != nullptr && encode_fixed(src, dst->bytes, true);
}

int protected_vault_get(const ProtectedVaultWire *vault,
                        const ProtectedServiceInput *service,
                        ProtectedUsernameInput *username,
                        ProtectedPasswordInput *password,
                        ProtectedAccessStats *stats) {
    if (vault == nullptr || service == nullptr || username == nullptr || password == nullptr)
        return VAULT_ERR_INVALID_PARAMETER;

    protected_secure_zero(username, sizeof(*username));
    protected_secure_zero(password, sizeof(*password));

    uint32_t selected = 0;
    const uint32_t found = find_match_masked(vault, service, &selected, stats);

    /*
     * 不能在查找后直接访问 credentials[selected]。再次固定扫描整个表，
     * 并用掩码提取结果，使数据页轨迹不依赖目标索引。
     */
    for (uint32_t i = 0; i < VAULT_MAX_CREDENTIALS; ++i) {
        const uint8_t mask = ct_mask_u8(found & ct_eq_u32(i, selected));
        const ProtectedCredentialWire &slot = vault->credentials[i];
        masked_copy_out(username->bytes, slot.username, mask,
                        stats == nullptr ? nullptr : &stats->username_bytes_read);
        masked_copy_out(password->bytes, slot.password, mask,
                        stats == nullptr ? nullptr : &stats->password_bytes_read);
    }

    return ct_select_u32(found, VAULT_OK, VAULT_ERR_NOT_FOUND);
}

int protected_vault_update(ProtectedVaultWire *vault,
                           const ProtectedServiceInput *service,
                           const ProtectedUsernameInput *username,
                           const ProtectedPasswordInput *password,
                           ProtectedAccessStats *stats) {
    if (vault == nullptr || service == nullptr || username == nullptr || password == nullptr)
        return VAULT_ERR_INVALID_PARAMETER;

    uint32_t selected = 0;
    const uint32_t found = find_match_masked(vault, service, &selected, stats);
    const uint32_t version_ok = static_cast<uint32_t>(vault->state_version != UINT64_MAX);
    const uint32_t apply = found & version_ok;

    for (uint32_t i = 0; i < VAULT_MAX_CREDENTIALS; ++i) {
        const uint8_t mask = ct_mask_u8(apply & ct_eq_u32(i, selected));
        ProtectedCredentialWire &slot = vault->credentials[i];
        masked_assign(slot.username, username->bytes, mask,
                      stats == nullptr ? nullptr : &stats->username_bytes_read);
        masked_assign(slot.password, password->bytes, mask,
                      stats == nullptr ? nullptr : &stats->password_bytes_read);
        if (stats != nullptr) ++stats->slots_written;
    }
    vault->state_version += apply;

    const uint32_t result = ct_select_u32(found, VAULT_OK, VAULT_ERR_NOT_FOUND);
    return ct_select_u32(version_ok, result, VAULT_ERR_INTERNAL);
}

int protected_vault_delete(ProtectedVaultWire *vault,
                           const ProtectedServiceInput *service,
                           ProtectedAccessStats *stats) {
    if (vault == nullptr || service == nullptr) return VAULT_ERR_INVALID_PARAMETER;

    uint32_t selected = 0;
    const uint32_t found = find_match_masked(vault, service, &selected, stats);
    const uint32_t version_ok = static_cast<uint32_t>(vault->state_version != UINT64_MAX);
    const uint32_t apply = found & version_ok;

    const ProtectedCredentialWire zero_slot = {};
    for (uint32_t i = 0; i < VAULT_MAX_CREDENTIALS; ++i) {
        ProtectedCredentialWire &slot = vault->credentials[i];
        const uint8_t mask = ct_mask_u8(apply & ct_eq_u32(i, selected));
        uint8_t *destination = reinterpret_cast<uint8_t *>(&slot);
        const uint8_t *zeros = reinterpret_cast<const uint8_t *>(&zero_slot);
        for (size_t j = 0; j < sizeof(slot); ++j)
            destination[j] = ct_select_u8(mask, zeros[j], destination[j]);
        if (stats != nullptr) ++stats->slots_written;
    }
    vault->credential_count -= apply;
    vault->state_version += apply;

    const uint32_t result = ct_select_u32(found, VAULT_OK, VAULT_ERR_NOT_FOUND);
    return ct_select_u32(version_ok, result, VAULT_ERR_INTERNAL);
}

int protected_vault_add(ProtectedVaultWire *vault,
                        const ProtectedServiceInput *service,
                        const ProtectedUsernameInput *username,
                        const ProtectedPasswordInput *password,
                        ProtectedAccessStats *stats) {
    if (vault == nullptr || service == nullptr || username == nullptr || password == nullptr)
        return VAULT_ERR_INVALID_PARAMETER;

    uint32_t duplicate_index = 0;
    const uint32_t duplicate = find_match_masked(vault, service, &duplicate_index, stats);

    uint32_t empty_found = 0;
    uint32_t selected = 0;
    for (uint32_t i = 0; i < VAULT_MAX_CREDENTIALS; ++i) {
        const uint32_t empty = ct_is_zero_u32(vault->credentials[i].in_use);
        const uint32_t take = empty & (empty_found ^ 1u);
        selected = ct_select_u32(take, i, selected);
        empty_found |= empty;
        if (stats != nullptr) ++stats->slots_scanned;
    }

    const uint32_t version_ok = static_cast<uint32_t>(vault->state_version != UINT64_MAX);
    const uint32_t apply = (duplicate ^ 1u) & empty_found & version_ok;
    for (uint32_t i = 0; i < VAULT_MAX_CREDENTIALS; ++i) {
        ProtectedCredentialWire &slot = vault->credentials[i];
        const uint8_t mask = ct_mask_u8(apply & ct_eq_u32(i, selected));
        const uint8_t one = 1;
        slot.in_use = ct_select_u8(mask, one, slot.in_use);
        masked_assign(slot.service, service->bytes, mask,
                      stats == nullptr ? nullptr : &stats->service_bytes_read);
        masked_assign(slot.username, username->bytes, mask,
                      stats == nullptr ? nullptr : &stats->username_bytes_read);
        masked_assign(slot.password, password->bytes, mask,
                      stats == nullptr ? nullptr : &stats->password_bytes_read);
        if (stats != nullptr) ++stats->slots_written;
    }
    vault->credential_count += apply;
    vault->state_version += apply;

    const uint32_t no_space_result = ct_select_u32(
        empty_found, VAULT_OK, VAULT_ERR_FULL);
    const uint32_t duplicate_result = ct_select_u32(
        duplicate, VAULT_ERR_DUPLICATE_SERVICE, no_space_result);
    return ct_select_u32(version_ok, duplicate_result, VAULT_ERR_INTERNAL);
}
