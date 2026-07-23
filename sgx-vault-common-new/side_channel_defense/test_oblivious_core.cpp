#include "ProtectedVaultCore.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void encode(const char *service_text, const char *username_text,
                   const char *password_text, ProtectedServiceInput *service,
                   ProtectedUsernameInput *username, ProtectedPasswordInput *password) {
    assert(protected_encode_service(service_text, service));
    assert(protected_encode_username(username_text, username));
    assert(protected_encode_password(password_text, password));
}

static bool same_stats(const ProtectedAccessStats &a, const ProtectedAccessStats &b) {
    return memcmp(&a, &b, sizeof(a)) == 0;
}

int main() {
    ProtectedVaultWire vault = {};
    vault.format_version = VAULT_FORMAT_VERSION;
    vault.state_version = 1;

    ProtectedServiceInput service = {};
    ProtectedUsernameInput username = {};
    ProtectedPasswordInput password = {};
    ProtectedAccessStats stats = {};

    encode("github", "alice", "github-secret", &service, &username, &password);
    assert(protected_vault_add(&vault, &service, &username, &password, &stats) == VAULT_OK);

    encode("bank", "alice-bank", "bank-secret", &service, &username, &password);
    protected_stats_reset(&stats);
    assert(protected_vault_add(&vault, &service, &username, &password, &stats) == VAULT_OK);

    ProtectedUsernameInput output_username = {};
    ProtectedPasswordInput output_password = {};
    ProtectedAccessStats github_stats = {};
    ProtectedAccessStats bank_stats = {};
    ProtectedAccessStats missing_stats = {};

    assert(protected_encode_service("github", &service));
    assert(protected_vault_get(
        &vault, &service, &output_username, &output_password, &github_stats) == VAULT_OK);
    assert(strcmp(output_username.bytes, "alice") == 0);
    assert(strcmp(output_password.bytes, "github-secret") == 0);

    assert(protected_encode_service("bank", &service));
    assert(protected_vault_get(
        &vault, &service, &output_username, &output_password, &bank_stats) == VAULT_OK);
    assert(strcmp(output_password.bytes, "bank-secret") == 0);

    assert(protected_encode_service("missing", &service));
    assert(protected_vault_get(
        &vault, &service, &output_username, &output_password, &missing_stats)
        == VAULT_ERR_NOT_FOUND);

    assert(same_stats(github_stats, bank_stats));
    assert(same_stats(github_stats, missing_stats));

    encode("bank", "new-user", "new-password", &service, &username, &password);
    assert(protected_vault_update(
        &vault, &service, &username, &password, nullptr) == VAULT_OK);
    assert(protected_vault_get(
        &vault, &service, &output_username, &output_password, nullptr) == VAULT_OK);
    assert(strcmp(output_password.bytes, "new-password") == 0);

    assert(protected_vault_delete(&vault, &service, nullptr) == VAULT_OK);
    assert(protected_vault_get(
        &vault, &service, &output_username, &output_password, nullptr)
        == VAULT_ERR_NOT_FOUND);

    puts("[PASS] protected vault core functional tests");
    puts("[PASS] get(first), get(second), and get(missing) have identical logical access counts");
    return 0;
}
