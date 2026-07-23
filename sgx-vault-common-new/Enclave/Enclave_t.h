#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "stdint.h"
#include "stddef.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_vault_create(const char* pin);
int ecall_vault_clear(void);
int ecall_vault_login(const char* pin);
int ecall_vault_add(const char* service, const char* username, const char* password);
int ecall_vault_get(const char* service, char* username, size_t username_capacity, char* password, size_t password_capacity);
int ecall_vault_update(const char* service, const char* username, const char* password);
int ecall_vault_delete(const char* service);
int ecall_vault_list(char* output, size_t output_capacity, size_t* required_size);
int ecall_vault_get_versions(uint32_t* format_version, uint64_t* state_version);
int ecall_vault_sealed_size(uint32_t* sealed_size);
int ecall_vault_seal(uint8_t* sealed, uint32_t sealed_capacity, uint32_t* actual_size);
int ecall_vault_unseal(const uint8_t* sealed, uint32_t sealed_size);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
