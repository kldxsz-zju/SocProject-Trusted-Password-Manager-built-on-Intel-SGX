#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "stdint.h"
#include "stddef.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecall_vault_create(sgx_enclave_id_t eid, int* retval, const char* pin);
sgx_status_t ecall_vault_clear(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_vault_login(sgx_enclave_id_t eid, int* retval, const char* pin);
sgx_status_t ecall_vault_add(sgx_enclave_id_t eid, int* retval, const char* service, const char* username, const char* password);
sgx_status_t ecall_vault_get(sgx_enclave_id_t eid, int* retval, const char* service, char* username, size_t username_capacity, char* password, size_t password_capacity);
sgx_status_t ecall_vault_update(sgx_enclave_id_t eid, int* retval, const char* service, const char* username, const char* password);
sgx_status_t ecall_vault_delete(sgx_enclave_id_t eid, int* retval, const char* service);
sgx_status_t ecall_vault_list(sgx_enclave_id_t eid, int* retval, char* output, size_t output_capacity, size_t* required_size);
sgx_status_t ecall_vault_get_versions(sgx_enclave_id_t eid, int* retval, uint32_t* format_version, uint64_t* state_version);
sgx_status_t ecall_vault_sealed_size(sgx_enclave_id_t eid, int* retval, uint32_t* sealed_size);
sgx_status_t ecall_vault_seal(sgx_enclave_id_t eid, int* retval, uint8_t* sealed, uint32_t sealed_capacity, uint32_t* actual_size);
sgx_status_t ecall_vault_unseal(sgx_enclave_id_t eid, int* retval, const uint8_t* sealed, uint32_t sealed_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
