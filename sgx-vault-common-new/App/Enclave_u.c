#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_vault_create_t {
	int ms_retval;
	const char* ms_pin;
	size_t ms_pin_len;
} ms_ecall_vault_create_t;

typedef struct ms_ecall_vault_clear_t {
	int ms_retval;
} ms_ecall_vault_clear_t;

typedef struct ms_ecall_vault_login_t {
	int ms_retval;
	const char* ms_pin;
	size_t ms_pin_len;
} ms_ecall_vault_login_t;

typedef struct ms_ecall_vault_add_t {
	int ms_retval;
	const char* ms_service;
	size_t ms_service_len;
	const char* ms_username;
	size_t ms_username_len;
	const char* ms_password;
	size_t ms_password_len;
} ms_ecall_vault_add_t;

typedef struct ms_ecall_vault_get_t {
	int ms_retval;
	const char* ms_service;
	size_t ms_service_len;
	char* ms_username;
	size_t ms_username_capacity;
	char* ms_password;
	size_t ms_password_capacity;
} ms_ecall_vault_get_t;

typedef struct ms_ecall_vault_update_t {
	int ms_retval;
	const char* ms_service;
	size_t ms_service_len;
	const char* ms_username;
	size_t ms_username_len;
	const char* ms_password;
	size_t ms_password_len;
} ms_ecall_vault_update_t;

typedef struct ms_ecall_vault_delete_t {
	int ms_retval;
	const char* ms_service;
	size_t ms_service_len;
} ms_ecall_vault_delete_t;

typedef struct ms_ecall_vault_list_t {
	int ms_retval;
	char* ms_output;
	size_t ms_output_capacity;
	size_t* ms_required_size;
} ms_ecall_vault_list_t;

typedef struct ms_ecall_vault_get_versions_t {
	int ms_retval;
	uint32_t* ms_format_version;
	uint64_t* ms_state_version;
} ms_ecall_vault_get_versions_t;

typedef struct ms_ecall_vault_sealed_size_t {
	int ms_retval;
	uint32_t* ms_sealed_size;
} ms_ecall_vault_sealed_size_t;

typedef struct ms_ecall_vault_seal_t {
	int ms_retval;
	uint8_t* ms_sealed;
	uint32_t ms_sealed_capacity;
	uint32_t* ms_actual_size;
} ms_ecall_vault_seal_t;

typedef struct ms_ecall_vault_unseal_t {
	int ms_retval;
	const uint8_t* ms_sealed;
	uint32_t ms_sealed_size;
} ms_ecall_vault_unseal_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[6];
} ocall_table_Enclave = {
	6,
	{
		(void*)Enclave_ocall_print,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_vault_create(sgx_enclave_id_t eid, int* retval, const char* pin)
{
	sgx_status_t status;
	ms_ecall_vault_create_t ms;
	ms.ms_pin = pin;
	ms.ms_pin_len = pin ? strlen(pin) + 1 : 0;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_vault_clear(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_vault_clear_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_vault_login(sgx_enclave_id_t eid, int* retval, const char* pin)
{
	sgx_status_t status;
	ms_ecall_vault_login_t ms;
	ms.ms_pin = pin;
	ms.ms_pin_len = pin ? strlen(pin) + 1 : 0;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_vault_add(sgx_enclave_id_t eid, int* retval, const char* service, const char* username, const char* password)
{
	sgx_status_t status;
	ms_ecall_vault_add_t ms;
	ms.ms_service = service;
	ms.ms_service_len = service ? strlen(service) + 1 : 0;
	ms.ms_username = username;
	ms.ms_username_len = username ? strlen(username) + 1 : 0;
	ms.ms_password = password;
	ms.ms_password_len = password ? strlen(password) + 1 : 0;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_vault_get(sgx_enclave_id_t eid, int* retval, const char* service, char* username, size_t username_capacity, char* password, size_t password_capacity)
{
	sgx_status_t status;
	ms_ecall_vault_get_t ms;
	ms.ms_service = service;
	ms.ms_service_len = service ? strlen(service) + 1 : 0;
	ms.ms_username = username;
	ms.ms_username_capacity = username_capacity;
	ms.ms_password = password;
	ms.ms_password_capacity = password_capacity;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_vault_update(sgx_enclave_id_t eid, int* retval, const char* service, const char* username, const char* password)
{
	sgx_status_t status;
	ms_ecall_vault_update_t ms;
	ms.ms_service = service;
	ms.ms_service_len = service ? strlen(service) + 1 : 0;
	ms.ms_username = username;
	ms.ms_username_len = username ? strlen(username) + 1 : 0;
	ms.ms_password = password;
	ms.ms_password_len = password ? strlen(password) + 1 : 0;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_vault_delete(sgx_enclave_id_t eid, int* retval, const char* service)
{
	sgx_status_t status;
	ms_ecall_vault_delete_t ms;
	ms.ms_service = service;
	ms.ms_service_len = service ? strlen(service) + 1 : 0;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_vault_list(sgx_enclave_id_t eid, int* retval, char* output, size_t output_capacity, size_t* required_size)
{
	sgx_status_t status;
	ms_ecall_vault_list_t ms;
	ms.ms_output = output;
	ms.ms_output_capacity = output_capacity;
	ms.ms_required_size = required_size;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_vault_get_versions(sgx_enclave_id_t eid, int* retval, uint32_t* format_version, uint64_t* state_version)
{
	sgx_status_t status;
	ms_ecall_vault_get_versions_t ms;
	ms.ms_format_version = format_version;
	ms.ms_state_version = state_version;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_vault_sealed_size(sgx_enclave_id_t eid, int* retval, uint32_t* sealed_size)
{
	sgx_status_t status;
	ms_ecall_vault_sealed_size_t ms;
	ms.ms_sealed_size = sealed_size;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_vault_seal(sgx_enclave_id_t eid, int* retval, uint8_t* sealed, uint32_t sealed_capacity, uint32_t* actual_size)
{
	sgx_status_t status;
	ms_ecall_vault_seal_t ms;
	ms.ms_sealed = sealed;
	ms.ms_sealed_capacity = sealed_capacity;
	ms.ms_actual_size = actual_size;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_vault_unseal(sgx_enclave_id_t eid, int* retval, const uint8_t* sealed, uint32_t sealed_size)
{
	sgx_status_t status;
	ms_ecall_vault_unseal_t ms;
	ms.ms_sealed = sealed;
	ms.ms_sealed_size = sealed_size;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

