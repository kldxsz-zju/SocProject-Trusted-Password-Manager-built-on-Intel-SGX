#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_vault_create(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vault_create_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vault_create_t* ms = SGX_CAST(ms_ecall_vault_create_t*, pms);
	ms_ecall_vault_create_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_vault_create_t), ms, sizeof(ms_ecall_vault_create_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_pin = __in_ms.ms_pin;
	size_t _len_pin = __in_ms.ms_pin_len ;
	char* _in_pin = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_pin, _len_pin);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pin != NULL && _len_pin != 0) {
		_in_pin = (char*)malloc(_len_pin);
		if (_in_pin == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pin, _len_pin, _tmp_pin, _len_pin)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_pin[_len_pin - 1] = '\0';
		if (_len_pin != strlen(_in_pin) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_vault_create((const char*)_in_pin);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_pin) free(_in_pin);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_vault_clear(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vault_clear_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vault_clear_t* ms = SGX_CAST(ms_ecall_vault_clear_t*, pms);
	ms_ecall_vault_clear_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_vault_clear_t), ms, sizeof(ms_ecall_vault_clear_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_vault_clear();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_vault_login(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vault_login_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vault_login_t* ms = SGX_CAST(ms_ecall_vault_login_t*, pms);
	ms_ecall_vault_login_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_vault_login_t), ms, sizeof(ms_ecall_vault_login_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_pin = __in_ms.ms_pin;
	size_t _len_pin = __in_ms.ms_pin_len ;
	char* _in_pin = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_pin, _len_pin);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_pin != NULL && _len_pin != 0) {
		_in_pin = (char*)malloc(_len_pin);
		if (_in_pin == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_pin, _len_pin, _tmp_pin, _len_pin)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_pin[_len_pin - 1] = '\0';
		if (_len_pin != strlen(_in_pin) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_vault_login((const char*)_in_pin);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_pin) free(_in_pin);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_vault_add(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vault_add_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vault_add_t* ms = SGX_CAST(ms_ecall_vault_add_t*, pms);
	ms_ecall_vault_add_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_vault_add_t), ms, sizeof(ms_ecall_vault_add_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_service = __in_ms.ms_service;
	size_t _len_service = __in_ms.ms_service_len ;
	char* _in_service = NULL;
	const char* _tmp_username = __in_ms.ms_username;
	size_t _len_username = __in_ms.ms_username_len ;
	char* _in_username = NULL;
	const char* _tmp_password = __in_ms.ms_password;
	size_t _len_password = __in_ms.ms_password_len ;
	char* _in_password = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_service, _len_service);
	CHECK_UNIQUE_POINTER(_tmp_username, _len_username);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_service != NULL && _len_service != 0) {
		_in_service = (char*)malloc(_len_service);
		if (_in_service == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_service, _len_service, _tmp_service, _len_service)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_service[_len_service - 1] = '\0';
		if (_len_service != strlen(_in_service) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_username != NULL && _len_username != 0) {
		_in_username = (char*)malloc(_len_username);
		if (_in_username == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_username, _len_username, _tmp_username, _len_username)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_username[_len_username - 1] = '\0';
		if (_len_username != strlen(_in_username) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_password != NULL && _len_password != 0) {
		_in_password = (char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_password, _len_password, _tmp_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_password[_len_password - 1] = '\0';
		if (_len_password != strlen(_in_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_vault_add((const char*)_in_service, (const char*)_in_username, (const char*)_in_password);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_service) free(_in_service);
	if (_in_username) free(_in_username);
	if (_in_password) free(_in_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_vault_get(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vault_get_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vault_get_t* ms = SGX_CAST(ms_ecall_vault_get_t*, pms);
	ms_ecall_vault_get_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_vault_get_t), ms, sizeof(ms_ecall_vault_get_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_service = __in_ms.ms_service;
	size_t _len_service = __in_ms.ms_service_len ;
	char* _in_service = NULL;
	char* _tmp_username = __in_ms.ms_username;
	size_t _tmp_username_capacity = __in_ms.ms_username_capacity;
	size_t _len_username = _tmp_username_capacity;
	char* _in_username = NULL;
	char* _tmp_password = __in_ms.ms_password;
	size_t _tmp_password_capacity = __in_ms.ms_password_capacity;
	size_t _len_password = _tmp_password_capacity;
	char* _in_password = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_service, _len_service);
	CHECK_UNIQUE_POINTER(_tmp_username, _len_username);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_service != NULL && _len_service != 0) {
		_in_service = (char*)malloc(_len_service);
		if (_in_service == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_service, _len_service, _tmp_service, _len_service)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_service[_len_service - 1] = '\0';
		if (_len_service != strlen(_in_service) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_username != NULL && _len_username != 0) {
		if ( _len_username % sizeof(*_tmp_username) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_username = (char*)malloc(_len_username)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_username, 0, _len_username);
	}
	if (_tmp_password != NULL && _len_password != 0) {
		if ( _len_password % sizeof(*_tmp_password) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_password = (char*)malloc(_len_password)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_password, 0, _len_password);
	}
	_in_retval = ecall_vault_get((const char*)_in_service, _in_username, _tmp_username_capacity, _in_password, _tmp_password_capacity);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_username) {
		if (memcpy_verw_s(_tmp_username, _len_username, _in_username, _len_username)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_password) {
		if (memcpy_verw_s(_tmp_password, _len_password, _in_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_service) free(_in_service);
	if (_in_username) free(_in_username);
	if (_in_password) free(_in_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_vault_update(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vault_update_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vault_update_t* ms = SGX_CAST(ms_ecall_vault_update_t*, pms);
	ms_ecall_vault_update_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_vault_update_t), ms, sizeof(ms_ecall_vault_update_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_service = __in_ms.ms_service;
	size_t _len_service = __in_ms.ms_service_len ;
	char* _in_service = NULL;
	const char* _tmp_username = __in_ms.ms_username;
	size_t _len_username = __in_ms.ms_username_len ;
	char* _in_username = NULL;
	const char* _tmp_password = __in_ms.ms_password;
	size_t _len_password = __in_ms.ms_password_len ;
	char* _in_password = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_service, _len_service);
	CHECK_UNIQUE_POINTER(_tmp_username, _len_username);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_service != NULL && _len_service != 0) {
		_in_service = (char*)malloc(_len_service);
		if (_in_service == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_service, _len_service, _tmp_service, _len_service)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_service[_len_service - 1] = '\0';
		if (_len_service != strlen(_in_service) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_username != NULL && _len_username != 0) {
		_in_username = (char*)malloc(_len_username);
		if (_in_username == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_username, _len_username, _tmp_username, _len_username)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_username[_len_username - 1] = '\0';
		if (_len_username != strlen(_in_username) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_password != NULL && _len_password != 0) {
		_in_password = (char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_password, _len_password, _tmp_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_password[_len_password - 1] = '\0';
		if (_len_password != strlen(_in_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_vault_update((const char*)_in_service, (const char*)_in_username, (const char*)_in_password);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_service) free(_in_service);
	if (_in_username) free(_in_username);
	if (_in_password) free(_in_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_vault_delete(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vault_delete_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vault_delete_t* ms = SGX_CAST(ms_ecall_vault_delete_t*, pms);
	ms_ecall_vault_delete_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_vault_delete_t), ms, sizeof(ms_ecall_vault_delete_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_service = __in_ms.ms_service;
	size_t _len_service = __in_ms.ms_service_len ;
	char* _in_service = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_service, _len_service);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_service != NULL && _len_service != 0) {
		_in_service = (char*)malloc(_len_service);
		if (_in_service == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_service, _len_service, _tmp_service, _len_service)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_service[_len_service - 1] = '\0';
		if (_len_service != strlen(_in_service) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = ecall_vault_delete((const char*)_in_service);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_service) free(_in_service);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_vault_list(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vault_list_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vault_list_t* ms = SGX_CAST(ms_ecall_vault_list_t*, pms);
	ms_ecall_vault_list_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_vault_list_t), ms, sizeof(ms_ecall_vault_list_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_output = __in_ms.ms_output;
	size_t _tmp_output_capacity = __in_ms.ms_output_capacity;
	size_t _len_output = _tmp_output_capacity;
	char* _in_output = NULL;
	size_t* _tmp_required_size = __in_ms.ms_required_size;
	size_t _len_required_size = sizeof(size_t);
	size_t* _in_required_size = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_output, _len_output);
	CHECK_UNIQUE_POINTER(_tmp_required_size, _len_required_size);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_output != NULL && _len_output != 0) {
		if ( _len_output % sizeof(*_tmp_output) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_output = (char*)malloc(_len_output)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_output, 0, _len_output);
	}
	if (_tmp_required_size != NULL && _len_required_size != 0) {
		if ( _len_required_size % sizeof(*_tmp_required_size) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_required_size = (size_t*)malloc(_len_required_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_required_size, 0, _len_required_size);
	}
	_in_retval = ecall_vault_list(_in_output, _tmp_output_capacity, _in_required_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_output) {
		if (memcpy_verw_s(_tmp_output, _len_output, _in_output, _len_output)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_required_size) {
		if (memcpy_verw_s(_tmp_required_size, _len_required_size, _in_required_size, _len_required_size)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_output) free(_in_output);
	if (_in_required_size) free(_in_required_size);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_vault_get_versions(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vault_get_versions_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vault_get_versions_t* ms = SGX_CAST(ms_ecall_vault_get_versions_t*, pms);
	ms_ecall_vault_get_versions_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_vault_get_versions_t), ms, sizeof(ms_ecall_vault_get_versions_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint32_t* _tmp_format_version = __in_ms.ms_format_version;
	size_t _len_format_version = sizeof(uint32_t);
	uint32_t* _in_format_version = NULL;
	uint64_t* _tmp_state_version = __in_ms.ms_state_version;
	size_t _len_state_version = sizeof(uint64_t);
	uint64_t* _in_state_version = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_format_version, _len_format_version);
	CHECK_UNIQUE_POINTER(_tmp_state_version, _len_state_version);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_format_version != NULL && _len_format_version != 0) {
		if ( _len_format_version % sizeof(*_tmp_format_version) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_format_version = (uint32_t*)malloc(_len_format_version)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_format_version, 0, _len_format_version);
	}
	if (_tmp_state_version != NULL && _len_state_version != 0) {
		if ( _len_state_version % sizeof(*_tmp_state_version) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_state_version = (uint64_t*)malloc(_len_state_version)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_state_version, 0, _len_state_version);
	}
	_in_retval = ecall_vault_get_versions(_in_format_version, _in_state_version);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_format_version) {
		if (memcpy_verw_s(_tmp_format_version, _len_format_version, _in_format_version, _len_format_version)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_state_version) {
		if (memcpy_verw_s(_tmp_state_version, _len_state_version, _in_state_version, _len_state_version)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_format_version) free(_in_format_version);
	if (_in_state_version) free(_in_state_version);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_vault_sealed_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vault_sealed_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vault_sealed_size_t* ms = SGX_CAST(ms_ecall_vault_sealed_size_t*, pms);
	ms_ecall_vault_sealed_size_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_vault_sealed_size_t), ms, sizeof(ms_ecall_vault_sealed_size_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint32_t* _tmp_sealed_size = __in_ms.ms_sealed_size;
	size_t _len_sealed_size = sizeof(uint32_t);
	uint32_t* _in_sealed_size = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sealed_size, _len_sealed_size);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_size != NULL && _len_sealed_size != 0) {
		if ( _len_sealed_size % sizeof(*_tmp_sealed_size) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_size = (uint32_t*)malloc(_len_sealed_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_size, 0, _len_sealed_size);
	}
	_in_retval = ecall_vault_sealed_size(_in_sealed_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_sealed_size) {
		if (memcpy_verw_s(_tmp_sealed_size, _len_sealed_size, _in_sealed_size, _len_sealed_size)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_size) free(_in_sealed_size);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_vault_seal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vault_seal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vault_seal_t* ms = SGX_CAST(ms_ecall_vault_seal_t*, pms);
	ms_ecall_vault_seal_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_vault_seal_t), ms, sizeof(ms_ecall_vault_seal_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed = __in_ms.ms_sealed;
	uint32_t _tmp_sealed_capacity = __in_ms.ms_sealed_capacity;
	size_t _len_sealed = _tmp_sealed_capacity;
	uint8_t* _in_sealed = NULL;
	uint32_t* _tmp_actual_size = __in_ms.ms_actual_size;
	size_t _len_actual_size = sizeof(uint32_t);
	uint32_t* _in_actual_size = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sealed, _len_sealed);
	CHECK_UNIQUE_POINTER(_tmp_actual_size, _len_actual_size);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed != NULL && _len_sealed != 0) {
		if ( _len_sealed % sizeof(*_tmp_sealed) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed = (uint8_t*)malloc(_len_sealed)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed, 0, _len_sealed);
	}
	if (_tmp_actual_size != NULL && _len_actual_size != 0) {
		if ( _len_actual_size % sizeof(*_tmp_actual_size) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_actual_size = (uint32_t*)malloc(_len_actual_size)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_actual_size, 0, _len_actual_size);
	}
	_in_retval = ecall_vault_seal(_in_sealed, _tmp_sealed_capacity, _in_actual_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_sealed) {
		if (memcpy_verw_s(_tmp_sealed, _len_sealed, _in_sealed, _len_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_actual_size) {
		if (memcpy_verw_s(_tmp_actual_size, _len_actual_size, _in_actual_size, _len_actual_size)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed) free(_in_sealed);
	if (_in_actual_size) free(_in_actual_size);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_vault_unseal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_vault_unseal_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_vault_unseal_t* ms = SGX_CAST(ms_ecall_vault_unseal_t*, pms);
	ms_ecall_vault_unseal_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_vault_unseal_t), ms, sizeof(ms_ecall_vault_unseal_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_sealed = __in_ms.ms_sealed;
	uint32_t _tmp_sealed_size = __in_ms.ms_sealed_size;
	size_t _len_sealed = _tmp_sealed_size;
	uint8_t* _in_sealed = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_sealed, _len_sealed);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed != NULL && _len_sealed != 0) {
		if ( _len_sealed % sizeof(*_tmp_sealed) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealed = (uint8_t*)malloc(_len_sealed);
		if (_in_sealed == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed, _len_sealed, _tmp_sealed, _len_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	_in_retval = ecall_vault_unseal((const uint8_t*)_in_sealed, _tmp_sealed_size);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_sealed) free(_in_sealed);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[12];
} g_ecall_table = {
	12,
	{
		{(void*)(uintptr_t)sgx_ecall_vault_create, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_vault_clear, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_vault_login, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_vault_add, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_vault_get, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_vault_update, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_vault_delete, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_vault_list, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_vault_get_versions, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_vault_sealed_size, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_vault_seal, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_vault_unseal, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[6][12];
} g_dyn_entry_table = {
	6,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

