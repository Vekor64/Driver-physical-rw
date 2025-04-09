#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include <cstdint>

typedef enum _request_codes
{
	init_driver = 0x358,
	get_base = 0x359,
	read_memory = 0x355,
	write_memory = 0x325,
	alloc_memory = 0x323,
	copy_memory = 0x324,
	protect_memory = 0x322,
	call_entry = 0x320,
	free_memory = 0x321,
	request_success = 0x22c,
	request_unique = 0x92b,
	request_unload = 0x93b,
	protect_process = 0x94b,
}request_codes, * prequest_codes;

typedef struct _unload_request
{
	bool buffer;
}unload_request, * punload_request;

typedef struct _read_request {
	HANDLE pid;
	PVOID address;
	PVOID buffer;
	SIZE_T size;
} read_request, * pread_request;

struct process_request_t
{
	ULONG process_id;
};


typedef struct _write_request {
	HANDLE pid;
	PVOID address;
	PVOID buffer;
	SIZE_T size;
} write_request, * pwrite_request;

typedef struct _base_request {
	HANDLE pid;
	HANDLE handle;
	CHAR name[100];
} base_request, * pbase_request;

typedef struct _driver_init {
	bool init;
} driver_init, * pdriver_init;

typedef struct _swap_request
{
	ULONG pid;
	PVOID dst;
	PVOID src;
	PVOID old;
}swap_request, * pswap_request;

typedef struct _free_request
{
	HANDLE targetPid;
	PVOID address;
	SIZE_T code;
}free_request, * pfree_request;

typedef struct _call_entry_request
{
	HANDLE process_id;
	PVOID address;
	PVOID shellcode;

	BOOLEAN result;
} call_entry_request, * pcall_entry_request;

typedef struct _allocate_request
{
	HANDLE targetPid;
	ULONG allocationType, protect;
	PVOID sourceAddress;
	PVOID targetAddress;
	SIZE_T size;
	SIZE_T code;

}allocate_request, * pallocate_request;

typedef struct _copy_request
{
	HANDLE targetPid;
	PVOID targetAddress;
	HANDLE sourcePid;
	PVOID sourceAddress;
	SIZE_T size;

} copy_request, * pcopy_request;


typedef struct _protect_request
{
	HANDLE targetPid;
	ULONG protect;
	uintptr_t sourceAddress;
	size_t size;
	size_t code;
}protect_request, * pprotect_request;

typedef struct _expose_request
{
	void* address;
	size_t size;
	uint32_t pid;
}expose_request, * pexpose_request;

typedef struct _pattern_request
{
	int pid;
	uintptr_t base;
	char signature[260];
	uintptr_t address;
}pattern_request, * ppattern_request;

typedef struct _request_data
{
	uint32_t unique;
	request_codes code;
	void* data;
}request_data, * prequest_data;