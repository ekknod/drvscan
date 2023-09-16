#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
#include <stdlib.h>
#include <TlHelp32.h>
#include <intrin.h>

#define INTEL 2
#define SUBGETVARIABLE 3
#define ACTIVE_DRIVER INTEL


#define IOCTL_INTEL 0x80862007
#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))

#define MIN_DIFFERENCE 9
#define POOLTAG (DWORD)'ECAC'
#define LOG(...) printf("[ecac.exe] "  __VA_ARGS__)
#define LOG_RED(...) \
printf("[ecac.exe] "); \
FontColor(4); \
printf(__VA_ARGS__); \
FontColor(7); \

typedef ULONG_PTR QWORD;
std::vector<QWORD> global_export_list;

class DLL_EXPORT
{
	QWORD address;
public:
	DLL_EXPORT(QWORD address) : address(address)
	{
		global_export_list.push_back((QWORD)&this->address);
	}
	operator QWORD () const { return address; }

};

//
// NTOSKRNL_EXPORT define variables are automatically resolved in km::initialize
//
#define NTOSKRNL_EXPORT(export_name) \
DLL_EXPORT export_name((QWORD)#export_name);

NTOSKRNL_EXPORT(MmUnlockPreChargedPagedPool);
NTOSKRNL_EXPORT(IofCompleteRequest);
NTOSKRNL_EXPORT(MmCopyMemory);
NTOSKRNL_EXPORT(PsLookupProcessByProcessId);
NTOSKRNL_EXPORT(ExAllocatePool2);
NTOSKRNL_EXPORT(ExFreePool);
NTOSKRNL_EXPORT(MmCopyVirtualMemory);
NTOSKRNL_EXPORT(PsGetThreadId);
NTOSKRNL_EXPORT(PsGetThreadProcess);
NTOSKRNL_EXPORT(PsGetProcessId);
NTOSKRNL_EXPORT(MmMapIoSpace);
NTOSKRNL_EXPORT(MmUnmapIoSpace);
NTOSKRNL_EXPORT(PsLookupThreadByThreadId);
NTOSKRNL_EXPORT(KeNumberProcessors);
NTOSKRNL_EXPORT(KeQueryPrcbAddress);
NTOSKRNL_EXPORT(PsGetCurrentThread);
NTOSKRNL_EXPORT(PsGetProcessWow64Process);
NTOSKRNL_EXPORT(PsGetProcessPeb);
NTOSKRNL_EXPORT(HalEnumerateEnvironmentVariablesEx);
NTOSKRNL_EXPORT(MmGetPhysicalAddress);
NTOSKRNL_EXPORT(MmGetVirtualForPhysical);
NTOSKRNL_EXPORT(KeStackAttachProcess);
NTOSKRNL_EXPORT(KeUnstackDetachProcess);
NTOSKRNL_EXPORT(MmIsAddressValid);

namespace kernel
{
	NTOSKRNL_EXPORT(memcpy);
}

QWORD ntoskrnl_base;

#pragma pack(1)
typedef struct {
	std::string             path;
	std::string             name;
	QWORD                   base;
	QWORD                   size;
} FILE_INFO ;

#pragma pack(1)
typedef struct {
	DWORD                  process_id;
	std::vector<FILE_INFO> process_modules;
} PROCESS_INFO;

#pragma pack(1)
typedef struct {
	QWORD                  address;
	QWORD                  length;
	DWORD                  tag;
} BIGPOOL_INFO;

#pragma pack(1)
typedef struct {
	DWORD                  pid;
	BYTE                   object_type;
	BYTE                   flags;
	QWORD                  handle;
	QWORD                  object;
	ACCESS_MASK            access_mask;
} HANDLE_INFO;

#pragma pack(1)
typedef struct {
	QWORD                  virtual_address;
	QWORD                  physical_address;
	DWORD                  page_count;
} EFI_PAGE_INFO;

#pragma pack(1)
typedef struct {
	QWORD                  virtual_address;
	QWORD                  physical_address;
	DWORD                  size;
} EFI_MODULE_INFO;

std::vector<FILE_INFO>       get_kernel_modules(void);
std::vector<FILE_INFO>       get_user_modules(DWORD pid);
std::vector<PROCESS_INFO>    get_system_processes();
std::vector<BIGPOOL_INFO>    get_kernel_allocations(void);
std::vector<HANDLE_INFO>     get_system_handle_information(void);
std::vector<EFI_PAGE_INFO>   get_efi_runtime_pages(void);
std::vector<EFI_MODULE_INFO> get_efi_module_list(void);

QWORD get_kernel_export(QWORD base, PCSTR driver_name, PCSTR export_name)
{
	HMODULE ntos = LoadLibraryA(driver_name);

	if (ntos == 0)
	{
		return 0;
	}

	QWORD export_address = (QWORD)GetProcAddress(ntos, export_name);
	if (export_address == 0)
	{
		goto cleanup;
	}

	export_address = export_address - (QWORD)ntos;
	export_address = export_address + base;

cleanup:
	FreeLibrary(ntos);
	return export_address;
}

QWORD get_function_size(QWORD function_address)
{
	QWORD begin = function_address;
	while (1)
	{
		if (*(WORD*)(function_address) == 0xCCC3)
		{
			break;
		}
		function_address++;
	}
	return (function_address - begin) + 1;
}

#if ACTIVE_DRIVER == INTEL

namespace km
{
	HANDLE driver_handle = 0;
	
	BOOL port_read(WORD address, PVOID buffer, QWORD length)
	{
		if (driver_handle == 0)
		{
			return 0;
		}

		typedef struct _PAYLOAD
		{
			QWORD case_number;
			QWORD reserved;
			QWORD return_value;
			QWORD address;
		} PAYLOAD, * PPAYLOAD;

		PAYLOAD io{};

		if (length == 1)
		{
			io.case_number = 1;
		} else if (length == 2)
		{
			io.case_number = 2;
		} else if (length == 4)
		{
			io.case_number = 3;
		} else {
			return 0;
		}

		io.address = address;

		DWORD returned = 0;
		if (!DeviceIoControl(driver_handle, IOCTL_INTEL, &io, sizeof(io), 0, 0, &returned, 0))
		{
			return 0;
		}

		memcpy(buffer, (const void*)&io.return_value, length);

		return 1;
	}

	BOOL port_write(WORD address, PVOID buffer, QWORD length)
	{
		if (driver_handle == 0)
		{
			return 0;
		}

		typedef struct _PAYLOAD
		{
			QWORD case_number;
			QWORD reserved;
			QWORD return_value;
			QWORD address;
			QWORD buffer;
		} PAYLOAD, * PPAYLOAD;

		PAYLOAD io{};

		if (length == 1)
		{
			io.case_number = 0x07;
			io.buffer = *(BYTE*)buffer;
		} else if (length == 2)
		{
			io.case_number = 0x08;
			io.buffer = *(WORD*)buffer;
		} else if (length == 4)
		{
			io.case_number = 0x09;
			io.buffer = *(DWORD*)buffer;
		} else {
			return 0;
		}

		io.address = address;

		DWORD returned = 0;
		if (!DeviceIoControl(driver_handle, IOCTL_INTEL, &io, sizeof(io), 0, 0, &returned, 0))
		{
			return 0;
		}

		return (io.return_value) == 1;
	}

	QWORD call(QWORD kernel_address, QWORD r1 = 0, QWORD r2 = 0, QWORD r3 = 0, QWORD r4 = 0, QWORD r5 = 0, QWORD r6 = 0, QWORD r7 = 0)
	{
		if (driver_handle == 0)
		{
			return 0;
		}

		typedef struct _PAYLOAD
		{
			QWORD case_number;
			QWORD res; 
			QWORD R0;
			QWORD R1;
			QWORD R2;
			QWORD R3;
			QWORD R4;
			QWORD R5;
			QWORD R6;
			QWORD R7;		
		} PAYLOAD, * PPAYLOAD;
		
		PAYLOAD io{};
		io.case_number = 0x1C;	
		io.R0 = kernel_address;
		io.R1 = r1;
		io.R2 = r2;
		io.R3 = r3;
		io.R4 = r4;
		io.R5 = r5;
		io.R6 = r6;
		io.R7 = r7;

		DWORD returned = 0;
		if (!DeviceIoControl(driver_handle, IOCTL_INTEL, &io, sizeof(io), 0, 0, &returned, 0))
		{
			return 0;
		}

		return io.R0;
	}

	template <typename T>
	T call(QWORD kernel_address, QWORD r1 = 0, QWORD r2 = 0, QWORD r3 = 0, QWORD r4 = 0, QWORD r5 = 0, QWORD r6 = 0, QWORD r7 = 0)
	{
		QWORD ret = call(kernel_address, r1, r2, r3, r4, r5, r6, r7);
		return *(T*)&ret;
	}

	QWORD allocate_memory(QWORD size)
	{
		return call(ExAllocatePool2, 0x0000000000000080UI64, PAGE_SIZE + size, POOLTAG);
	}

	void free_memory(QWORD address)
	{
		call(ExFreePool, address, POOLTAG, 0, 0);
	}

	QWORD install_function(PVOID shellcode)
	{
		QWORD size = get_function_size((QWORD)shellcode);
		QWORD mem  = allocate_memory(size);
		if (mem == 0)
		{
			return 0;
		}
		call(kernel::memcpy, mem, (QWORD)shellcode, size );
		return mem;
	}

	void uninstall_function(QWORD shellcode_function)
	{
		free_memory(shellcode_function);
	}

	QWORD call_shellcode(PVOID shellcode, QWORD r1 = 0, QWORD r2 = 0, QWORD r3 = 0, QWORD r4 = 0, QWORD r5 = 0, QWORD r6 = 0, QWORD r7 = 0)
	{
		QWORD func = install_function(shellcode);
		if (func == 0)
		{
			return 0;
		}
		QWORD ret = call(func, r1, r2, r3, r4, r5, r6, r7);
		uninstall_function(func);
		return ret;
	}

	BOOL initialize(void)
	{
		if (driver_handle != 0)
		{
			return 1;
		}

		QWORD target_driver = 0;

		for (auto &drv : get_kernel_modules())
		{
			if (!_strcmpi(drv.name.c_str(), "iqww64e.sys"))
			{
				target_driver = drv.base;
				break;
			}
		}

		if (target_driver == 0)
		{
			LOG("driver iqww64e.sys is not loaded\n");
			return 0;
		}

		driver_handle = CreateFileA("\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		if (driver_handle == INVALID_HANDLE_VALUE)
		{
			LOG("intel driver is not running\n");
			driver_handle = 0;
			return 0;
		}


		//
		// IOCTL:  0x1C
		//
		unsigned char payload[] = {
			0x48, 0x83, 0xEC, 0x58,                      // sub    rsp,0x58
			0x4C, 0x8B, 0x57, 0x10,                      // mov    r10,QWORD PTR [rdi+0x10]
			0x48, 0x8B, 0x47, 0x48,                      // mov    rax,QWORD PTR [rdi+0x48]
			0x48, 0x89, 0x44, 0x24, 0x30,                // mov    QWORD PTR [rsp+0x30],rax
			0x48, 0x8B, 0x47, 0x40,                      // mov    rax,QWORD PTR [rdi+0x40]
			0x48, 0x89, 0x44, 0x24, 0x28,                // mov    QWORD PTR [rsp+0x28],rax
			0x48, 0x8B, 0x47, 0x38,                      // mov    rax,QWORD PTR [rdi+0x38]
			0x48, 0x89, 0x44, 0x24, 0x20,                // mov    QWORD PTR [rsp+0x20],rax
			0x4C, 0x8B, 0x4F, 0x30,                      // mov    r9,QWORD PTR [rdi+0x30]
			0x4C, 0x8B, 0x47, 0x28,                      // mov    r8,QWORD PTR [rdi+0x28]
			0x48, 0x8B, 0x57, 0x20,                      // mov    rdx,QWORD PTR [rdi+0x20]
			0x48, 0x8B, 0x4F, 0x18,                      // mov    rcx,QWORD PTR [rdi+0x18]
			0x41, 0xFF, 0xD2,                            // call   r10
			0x48, 0x89, 0x44, 0x24, 0x40,                // mov    QWORD PTR [rsp+0x40],rax
			0x48, 0x83, 0xC4, 0x58,                      // add    rsp,0x58
			0xC3                                         // ret
		};

		target_driver = target_driver + 0x2450;
		for (int i = 0; i < sizeof(payload); i++)
		{
			typedef struct { QWORD a0,a1,a2,a3; } I0; I0 i0{0x25,0,0,target_driver + i};
			DeviceIoControl(driver_handle, IOCTL_INTEL, &i0, sizeof(i0), 0, 0, 0, 0);

			typedef struct { QWORD a0,a1,a2,a3,a4,a5; } I1; I1 i1{0x19,0,0,0,i0.a2,1};
			DeviceIoControl(driver_handle, IOCTL_INTEL, &i1, sizeof(i1), 0, 0, 0, 0);

			typedef struct { QWORD a0,a1,a2,a3,a4; } I2; I2 i2{0x33,0,(QWORD)&payload[i],i1.a3,1};
			DeviceIoControl(driver_handle, IOCTL_INTEL, &i2, sizeof(i2), 0, 0, 0, 0);

			typedef struct { QWORD a0, a1,a2, a3, a4, a5; } I3 ; I3 i3{0x1A, 0,0, i1.a3, 0, 1};
			DeviceIoControl(driver_handle, IOCTL_INTEL, &i3, sizeof(i3), 0, 0, 0, 0);
		}

		unsigned char integrity_check[sizeof(payload)]{};
		typedef struct { QWORD a0,a1,a2,a3,a4; } PX; PX px{0x33,0,target_driver,(QWORD)integrity_check,sizeof(integrity_check)};
		DeviceIoControl(driver_handle, IOCTL_INTEL, &px, sizeof(px), 0, 0, 0, 0);

		for (int i = 0; i < sizeof(integrity_check); i++)
		{
			if (integrity_check[i] != payload[i])
			{
				LOG("driver integrity check failed\n");
				CloseHandle(driver_handle);
				driver_handle = 0;
				return 0;
			}
		}

		//
		// uninstall old shellcodes to avoid memory leaks
		//
		for (auto &pool : get_kernel_allocations())
		{
			if (pool.tag == POOLTAG)
			{
				uninstall_function(pool.address);
			}
		}

		return driver_handle != 0;
	}

	namespace vm
	{
		BOOL read(DWORD pid, QWORD address, PVOID buffer, QWORD length)
		{
			BOOL ret = 0;

			if (!km::initialize())
			{
				return ret;
			}

			if (pid == 4)
			{
				QWORD alloc_buffer = (QWORD)allocate_memory(length);

				if (alloc_buffer == 0)
					return 0;

				QWORD res = 0;
				QWORD status = call(MmCopyMemory, (QWORD)alloc_buffer, address, length, 0x02, (QWORD)&res);
				if (status == 0)
				{
					call(kernel::memcpy, (QWORD)buffer, alloc_buffer, res );
					ret = 1;
				}
				free_memory(alloc_buffer);
			}
			else if (pid == 0)
			{
				ret = km::call(kernel::memcpy, (QWORD)buffer, address, length) != 0;
			} else {
				QWORD target_process = 0, current_process = 0;
				if (call(PsLookupProcessByProcessId, pid, (QWORD)&target_process) != 0)
				{
					return 0;
				}
				if (call(PsLookupProcessByProcessId, GetCurrentProcessId(), (QWORD)&current_process) != 0)
				{
					return 0;
				}		
				ret = call(MmCopyVirtualMemory, target_process, address, current_process, (QWORD)buffer, length, 0, (QWORD)&length) == 0;
			}
			return ret;
		}

		template <typename t>
		t read(DWORD pid, QWORD address)
		{
			t b;
			if (!read(pid, address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}

		QWORD read_i64(DWORD pid, QWORD address)
		{
			QWORD b;
			if (!read(pid, address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}

		DWORD read_i32(DWORD pid, QWORD address)
		{
			DWORD b;
			if (!read(pid, address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}

		QWORD get_relative_address(DWORD pid, QWORD instruction, DWORD offset, DWORD instruction_size)
		{
			INT32 rip_address = read_i32(pid, instruction + offset);
			return (QWORD)(instruction + instruction_size + rip_address);
		}
	}
	
	namespace pm
	{
		BOOL read(QWORD address, PVOID buffer, QWORD length)
		{	
			BOOL ret = 0;
			QWORD alloc_buffer = (QWORD)allocate_memory(length);

			if (alloc_buffer == 0)
				return ret;

			QWORD res = 0;
			QWORD status = call(MmCopyMemory, (QWORD)alloc_buffer, address, length, 0x01, (QWORD)&res);
			if (status == 0)
			{
				call(kernel::memcpy, (QWORD)buffer, alloc_buffer, res );
				ret = 1;
			}
			free_memory(alloc_buffer);
			return ret;
		}

		template <typename t>
		t read(ULONG_PTR address)
		{
			t b;
			if (!read(address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}
	}

	namespace io
	{
		BOOL read(QWORD address, PVOID buffer, QWORD length)
		{
			if (!km::initialize())
			{
				return 0;
			}
			QWORD alloc = call(MmMapIoSpace, address, length);
			if (alloc)
			{
				call(kernel::memcpy, (QWORD)buffer, alloc, length);
				call(MmUnmapIoSpace, alloc, length);
				return 1;
			}
			return 0;
		}

		BOOL write(QWORD address, PVOID buffer, QWORD length)
		{
			if (!km::initialize())
			{
				return 0;
			}
			QWORD alloc = call(MmMapIoSpace, address, length);
			if (alloc)
			{
				call(kernel::memcpy, alloc, (QWORD)buffer, length);
				call(MmUnmapIoSpace, alloc, length);
				return 1;
			}
			return 0;
		}

		template <typename t>
		t read(QWORD address)
		{
			t b;
			if (!read(address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}
		template <typename t>
		BOOL write(QWORD address, t value)
		{
			return km::io::write(address, &value, sizeof(t));
		}
	}

	namespace pci
	{
		WORD read_i16_legacy(BYTE bus, BYTE slot, BYTE func, BYTE offset)
		{
			DWORD address = 0x80000000 | bus << 16 | slot << 11 | func <<  8 | offset;
			port_write(0xCF8, &address, 4);
			port_read(0xCFC, &address, 4);
			return (address >> ((offset & 2) * 8)) & 0xFFFF;
		}

		void write_i16_legacy(BYTE bus, BYTE slot, BYTE func, BYTE offset, WORD value)
		{
			DWORD address = 0x80000000 | bus << 16 | slot << 11 | func <<  8 | offset;
			port_write(0xCF8, &address, 4);
			port_write(0xCFC, &value, 2);
		}
	}
}

#elif ACTIVE_DRIVER == SUBGETVARIABLE

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

extern "C" VOID NTAPI RtlInitUnicodeString (PUNICODE_STRING, PCWSTR);
extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
extern "C" NTSTATUS NTAPI NtQuerySystemEnvironmentValueEx(PUNICODE_STRING, LPGUID, PVOID, PULONG, PULONG);

namespace km
{
	QWORD call(QWORD kernel_address, QWORD r1 = 0, QWORD r2 = 0, QWORD r3 = 0, QWORD r4 = 0, QWORD r5 = 0, QWORD r6 = 0, QWORD r7 = 0)
	{
		#pragma pack(push,1)
		typedef struct {
			QWORD param_1;
			QWORD param_2;
			QWORD param_3;
			QWORD param_4;
			QWORD param_5;
			QWORD param_6;
			QWORD param_7;
		} PAYLOAD ;
		#pragma pack(pop)

		PAYLOAD parameters;
		parameters.param_1 = r1;
		parameters.param_2 = r2;
		parameters.param_3 = r3;
		parameters.param_4 = r4;
		parameters.param_5 = r5;
		parameters.param_6 = r6;
		parameters.param_7 = r7;

		QWORD peb = __readgsqword(0x60);
		peb = *(QWORD*)(peb + 0x18);
		peb = *(QWORD*)(peb + 0x20);

		*(QWORD*)(peb + 0x18) = kernel_address;
		*(QWORD*)(peb + 0x10) = (QWORD)&parameters;

		UNICODE_STRING string;
		RtlInitUnicodeString(&string, L"SecureBoot");

		ULONG ret = 0;
		ULONG ret_len = 1;
		ULONG attributes = 0;

		GUID gEfiGlobalVariableGuid         = { 0x8BE4DF61, 0x93CA, 0x11D2, { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C }};
		NTSTATUS status = NtQuerySystemEnvironmentValueEx(&string,
							&gEfiGlobalVariableGuid,
							&ret,
							&ret_len,
							&attributes);

		QWORD result = *(QWORD*)(peb + 0x18);
		*(QWORD*)(peb + 0x18) = 0;
		*(QWORD*)(peb + 0x10) = 0;

		if (status == 0)
			return 0;

		return result;
	}

	QWORD allocate_memory(QWORD size)
	{
		return call(ExAllocatePool2, 0x0000000000000080UI64, PAGE_SIZE + size, POOLTAG);
	}

	void free_memory(QWORD address)
	{
		call(ExFreePool, address, POOLTAG, 0, 0);
	}

	QWORD install_function(PVOID shellcode)
	{
		QWORD size = get_function_size((QWORD)shellcode);
		QWORD mem  = allocate_memory(size);
		if (mem == 0)
		{
			return 0;
		}
		call(kernel::memcpy, mem, (QWORD)shellcode, size );
		return mem;
	}

	void uninstall_function(QWORD shellcode_function)
	{
		free_memory(shellcode_function);
	}

	QWORD call_shellcode(PVOID shellcode, QWORD r1 = 0, QWORD r2 = 0, QWORD r3 = 0, QWORD r4 = 0, QWORD r5 = 0, QWORD r6 = 0, QWORD r7 = 0)
	{
		QWORD func = install_function(shellcode);
		if (func == 0)
		{
			return 0;
		}
		QWORD ret = call(func, r1, r2, r3, r4, r5, r6, r7);
		uninstall_function(func);
		return ret;
	}

	BOOL initialize(void)
	{
		static BOOL done = 0;

		if (done)
			return 1;

		BOOLEAN privs=1;
		if (RtlAdjustPrivilege(22, 1, 0, &privs) != 0l)
		{
			LOG("run as admin\n");
			return 0;
		}

		//
		// uninstall old shellcodes to avoid memory leaks
		//
		for (auto &pool : get_kernel_allocations())
		{
			if (pool.tag == POOLTAG)
			{
				uninstall_function(pool.address);
			}
		}

		done = 1;

		return 1;
	}

	namespace vm
	{
		BOOL read(DWORD pid, QWORD address, PVOID buffer, QWORD length)
		{
			BOOL ret = 0;

			if (!km::initialize())
			{
				return ret;
			}

			if (pid == 4)
			{
				
				QWORD alloc_buffer = (QWORD)allocate_memory(length);

				if (alloc_buffer == 0)
					return 0;

				QWORD res = 0;
				QWORD status = call(MmCopyMemory, (QWORD)alloc_buffer, address, length, 0x02, (QWORD)&res);
				if (status == 0)
				{
					call(kernel::memcpy, (QWORD)buffer, alloc_buffer, res );
					ret = 1;
				}
				free_memory(alloc_buffer);
			}
			else if (pid == 0)
			{
				ret = km::call(kernel::memcpy, (QWORD)buffer, address, length) != 0;
			} else {
				QWORD target_process = 0, current_process = 0;
				if (call(PsLookupProcessByProcessId, pid, (QWORD)&target_process) != 0)
				{
					return 0;
				}
				if (call(PsLookupProcessByProcessId, GetCurrentProcessId(), (QWORD)&current_process) != 0)
				{
					return 0;
				}		
				ret = call(MmCopyVirtualMemory, target_process, address, current_process, (QWORD)buffer, length, 0, (QWORD)&length) == 0;
			}
			return ret;
		}

		template <typename t>
		t read(DWORD pid, QWORD address)
		{
			t b;
			if (!read(pid, address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}

		QWORD read_i64(DWORD pid, QWORD address)
		{
			QWORD b;
			if (!read(pid, address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}

		DWORD read_i32(DWORD pid, QWORD address)
		{
			DWORD b;
			if (!read(pid, address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}

		QWORD get_relative_address(DWORD pid, QWORD instruction, DWORD offset, DWORD instruction_size)
		{
			INT32 rip_address = read_i32(pid, instruction + offset);
			return (QWORD)(instruction + instruction_size + rip_address);
		}
	}
	
	namespace pm
	{
		BOOL read(QWORD address, PVOID buffer, QWORD length)
		{	
			BOOL ret = 0;
			QWORD alloc_buffer = (QWORD)allocate_memory(length);

			if (alloc_buffer == 0)
				return ret;

			QWORD res = 0;
			QWORD status = call(MmCopyMemory, (QWORD)alloc_buffer, address, length, 0x01, (QWORD)&res);
			if (status == 0)
			{
				call(kernel::memcpy, (QWORD)buffer, alloc_buffer, res );
				ret = 1;
			}
			free_memory(alloc_buffer);
			return ret;
		}

		template <typename t>
		t read(ULONG_PTR address)
		{
			t b;
			if (!read(address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}
	}

	namespace io
	{
		BOOL read(QWORD address, PVOID buffer, QWORD length)
		{
			if (!km::initialize())
			{
				return 0;
			}
			QWORD alloc = call(MmMapIoSpace, address, length);
			if (alloc)
			{
				call(kernel::memcpy, (QWORD)buffer, alloc, length);
				call(MmUnmapIoSpace, alloc, length);
				return 1;
			}
			return 0;
		}

		BOOL write(QWORD address, PVOID buffer, QWORD length)
		{
			if (!km::initialize())
			{
				return 0;
			}
			QWORD alloc = call(MmMapIoSpace, address, length);
			if (alloc)
			{
				call(kernel::memcpy, alloc, (QWORD)buffer, length);
				call(MmUnmapIoSpace, alloc, length);
				return 1;
			}
			return 0;
		}

		template <typename t>
		t read(QWORD address)
		{
			t b;
			if (!read(address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}
		template <typename t>
		BOOL write(QWORD address, t value)
		{
			return km::io::write(address, &value, sizeof(t));
		}
	}

	namespace pci
	{
		WORD read_i16_legacy(BYTE bus, BYTE slot, BYTE func, BYTE offset)
		{
			// DWORD address = 0x80000000 | bus << 16 | slot << 11 | func <<  8 | offset;
			// port_write(0xCF8, &address, 4);
			// port_read(0xCFC, &address, 4);
			// return (address >> ((offset & 2) * 8)) & 0xFFFF;
			return 0;
		}

		void write_i16_legacy(BYTE bus, BYTE slot, BYTE func, BYTE offset, WORD value)
		{
			// DWORD address = 0x80000000 | bus << 16 | slot << 11 | func <<  8 | offset;
			// port_write(0xCF8, &address, 4);
			// port_write(0xCFC, &value, 2);
		}
	}
}
#endif

void FontColor(int color=0x07)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

BOOLEAN IsAddressEqual(QWORD address0, QWORD address2, INT64 cnt)
{
	INT64 res = abs(  (INT64)(address2 - address0)  );
	return res <= cnt;
}

void scan_section(DWORD diff, CHAR *section_name, QWORD local_image, QWORD runtime_image, QWORD size, QWORD section_address, std::vector<DWORD> &wla)
{
	for (QWORD i = 0; i < size; i++)
	{
		if (((unsigned char*)local_image)[i] == ((unsigned char*)runtime_image)[i])
		{
			continue;
		}

		DWORD cnt = 0;
		while (1)
		{

			if (i + cnt >= size)
			{
				break;
			}

			if (((unsigned char*)local_image)[i + cnt] == ((unsigned char*)runtime_image)[i + cnt])
			{
				break;
			}

			cnt++;
		}

		if (cnt >= diff)
		{
			BOOL found = 0;
			 
			//
			// check if it was allowed change from our earlier clean dump
			//
			for (auto wl : wla)
			{
				if (IsAddressEqual(wl, (section_address + i), 8))
				{
					found = 1;
					break;
				}
			}
			if (found == 0)
			{
				printf("%s:0x%llx is modified (%ld bytes): ", section_name, section_address + i, cnt);
				FontColor(2);
				for (DWORD j = 0; j < cnt; j++)
				{
					printf("%02X ", ((unsigned char*)local_image)[i + j]);
				}
				FontColor(7);
				printf("-> ");

				FontColor(4);
				for (DWORD j = 0; j < cnt; j++)
				{
					printf("%02X ", ((unsigned char*)runtime_image)[i + j]);
				}
				FontColor(7);
				printf("\n");
			}
		}
		i += cnt;
	}
}

std::vector<DWORD> get_whitelisted_addresses(QWORD local_image, QWORD runtime_image, DWORD size, DWORD section_address)
{
	std::vector<DWORD> whitelist_addresses;

	for (DWORD i = 0; i < size; i++)
	{
		if (((unsigned char*)local_image)[i] == ((unsigned char*)runtime_image)[i])
		{
			continue;
		}
		DWORD cnt = 0;
		while (1)
		{

			if (i + cnt >= size)
			{
				break;
			}

			if (((unsigned char*)local_image)[i + cnt] == ((unsigned char*)runtime_image)[i + cnt])
			{
				break;
			}

			cnt++;
		}
		if (cnt >= 1)
		{
			whitelist_addresses.push_back( (section_address + i) );
		}
		i += cnt;	
	}

	return whitelist_addresses;
}

QWORD vm_dump_module_ex(DWORD pid, QWORD base, BOOL code_only)
{
	QWORD a0, a1, a2, a3 = 0;
	char *a4;

	a0 = base;
	if (a0 == 0)
		return 0;

	a1 = km::vm::read<DWORD>(pid, a0 + 0x03C) + a0;
	if (a1 == a0)
	{
		return 0;
	}

	a2 = km::vm::read<DWORD>(pid, a1 + 0x050);
	if (a2 < 8)
		return 0;

	a4 = (char *)malloc(a2+24);


	*(QWORD*)(a4)=base;
	*(QWORD*)(a4 + 8)=a2;
	*(QWORD*)(a4 + 16)=a3;

	a4 += 24;


	QWORD image_dos_header = base;
	QWORD image_nt_header = km::vm::read<DWORD>(pid, image_dos_header + 0x03C) + image_dos_header;

	DWORD headers_size = km::vm::read<DWORD>(pid, image_nt_header + 0x54);
	km::vm::read(pid, image_dos_header, a4, headers_size);

	unsigned short machine = km::vm::read<WORD>(pid, image_nt_header + 0x4);

	QWORD section_header = machine == 0x8664 ?
		image_nt_header + 0x0108 :
		image_nt_header + 0x00F8;

	
	for (WORD i = 0; i < km::vm::read<WORD>(pid, image_nt_header + 0x06); i++) {

		QWORD section = section_header + (i * 40);
		DWORD section_characteristics = km::vm::read<DWORD>(pid, section + 0x24);


		if (code_only)
		{
			if (!(section_characteristics & 0x00000020))
				continue;
		}

		if ((section_characteristics & 0x02000000))
			continue;

		QWORD local_virtual_address = base + km::vm::read<DWORD>(pid, section + 0x0c);
		DWORD local_virtual_size = km::vm::read<DWORD>(pid, section + 0x08);
		QWORD target_virtual_address = (QWORD)a4 + km::vm::read<DWORD>(pid, section + 0x14);
		km::vm::read(pid, local_virtual_address, (PVOID)target_virtual_address, local_virtual_size );
		*(DWORD*)((QWORD)a4 + (section - image_dos_header) + 0x10) = local_virtual_size;
	}
	return (QWORD)a4;
}

void vm_free_module(QWORD dumped_module)
{
	dumped_module-=24;
	free((void *)dumped_module);
}

PVOID LoadFileEx(PCSTR path, DWORD *out_len)
{
	VOID *ret = 0;

	FILE *f = fopen(path, "rb");
	if (f)
	{
		fseek(f, 0, SEEK_END);
		long len = ftell(f);
		fseek(f, 0, SEEK_SET);


		if (out_len)
			*out_len = len;

		ret = malloc(len);

		if (fread(ret, len, 1, f) != 1)
		{
			free(ret);
			ret = 0;
		}

		fclose(f);
	}

	return (PVOID)ret;
}

void FreeFileEx(PVOID hMod)
{
	free(hMod);
}

BOOL write_dump_file(std::string name, PVOID buffer, QWORD size)
{
	if (CreateDirectoryA("./dumps/", NULL) || ERROR_ALREADY_EXISTS == GetLastError())
	{
		std::string path = "./dumps/" + name;
		FILE *f = fopen(path.c_str(), "wb");

		if (f)
		{
			fwrite(buffer, size, 1, f);

			fclose(f);

			return 1;
		}
	}

	return 0;
}

BOOL dump_module_to_file(DWORD pid, FILE_INFO file)
{

	QWORD target_base = vm_dump_module_ex(pid, file.base, 0);

	if (target_base == 0 || *(WORD*)target_base != IMAGE_DOS_SIGNATURE)
	{
		vm_free_module(target_base);
		return FALSE;
	}

	//
	// write dump file to /dumps/drivername
	//
	if (write_dump_file (file.name.c_str(), (PVOID)target_base, *(QWORD*)(target_base - 24 + 8)))
		LOG("driver: %s is succesfully dumped\n", file.name.c_str());

	HMODULE dll = (HMODULE)LoadFileEx(file.path.c_str(), 0);
	if (!dll)
	{
		vm_free_module(target_base);
		return 0;
	}
	
	QWORD image_dos_header = (QWORD)dll;
	QWORD image_nt_header = *(DWORD*)(image_dos_header + 0x03C) + image_dos_header;
	unsigned short machine = *(WORD*)(image_nt_header + 0x4);

	QWORD section_header_off = machine == 0x8664 ?
		image_nt_header + 0x0108 :
		image_nt_header + 0x00F8;

	std::vector <DWORD> whitelist_addresses;

	for (WORD i = 0; i < *(WORD*)(image_nt_header + 0x06); i++) {
		QWORD section = section_header_off + (i * 40);
		ULONG section_characteristics = *(ULONG*)(section + 0x24);

		UCHAR *section_name = (UCHAR*)(section + 0x00);
		ULONG section_virtual_address = *(ULONG*)(section + 0x0C);
		ULONG section_raw_address = *(ULONG*)(section + 0x14);
		ULONG section_virtual_size = *(ULONG*)(section + 0x08);

		if (section_characteristics & 0x00000020 && !(section_characteristics & 0x02000000))
		{
			//
			// skip Warbird page
			//
			if (!strcmp((const char*)section_name, "PAGEwx3"))
			{
				continue;
			}
		
			auto temp = get_whitelisted_addresses(
				(QWORD)((BYTE*)dll + section_raw_address),
				(QWORD)(target_base + section_raw_address),
				section_virtual_size,
				section_virtual_address
			);

			whitelist_addresses.reserve(whitelist_addresses.size() + temp.size());
			whitelist_addresses.insert(whitelist_addresses.end(), temp.begin(), temp.end());

		}
	}

	FreeFileEx(dll);
	vm_free_module(target_base);

	if (whitelist_addresses.size())
	{
		FILE *f = fopen(("./dumps/" + file.name + ".wl").c_str(), "wb+");
		if (f) {
			for (auto& wt : whitelist_addresses)
			{
				fwrite(&wt, sizeof(wt), 1, f);
			}
			fclose(f);
		}
	}

	return TRUE;
}

void compare_sections(QWORD local_image, QWORD runtime_image, DWORD diff, std::vector<DWORD> &whitelist_addresses)
{
	QWORD image_dos_header = (QWORD)local_image;
	QWORD image_nt_header = *(DWORD*)(image_dos_header + 0x03C) + image_dos_header;
	unsigned short machine = *(WORD*)(image_nt_header + 0x4);

	QWORD section_header_off = machine == 0x8664 ?
		image_nt_header + 0x0108 :
		image_nt_header + 0x00F8;

	for (WORD i = 0; i < *(WORD*)(image_nt_header + 0x06); i++) {
		QWORD section = section_header_off + (i * 40);
		ULONG section_characteristics = *(ULONG*)(section + 0x24);

		UCHAR *section_name = (UCHAR*)(section + 0x00);
		ULONG section_virtual_address = *(ULONG*)(section + 0x0C);
		ULONG section_raw_address = *(ULONG*)(section + 0x14);
		ULONG section_virtual_size = *(ULONG*)(section + 0x08);

		if (section_characteristics & 0x00000020 && !(section_characteristics & 0x02000000))
		{
			//
			// skip Warbird page
			//
			if (!strcmp((const char*)section_name, "PAGEwx3"))
			{
				continue;
			}
		
			scan_section(
				diff,
				(CHAR*)section_name,
				(QWORD)((BYTE*)local_image + section_raw_address),
				(QWORD)(runtime_image + section_raw_address),
				section_virtual_size,
				section_virtual_address,
				whitelist_addresses
			);
		}
	}
}

void scan_image(DWORD pid, FILE_INFO file, DWORD diff, BOOL use_cache)
{
	//
	// try to use existing memory dumps
	//

	HMODULE local_image = 0;
	std::vector<DWORD> whitelist_addresses;

	if (use_cache)
	{
		local_image = (HMODULE)LoadFileEx(("./dumps/" + file.name).c_str(), 0);
		if (local_image == 0)
		{
			local_image = (HMODULE)LoadFileEx(file.path.c_str(), 0);
		}

	
		DWORD size;
		PVOID wt = LoadFileEx(("./dumps/" + file.name + ".wl").c_str(), &size);
		if (wt)
		{
			for (DWORD i = 0; i < size / sizeof(DWORD); i++)
			{
				whitelist_addresses.push_back(((DWORD*)wt)[i]);
			}
		}
		FreeFileEx(wt);
	}
	else
	{
		const char *sub_str = strstr(file.path.c_str(), "\\dump_");

		if (sub_str)
		{
			std::string sub_name = sub_str + 6;
			file.path = "C:\\Windows\\System32\\Drivers\\" + sub_name;
		}

		local_image = (HMODULE)LoadFileEx(file.path.c_str(), 0);
	}

	if (local_image)
	{
		QWORD runtime_image = vm_dump_module_ex(pid, file.base, 1);

		if (runtime_image == 0 || *(WORD*)runtime_image != IMAGE_DOS_SIGNATURE)
		{
			FreeFileEx(local_image);
			vm_free_module(runtime_image);
			return;
		}

		LOG("scanning image: %s\n", file.path.c_str());

		QWORD image_dos_header = (QWORD)local_image;
		QWORD image_nt_header = *(DWORD*)(image_dos_header + 0x03C) + image_dos_header;
		unsigned short machine = *(WORD*)(image_nt_header + 0x4);

		DWORD min_difference = MIN_DIFFERENCE;

		if (whitelist_addresses.size())
		{
			if (machine != 0x8664)
				min_difference = 3;
			else
				min_difference = 1;
		} else {
			if (pid != 4)
			{
				if (machine != 0x8664)
					min_difference = 3;
				else
					min_difference = 1;
			}
		}

		//
		// force min difference if it's set.
		//
		if (diff != 0)
		{
			min_difference = diff;
		}

		compare_sections((QWORD)local_image, runtime_image, min_difference, whitelist_addresses);

		vm_free_module(runtime_image);
		FreeFileEx(local_image);
	} else {
		LOG_RED("failed to open %s\n", file.path.c_str());
	}
}


#define GET_BIT(data, bit) ((data >> bit) & 1)
void scan_pci(void)
{
	typedef struct {
		
		unsigned char  bus, slot, cfg[0x100];
		unsigned char  blk;
	} DEVICE_INFO;

	std::vector<DEVICE_INFO> devices;

	for (unsigned char bus = 0; bus < 255; bus++)
	{
		for (unsigned char slot = 0; slot < 32; slot++)
		{	
			WORD device_control = km::pci::read_i16_legacy(bus, slot, 0, 4);
			if (device_control == 0xFFFF)
			{
				continue;
			}

			DEVICE_INFO device;
			device.bus = bus;
			device.slot = slot;
			device.blk = 0;
			for (int i = 0; i < 0x100; i+=2)
			{
				*(WORD*)&device.cfg[i] = km::pci::read_i16_legacy(bus, slot, 0, i);
			}
			devices.push_back(device);
		}
	}

	//
	// test shadow cfg (pcileech-fpga 4.11 and lower)
	//
	for (auto & dev : devices)
	{
		DWORD tick = GetTickCount();
		km::pci::write_i16_legacy(dev.bus, dev.slot, 0, 0xA0, *(WORD*)(dev.cfg + 0xA0));
		tick = GetTickCount() - tick;
		if (tick > 100)
			continue;

		tick = GetTickCount();
		km::pci::write_i16_legacy(dev.bus, dev.slot, 0, 0xA8, *(WORD*)(dev.cfg + 0xA8));
		tick = GetTickCount() - tick;
		if (tick > 100)
		{
			dev.blk = 1;
			break;
		}
	}
	
	//
	// check configuration space
	//
	for (auto & dev : devices)
	{
		//
		// device was already blocked
		//
		if (dev.blk)
		{
			continue;
		}

		if (!GET_BIT(*(WORD*)(dev.cfg + 0x04), 2))
		{
			dev.blk = 1;
		}

		/*
		QWORD mgmt_base         = 0xF0000000;
		QWORD memory_mapped_cfg = mgmt_base + ((dev.bus - 0) << 20 | dev.slot << 15 | 0 << 12);
		WORD vendor_id = km::io::read<WORD>(memory_mapped_cfg + 0x00);
		WORD device_id = km::io::read<WORD>(memory_mapped_cfg + 0x02);

		printf("vendor: %lx device: %lx\n", vendor_id, device_id);
		*/
	
	}

	for (auto &dev : devices)
	{
		if (!dev.blk)
		{
			continue;
		}
		

		FontColor(14);
		LOG_RED("device [%02X:%02X:%02X] [%04X:%04X] is not allowed device\n", dev.bus, dev.slot, 0, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02));
		FontColor(7);
	}
}

//
// https://github.com/ekknod/Anti-Cheat-TestBench/blob/7abfd9ed2cb9e608fe6a0200ff1fbfa05fdfdade/main.c#L77
//
BOOL IsThreadFoundKTHREAD(QWORD process, QWORD thread)
{
	BOOL contains = 0;


	PLIST_ENTRY list_head = (PLIST_ENTRY)((QWORD)process + 0x30);
	PLIST_ENTRY list_entry = list_head;

	while ((list_entry = list_entry->Flink) != 0 && list_entry != list_head) {
		QWORD entry = (QWORD)((char*)list_entry - 0x2f8);
		if (entry == thread) {
			contains = 1;
			break;
		}
	}

	return contains;
}

void scan_thread(DWORD attachpid, QWORD thread_address, QWORD target_process)
{	
	QWORD thread_id = km::call(PsGetThreadId, thread_address);
	QWORD process = km::call(PsGetThreadProcess, thread_address);
	QWORD process_id = km::call(PsGetProcessId, process);

	if (process_id != 0)
	{
		QWORD lookup_object = 0;
		if (km::call(PsLookupThreadByThreadId, thread_id, (QWORD)&lookup_object) != 0)
		{
			LOG_RED("[%lld][%lld][%llX] thread is unlinked from PsLookupThreadByThreadId\n", process_id, thread_id, thread_address);
			goto NXT;
		}

		if (lookup_object != thread_address)
		{
			LOG_RED("[%lld][%lld][%llX] thread has wrong thread ID\n", process_id, thread_id, thread_address);
		}
	} else {
		static QWORD func = km::install_function((PVOID)IsThreadFoundKTHREAD);
		if (km::call(func, process, thread_address) == 0)
		{
			LOG_RED("[%lld][%lld][%llX] thread is unlinked from KTHREAD\n", process_id, thread_id, thread_address);
		}
	}
NXT:
	if (attachpid)
	{
		if (process == target_process)
		{
			return;
		}

		if (km::vm::read<QWORD>(4, thread_address + 0x98 + 0x20) == target_process)
		{
			LOG("[%lld][%lld][%llx] thread is attached to %d\n", process_id, thread_id, thread_address, attachpid);
		}
	}
}

//
// bruteforce KPRCB function from Anti-Cheat testbench project
//
void scan_threads(QWORD curr_thread, DWORD attachpid, QWORD target_process)
{
	static UCHAR processor_count = km::vm::read<UCHAR>(4, KeNumberProcessors);

	std::vector<QWORD> thread_list;
	std::vector<QWORD> check_list;

	for (UCHAR i = 0; i < processor_count; i++)
	{
		QWORD prcb = km::call(KeQueryPrcbAddress, i);

		if (prcb == 0)
			continue;
		
		QWORD threads[2]{};
		km::call(kernel::memcpy, (QWORD)threads, prcb + 0x08, sizeof(threads));

		if (threads[0])
		{
			thread_list.push_back(threads[0]);
		}

		if (threads[1])
		{
			thread_list.push_back(threads[1]);
		}
	}

	for (auto &thread : thread_list)
	{
		if (thread != curr_thread)
		{
			scan_thread(attachpid, thread, target_process);
		}
	}
}

//
// bruteforce scan Cr3 and find EFI RT pages
//
#include "ia32.hpp"
#define PAGE_SHIFT 12l

typedef struct {
	QWORD (*MmGetPhysicalAddressFn)(QWORD BaseAddress);
	QWORD (*MmGetVirtualForPhysicalFn)(QWORD BaseAddress);
	BOOLEAN (*MmIsAddressValidFn)(PVOID VirtualAddress);

	PVOID page_address_buffer;
	PVOID page_count_buffer;

	DWORD *total_count;


} EFI_RT_PAGES ;

QWORD __get_efi_runtime_pages(EFI_RT_PAGES *info)
{
	cr3 kernel_cr3;
	kernel_cr3.flags = __readcr3();
	
	DWORD index = 0;

	QWORD physical_address = kernel_cr3.address_of_page_directory << PAGE_SHIFT;

	pml4e_64* pml4 = (pml4e_64*)(info->MmGetVirtualForPhysicalFn(physical_address));

	if (!info->MmIsAddressValidFn(pml4) || !pml4)
		return 0;

	
	for (int pml4_index = 256; pml4_index < 512; pml4_index++)
	{

		physical_address = pml4[pml4_index].page_frame_number << PAGE_SHIFT;
		if (!pml4[pml4_index].present)
		{
			continue;
		}
	
		pdpte_64* pdpt = (pdpte_64*)(info->MmGetVirtualForPhysicalFn(physical_address));
		if (!info->MmIsAddressValidFn(pdpt) || !pdpt)
			continue;

		for (int pdpt_index = 0; pdpt_index < 512; pdpt_index++)
		{

			physical_address = pdpt[pdpt_index].page_frame_number << PAGE_SHIFT;
			if (!pdpt[pdpt_index].present)
			{
				continue;
			}

			pde_64* pde = (pde_64*)(info->MmGetVirtualForPhysicalFn(physical_address));
			if (!info->MmIsAddressValidFn(pde) || !pde)
				continue;

			//
			// 1gb
			//
			if (pdpt[pdpt_index].large_page)
			{
				//
				// we dont need add 1gb pages, but in case you want add them you can uncomment
				//
				/*
				DWORD page_count = 0;
				for (auto i = 0; i < 0x40000; i++)
				{
					
					if (!pde[i].present)
					{
						continue;
					}

					if (pde[i].execute_disable)
					{
						continue;
					}
					
					if (info->MmGetVirtualForPhysicalFn(physical_address + (i * PAGE_SIZE)) != 0)
					{
						continue;
					}

					page_count = (i + 1);
				}
				if (page_count)
				{
					if (*info->total_count > index)
					{
						*(QWORD*)((QWORD)info->page_address_buffer + (index * 8)) = physical_address;
						*(QWORD*)((QWORD)info->page_count_buffer + (index * 8))   = page_count;
						index++;
					}
				}
				*/
				continue;
			}



			DWORD page_count=0;
			QWORD previous_address=0;
			for (int pde_index = 0; pde_index < 512; pde_index++) {
				physical_address = pde[pde_index].page_frame_number << PAGE_SHIFT;

				if (!pde[pde_index].present)
				{
					continue;
				}

				pte_64* pte = (pte_64*)(info->MmGetVirtualForPhysicalFn(physical_address));
				if (!info->MmIsAddressValidFn(pte) || !pte)
					continue;


				//
				// 2mb page
				//
				
				if (pde[pde_index].large_page)
				{
					//
					// we dont need add 2mb pages, but in case you want add them you can uncomment
					//
					/*
					DWORD page_count = 0;
					for (auto i = 0; i < 512; i++)
					{
						if (!pte[i].present)
						{
							continue;
						}

						if (pte[i].execute_disable)
						{
							continue;
						}

						if (info->MmGetVirtualForPhysicalFn(physical_address + (i * PAGE_SIZE)) != 0)
						{
							continue;
						}

						page_count = (i + 1);
					}
					if (page_count)
					{
						if (*info->total_count > index)
						{
							*(QWORD*)((QWORD)info->page_address_buffer + (index * 8)) = physical_address;
							*(QWORD*)((QWORD)info->page_count_buffer + (index * 8))   = page_count;
							index++;
						}
					}
					*/
					continue;
				}
				

	
				for (int pte_index = 0; pte_index < 512; pte_index++)
				{
					physical_address = pte[pte_index].page_frame_number << PAGE_SHIFT;
					if (!pte[pte_index].present)
					{
						continue;
					}
					
					if (pte[pte_index].execute_disable)
					{
						continue;
					}
					
					if (info->MmGetVirtualForPhysicalFn(physical_address) != 0)
					{
						continue;
					}

					if ((physical_address - previous_address) == 0x1000)
					{
						page_count++;
					}
					else
					{
						if (page_count > 3 && *info->total_count > index)
						{
							*(QWORD*)((QWORD)info->page_address_buffer + (index * 8)) = previous_address - (page_count * 0x1000);
							*(QWORD*)((QWORD)info->page_count_buffer + (index * 8)) = page_count;
							index++;
						}
						page_count = 0;
					}
					previous_address = physical_address;
				}
			}
		}
	}
	*info->total_count = index;
	return 1;
}

std::vector<EFI_PAGE_INFO> get_efi_runtime_pages2(void)
{
	std::vector<EFI_PAGE_INFO> ret;

	QWORD page_address[1000], page_count[1000];
	DWORD address_count = 1000;

	EFI_RT_PAGES info{};
	*(QWORD*)&info.MmGetPhysicalAddressFn = MmGetPhysicalAddress;
	*(QWORD*)&info.MmGetVirtualForPhysicalFn = MmGetVirtualForPhysical;
	*(QWORD*)&info.MmIsAddressValidFn = MmIsAddressValid;

	info.page_address_buffer = (PVOID)page_address;
	info.page_count_buffer   = (PVOID)page_count;
	info.total_count         = &address_count;

	QWORD status = km::call_shellcode((PVOID)__get_efi_runtime_pages, (QWORD)&info);
	if (status == 0)
	{
		return {};
	}

	for (DWORD i = 0; i < address_count; i++)
	{
		ret.push_back( {page_address[i], page_address[i], (DWORD)page_count[i]} );
	}

	return ret;
}

BOOL get_first_efi_page(EFI_PAGE_INFO *entry)
{
	QWORD HalEfiRuntimeServicesTableAddr = km::vm::get_relative_address(0, HalEnumerateEnvironmentVariablesEx + 0xC, 1, 5);
	HalEfiRuntimeServicesTableAddr = km::vm::get_relative_address(0, HalEfiRuntimeServicesTableAddr + 0x69, 3, 7);
	HalEfiRuntimeServicesTableAddr = km::vm::read<QWORD>(0, HalEfiRuntimeServicesTableAddr);

	//
	// no table found
	//
	if (HalEfiRuntimeServicesTableAddr == 0)
	{
		return 0;
	}

	QWORD virtual_address = (QWORD)PAGE_ALIGN(km::vm::read<QWORD>(0, HalEfiRuntimeServicesTableAddr));
	if (virtual_address == 0)
		return 0;

	while (1)
	{
		if (km::call<BOOLEAN>(MmIsAddressValid, virtual_address) == 0)
		{
			virtual_address += PAGE_SIZE;
			break;
		}

		QWORD phys = km::call(MmGetPhysicalAddress, virtual_address);
		if (phys == 0)
		{
			virtual_address += PAGE_SIZE;
			break;
		}
		else if (phys == 0x1000)
		{
			break;
		}
		virtual_address -= PAGE_SIZE;
	}

	DWORD page_count = 1;
	QWORD physical_address = km::call(MmGetPhysicalAddress, virtual_address);

	while (1)
	{
		QWORD phys = km::call(MmGetPhysicalAddress, virtual_address + (page_count * PAGE_SIZE));
		if ((phys - physical_address) == (page_count * PAGE_SIZE))
		{
			page_count++;
		}
		else
		{
			break;
		}
	}

	entry->virtual_address  = virtual_address;
	entry->physical_address = physical_address;
	entry->page_count       = page_count;

	return 1;
}

BOOL get_next_efi_page(EFI_PAGE_INFO *entry)
{
	if (entry->virtual_address == 0)
	{
		return get_first_efi_page(entry);
	}

	QWORD next_virt = (entry->virtual_address + (entry->page_count * PAGE_SIZE));
	QWORD next_phys = km::call(MmGetPhysicalAddress, next_virt);
	if (next_phys == 0)
	{
		*entry = {};
		return 0;
	}

	if (km::call<BOOLEAN>(MmIsAddressValid, next_virt) == 0)
	{
		*entry = {};
		return 0;
	}

	entry->virtual_address  = next_virt;
	entry->physical_address = next_phys;
	DWORD count = 1;

	while (km::call(MmGetPhysicalAddress, next_virt + (count * PAGE_SIZE)) == next_phys + (count * PAGE_SIZE))
		count++;

	entry->page_count = count;
	return 1;
}

std::vector<EFI_PAGE_INFO> get_efi_runtime_pages(void)
{
	std::vector<EFI_PAGE_INFO> ret;
	EFI_PAGE_INFO page{};
	while (get_next_efi_page(&page))
	{
		if (page.page_count < 3)
		{
			continue;
		}
		static QWORD MiGetPteAddress = (QWORD)(km::vm::read<INT>(0, MmUnlockPreChargedPagedPool + 8) + MmUnlockPreChargedPagedPool + 12);
		QWORD pte_address = km::call(MiGetPteAddress, page.virtual_address);
		if (pte_address)
		{
			QWORD info = km::vm::read<QWORD>(0, pte_address);
			if ((info&8)!=0 && (info&0x10)!=0)
			{
				continue;
			}
		}
		ret.push_back( {page.virtual_address, page.physical_address, page.page_count} );
	}
	return ret;
}

std::vector<EFI_MODULE_INFO> get_efi_module_list2(void)
{
	std::vector<EFI_MODULE_INFO> modules;

	for (auto &page : get_efi_runtime_pages2())
	{
		LOG("EFI page found [0x%llx - 0x%llx] page count: %ld\n", page.physical_address, page.physical_address + (page.page_count * PAGE_SIZE), page.page_count);

		if (modules.size())
		{
			continue;
		}
		
		for (DWORD page_num = 0; page_num < page.page_count; page_num++)
		{
			QWORD module_base = page.physical_address + (page_num * PAGE_SIZE);
			if (km::io::read<WORD>(module_base) == IMAGE_DOS_SIGNATURE)
			{
				QWORD nt = km::io::read<DWORD>(module_base + 0x03C) + module_base;
				if (km::io::read<WORD>(nt) != IMAGE_NT_SIGNATURE)
				{
					continue;
				}
				modules.push_back({module_base, module_base, km::io::read<DWORD>(nt + 0x050)});
			}
		}
		
		if (modules.size() < 4)
		{
			modules.clear();
		}
		else
		{
			for (auto &base : modules)
			{
				LOG("[%llx] EFI runtime image found: [0x%llx - 0x%llx]\n", page.physical_address, base.physical_address, base.physical_address + base.size);
			}
		}
	}
	return modules;
}

std::vector<EFI_MODULE_INFO> get_efi_module_list(void)
{
	std::vector<EFI_MODULE_INFO> modules;

	for (auto &page : get_efi_runtime_pages())
	{
		LOG("EFI page found [0x%llx - 0x%llx] page count: %ld\n", page.physical_address, page.physical_address + (page.page_count * PAGE_SIZE), page.page_count);

		if (modules.size())
		{
			continue;
		}
		
		for (DWORD page_num = 0; page_num < page.page_count; page_num++)
		{
			QWORD module_base = page.virtual_address + (page_num * PAGE_SIZE);
			if (km::vm::read<WORD>(0, module_base) == IMAGE_DOS_SIGNATURE)
			{
				QWORD nt = km::vm::read<DWORD>(0, module_base + 0x03C) + module_base;
				if (km::vm::read<WORD>(0, nt) != IMAGE_NT_SIGNATURE)
				{
					continue;
				}
				QWORD module_base_phys = page.physical_address + (page_num * PAGE_SIZE);
				modules.push_back({module_base, module_base_phys, km::vm::read<DWORD>(0, nt + 0x050)});
			}
		}
		
		if (modules.size() < 4)
		{
			modules.clear();
		}
		else
		{
			for (auto &base : modules)
			{
				LOG("[%llx] EFI runtime image found: [0x%llx - 0x%llx]\n", page.physical_address, base.physical_address, base.physical_address + base.size);
				//
				// to-do: verify image integrity
				//
			}
		}
	}
	return modules;
}

void scan_efi(void)
{
	QWORD HalEfiRuntimeServicesTableAddr = km::vm::get_relative_address(4, HalEnumerateEnvironmentVariablesEx + 0xC, 1, 5);
	HalEfiRuntimeServicesTableAddr = km::vm::get_relative_address(4, HalEfiRuntimeServicesTableAddr + 0x69, 3, 7);
	HalEfiRuntimeServicesTableAddr = km::vm::read<QWORD>(4, HalEfiRuntimeServicesTableAddr);

	//
	// no table found
	//
	if (HalEfiRuntimeServicesTableAddr == 0)
	{
		return;
	}

	QWORD HalEfiRuntimeServicesTable[9];
	km::vm::read(4, HalEfiRuntimeServicesTableAddr, &HalEfiRuntimeServicesTable, sizeof(HalEfiRuntimeServicesTable));
	

	//
	// you can also test get_efi_module_list2();
	//
	std::vector<EFI_MODULE_INFO> module_list = get_efi_module_list();
	for (int i = 0; i < 9; i++)
	{
		QWORD rt_func = HalEfiRuntimeServicesTable[i];
		if (km::vm::read<WORD>(0, rt_func) == 0x25ff)
		{
			LOG_RED("EFI Runtime service [%d] is hooked with byte patch: %llx\n", i, rt_func);
			continue;
		}
		
		QWORD physical_address = km::call(MmGetPhysicalAddress, rt_func);
		BOOL found = 0;
		for (auto &base : module_list)
		{
			if (physical_address >= (QWORD)base.physical_address && physical_address <= (QWORD)((QWORD)base.physical_address + base.size))
			{
				found = 1;
				break;
			}
		}

		if (!found)
		{
			LOG_RED("EFI Runtime service [%d] is hooked with pointer swap: %llx, %llx\n", i, rt_func, physical_address);
		}
	}
}

int main(int argc, char **argv)
{

	for (auto &drv : get_kernel_modules())
	{
		if (!_strcmpi(drv.name.c_str(), "ntoskrnl.exe"))
		{
			ntoskrnl_base = drv.base;
			break;
		}
	}

	if (ntoskrnl_base == 0)
	{
		LOG_RED("ntoskrnl.exe base address not found\n");
	}

	for (auto &i : global_export_list)
	{
		QWORD temp = *(QWORD*)i;

		*(QWORD*)i = get_kernel_export(ntoskrnl_base, "ntoskrnl.exe", (PCSTR)temp);
		if (*(QWORD*)i == 0)
		{
			LOG_RED("export %s not found\n", (PCSTR)temp);
			return 0;
		}
	}

	if (!km::initialize())
	{
		LOG_RED("failed to initialize driver\n");
		return 0;
	}
	
	if (argc < 2)
	{
		LOG("--help\n");
		return getchar();
	}

	BOOL scan=0, pid = 4, cache = 0, scanpci = 0, diff = 0, use_cache = 0, scanthreads = 0, attachpid = 0,scanefi=0;

	for (int i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "--help"))
		{
			printf(
				"\n\n"

				"--scan                    scan target process memory changes\n"
				"   --diff      (optional) the amount of bytes that have to be different before logging the patch\n"
				"   --usecache  (optional) if option is selected, we use local dumps instead of original disk files\n"
				"   --savecache (optional) dump target process modules to disk, these can be used later with --usecache\n"
				"   --pid       (optional) target process id\n\n"
				"--scanpci                 scan pcileech-fpga cards from the system (4.11 and lower)\n\n"
				"--scanthreads             scan system threads\n"
				"   --attachpid (optional) check if thread is attached to target process id\n\n"
				"--scanefi                 scan efi runtime services\n\n\n"
			);


			printf("\nExample (verifying modules integrity by using cache):\n"
				"1.			making sure Windows is not infected\n"
				"1.			ecac.exe --savecache --pid 4\n"
				"2.			reboot the computer\n"
				"3.			load malware what is potentially modifying modules\n"
				"4.			ecac.exe --scan --usecache --pid 4\n"
				"all malware patches should be now visible\n\n"
			);
			
		}

		else if (!strcmp(argv[i], "--scan"))
		{
			scan = 1;
		}

		else if (!strcmp(argv[i], "--diff"))
		{
			diff = atoi(argv[i + 1]);
		}

		else if (!strcmp(argv[i], "--pid"))
		{
			pid = atoi(argv[i + 1]);
		}

		else if (!strcmp(argv[i], "--savecache"))
		{
			cache = 1;
		}

		else if (!strcmp(argv[i], "--scanpci"))
		{
			scanpci = 1;
		}

		else if (!strcmp(argv[i], "--usecache"))
		{
			use_cache = 1;
		}

		else if (!strcmp(argv[i], "--scanthreads"))
		{
			scanthreads = 1;
		}

		else if (!strcmp(argv[i], "--attachpid"))
		{
			attachpid = atoi(argv[i + 1]);
		}

		else if (!strcmp(argv[i], "--scanefi"))
		{
			scanefi = 1;
		}
	}

	//
	// uninstall old shellcodes to avoid memory leaks
	//
	for (auto &pool : get_kernel_allocations())
	{
		if (pool.tag == POOLTAG)
		{
			km::uninstall_function(pool.address);
		}
	}

	if (scanefi)
	{
		LOG("scanning EFI runtime memory\n");
		scan_efi();
		LOG("EFI runtime memory scan is complete\n");
	}

	if (scanthreads)
	{
		QWORD target_process = 0;
		if (attachpid)
		{
			if (km::call(PsLookupProcessByProcessId, attachpid, (QWORD)&target_process) != 0)
			{
				LOG("target process is not running\n");
				return 0;
			}
		}

		QWORD curr_thread = km::call(PsGetCurrentThread);

		LOG("scanning unlinked system threads\n");
		for (int i = 0; i < 10000; i++)
		{
			scan_threads(curr_thread, attachpid, target_process);
		}
		LOG("system thread scan is complete\n");
	}

	if (scanpci)
	{
		LOG("scanning PCIe devices\n");
		scan_pci();
		LOG("PCIe scan is complete\n");
	}

	if (scan)
	{
		std::vector<FILE_INFO> modules;

		if (pid == 4)
		{
			modules = get_kernel_modules();
		}
		else
		{
			modules = get_user_modules(pid);
		}

		LOG("\nscanning modules\n");
		for (auto mod : modules)
		{
			scan_image(pid, mod, diff, use_cache);
		}

		LOG("scan is complete\n");
	}

	if (cache)
	{
		std::vector<FILE_INFO> modules;

		if (pid == 4 || pid == 0)
		{
			modules = get_kernel_modules();
		}
		else
		{
			modules = get_user_modules(pid);
		}

		for (auto &mod : modules)
		{
			dump_module_to_file(pid, mod);
		}
	
	}

	//
	// garbage collector
	//
	for (auto &pool : get_kernel_allocations())
	{
		if (pool.tag == POOLTAG)
		{
			LOG("uninstalling shellcode: %llx\n", pool.address);
			km::uninstall_function(pool.address);
		}
	}

	return 0;
}

#pragma pack(push, 8)
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#pragma comment(lib, "ntdll.lib")
extern "C" __kernel_entry NTSTATUS NtQuerySystemInformation(
ULONG SystemInformationClass,
PVOID                    SystemInformation,
ULONG                    SystemInformationLength,
PULONG                   ReturnLength
);

std::vector<FILE_INFO> get_kernel_modules(void)
{
	std::vector<FILE_INFO> driver_information;


	ULONG req = 0;
	NTSTATUS status = NtQuerySystemInformation(11, 0, 0, &req);
	if (status != 0xC0000004)
	{
		return driver_information;
	}

	PRTL_PROCESS_MODULES system_modules = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, req, MEM_COMMIT, PAGE_READWRITE);

	status = NtQuerySystemInformation(11, system_modules, req, &req);

	if (status != 0)
	{
		VirtualFree(system_modules, 0, MEM_RELEASE);
		return driver_information;
	}

	for (ULONG i = system_modules->NumberOfModules; i--;)
	{
		RTL_PROCESS_MODULE_INFORMATION entry = system_modules->Modules[i];	
		char *sub_string = strstr((char *const)entry.FullPathName, "system32");
		if (sub_string == 0)
		{
			sub_string = strstr((char *const)entry.FullPathName, "System32");
		}

		std::string path;
		if (sub_string)
		{
			path = "C:\\Windows\\" + std::string(sub_string);
		}
		else
		{
			path = std::string((const char *)entry.FullPathName);
		}

		PCSTR name = (PCSTR)&entry.FullPathName[entry.OffsetToFileName];

		FILE_INFO temp_information;
		temp_information.path = path;
		temp_information.name = name;
		temp_information.base = (QWORD)entry.ImageBase;
		temp_information.size = (QWORD)entry.ImageSize;
		driver_information.push_back(temp_information);	
	}
	
	VirtualFree(system_modules, 0, MEM_RELEASE);

	return driver_information;
}

typedef struct tagMODULEENTRY32EX
{
    DWORD   dwSize;
    DWORD   th32ModuleID;       // This module
    DWORD   th32ProcessID;      // owning process
    DWORD   GlblcntUsage;       // Global usage count on the module
    DWORD   ProccntUsage;       // Module usage count in th32ProcessID's context
    DWORD   modBaseAddr;        // Base address of module in th32ProcessID's context
    DWORD   modBaseSize;        // Size in bytes of module starting at modBaseAddr
    DWORD   hModule;            // The hModule of this module in th32ProcessID's context
    char    szModule[MAX_MODULE_NAME32 + 1];
    char    szExePath[MAX_PATH];
} MODULEENTRY32EX;

std::vector<FILE_INFO> get_user_modules(DWORD pid)
{
	std::vector<FILE_INFO> info;


	HANDLE snp = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

	if (snp == INVALID_HANDLE_VALUE)
	{
		return info;
	}

	MODULEENTRY32 module_entry{};
	module_entry.dwSize = sizeof(module_entry);

	if (!Module32First(snp, &module_entry))
	{
		CloseHandle(snp);
		return info;
	}

	QWORD nt_header = km::vm::read<DWORD>(pid, (QWORD)module_entry.modBaseAddr + 0x03C) + (QWORD)module_entry.modBaseAddr;
	BOOL  wow64_process = km::vm::read<WORD>(pid, nt_header + 0x4) == 0x8664 ? 0 : 1;
	
	while (Module32Next(snp, &module_entry))
	{
		if (wow64_process)
		{
			if (strstr(module_entry.szExePath, "SYSTEM32"))
			{
				continue;
			}

			if (strstr(module_entry.szExePath, "System32"))
			{
				continue;
			}
		}

		if (strstr(module_entry.szExePath, "WindowsApps"))
		{
			continue;
		}

		FILE_INFO temp;
		temp.base = (QWORD)module_entry.modBaseAddr;
		temp.size = module_entry.modBaseSize;
		temp.path = std::string(module_entry.szExePath);
		temp.name = std::string(module_entry.szModule);

		info.push_back(temp);
	}
	CloseHandle(snp);
	return info;
}

std::vector<PROCESS_INFO> get_system_processes()
{
	std::vector<PROCESS_INFO> process_info;

	HANDLE snp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(entry);

	while (Process32Next(snp, &entry))
	{
		if (entry.th32ProcessID == 0)
		{
			continue;
		}
		if (entry.th32ProcessID == 4)
			process_info.push_back({entry.th32ProcessID, get_kernel_modules()});
		else
			process_info.push_back({entry.th32ProcessID, get_user_modules(entry.th32ProcessID)});
	}
	CloseHandle(snp);
	return process_info;
}

//
// https://github.com/processhacker/plugins-extra/blob/master/PoolMonPlugin/pooltable.c 
//
NTSTATUS EnumBigPoolTable(
	_Out_ PVOID* Buffer
)
{
	NTSTATUS status;
	PVOID buffer;
	ULONG bufferSize;
	ULONG attempts;

	bufferSize = 0x100;
	buffer = malloc(bufferSize);

	status = NtQuerySystemInformation(
		0x42,
		buffer,
		bufferSize,
		&bufferSize
	);
	attempts = 0;

	while (status == 0xC0000004 && attempts < 8)
	{
		free(buffer);
		buffer = malloc(bufferSize);

		status = NtQuerySystemInformation(
			0x42,
			buffer,
			bufferSize,
			&bufferSize
		);
		attempts++;
	}

	if (status == 0)
		*Buffer = buffer;
	else
		free(buffer);

	return status;
}

typedef struct _SYSTEM_BIGPOOL_ENTRY {
    union {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };
    ULONG_PTR SizeInBytes;
    union {
        UCHAR Tag[4];
        ULONG TagULong;
    };
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
    ULONG Count; 
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

std::vector<BIGPOOL_INFO> get_kernel_allocations(void)
{
	std::vector<BIGPOOL_INFO> info;
	PVOID buffer;

	if (EnumBigPoolTable(&buffer) != 0)
	{
		return info;
	}

	PSYSTEM_BIGPOOL_INFORMATION bigpool_info = (PSYSTEM_BIGPOOL_INFORMATION)buffer;
	for (ULONG i = 0; i < bigpool_info->Count; i++)
	{
		QWORD virtual_address = (QWORD)bigpool_info->AllocatedInfo[i].VirtualAddress;
		virtual_address = virtual_address - 1; // prefix.

		if (virtual_address && bigpool_info->AllocatedInfo[i].NonPaged)
		{			
			info.push_back({virtual_address, bigpool_info->AllocatedInfo[i].SizeInBytes, bigpool_info->AllocatedInfo[i].TagULong});
		}
	}
	free(buffer);
	return info;
}

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

NTSTATUS PhEnumHandles(_Out_ PSYSTEM_HANDLE_INFORMATION* Handles)
{
	static ULONG initialBufferSize = 0x4000;
	NTSTATUS status;
	PVOID buffer;
	ULONG bufferSize;

	bufferSize = initialBufferSize;
	buffer = malloc(bufferSize);

	while ((status = NtQuerySystemInformation(
		0x10,
		buffer,
		bufferSize,
		NULL
	)) == 0xC0000004)
	{
		free(buffer);
		bufferSize *= 2;
		buffer = malloc(bufferSize);
	}

	if (status != 0)
	{
		free(buffer);
		return status;
	}

	if (bufferSize <= 0x100000) initialBufferSize = bufferSize;
	*Handles = (PSYSTEM_HANDLE_INFORMATION)buffer;

	return status;
}

std::vector<HANDLE_INFO> get_system_handle_information(void)
{
	std::vector<HANDLE_INFO> info;
	PSYSTEM_HANDLE_INFORMATION handle_info = 0;

	if (PhEnumHandles(&handle_info))
	{
		return info;
	}

	for (ULONG i = 0; i < handle_info->HandleCount; i++)
	{
		HANDLE_INFO entry;
		entry.pid = handle_info->Handles[i].ProcessId;
		entry.object_type = handle_info->Handles[i].ObjectTypeNumber;
		entry.flags = handle_info->Handles[i].Flags;
		entry.handle = handle_info->Handles[i].Handle;
		entry.object = (QWORD)handle_info->Handles[i].Object;
		entry.access_mask = handle_info->Handles[i].GrantedAccess;

		info.push_back(entry);
	}

	free(handle_info);

	return info;
}

