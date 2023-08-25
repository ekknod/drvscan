#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
#include <stdlib.h>
#include <TlHelp32.h>
#include <intrin.h>

#define IOCTL_INTEL 0x80862007
#define MIN_DIFFERENCE 9
#define POOLTAG (DWORD)'ECAC'

typedef ULONG_PTR QWORD;
std::vector<QWORD> global_export_list;
std::vector<QWORD> global_pattern_list;

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


QWORD g_ntoskrnl_base;
NTOSKRNL_EXPORT(MmCopyMemory);
NTOSKRNL_EXPORT(PsLookupProcessByProcessId);
NTOSKRNL_EXPORT(ExAllocatePoolWithTag);
NTOSKRNL_EXPORT(ExFreePoolWithTag);
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

namespace kernel
{
	NTOSKRNL_EXPORT(memcpy);
}


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
	DWORD                  tag;
} BIGPOOL_INFO;

std::vector<FILE_INFO>    get_kernel_modules(void);
std::vector<FILE_INFO>    get_user_modules(DWORD pid);
std::vector<PROCESS_INFO> get_system_processes();
std::vector<BIGPOOL_INFO> get_kernel_allocations(void);

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

BOOLEAN data_compare(const BYTE* data, const BYTE* pattern, const char* mask)
{
	for (; *mask; ++mask, ++data, ++pattern)
		if (*mask == 'x' && *data != *pattern)
			return 0;
	return (*mask) == 0;
}

QWORD find_pattern_ex(UINT64 dwAddress, QWORD dwLen, UCHAR *pattern, char *mask)
{
	if (dwLen <= 0)
		return 0;
	for (QWORD i = 0; i < dwLen; i++)
		if (data_compare((BYTE*)(dwAddress + i), pattern, mask))
			return (QWORD)(dwAddress + i);
	return 0;
}

QWORD find_pattern(QWORD module, UCHAR *pattern, CHAR *mask, QWORD len, int counter=1)
{
	ULONG_PTR ret = 0;
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((BYTE*)pidh + pidh->e_lfanew);
	PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((BYTE*)pinh + sizeof(IMAGE_NT_HEADERS64));
	
	for (USHORT sec = 0; sec < pinh->FileHeader.NumberOfSections; sec++)
	{
		
		if ((pish[sec].Characteristics & 0x00000020))
		{
			QWORD address = find_pattern_ex(pish[sec].VirtualAddress + (ULONG_PTR)(module), pish[sec].Misc.VirtualSize - len, pattern, mask);
 
			if (address) {
				ret = address;

				counter --;

				if (counter == 0)
					break;
			}
		}
		
	}
	return ret;
}

QWORD find_kernel_pattern(QWORD module, PCSTR driver_name, UCHAR *pattern, QWORD len, int counter=1)
{
	HMODULE ntos = LoadLibraryA(driver_name);

	if (ntos == 0)
	{
		return 0;
	}

	std::vector<CHAR> mask;
	for (QWORD i = 0; i < len; i++)
	{
		if (pattern[i] == 0xEC)
		{
			mask.push_back('?');
		}
		else
		{
			mask.push_back('x');
		}
	}


	QWORD pattern_address = find_pattern((QWORD)ntos, pattern, mask.data(), len, counter);
	if (pattern_address == 0)
	{
		goto cleanup;
	}

	pattern_address = pattern_address - (QWORD)ntos;
	pattern_address = pattern_address + module;

cleanup:
	FreeLibrary(ntos);
	return pattern_address;
}

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

	QWORD allocate_memory(QWORD size)
	{
		return call(ExAllocatePoolWithTag, 0, 0x1000 + size, POOLTAG);
	}

	void free_memory(QWORD address)
	{
		call(ExFreePoolWithTag, address, POOLTAG);
	}

	QWORD install_function(PVOID shellcode, QWORD size)
	{
		QWORD mem = allocate_memory(size);
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

	QWORD call_shellcode(PVOID shellcode, QWORD size, QWORD r1 = 0, QWORD r2 = 0, QWORD r3 = 0, QWORD r4 = 0, QWORD r5 = 0, QWORD r6 = 0, QWORD r7 = 0)
	{
		QWORD func = install_function(shellcode, size);
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
		QWORD ntoskrnl_base = 0;

		for (auto &drv : get_kernel_modules())
		{
			if (!_strcmpi(drv.name.c_str(), "driver.sys"))
			{
				target_driver = drv.base;
			}

			if (!_strcmpi(drv.name.c_str(), "ntoskrnl.exe"))
			{
				ntoskrnl_base = drv.base;
			}
		}

		if (target_driver == 0 || ntoskrnl_base == 0)
		{
			printf("[-] driver is not loaded\n");
			return 0;
		}

		g_ntoskrnl_base = ntoskrnl_base;

		for (auto &i : global_export_list)
		{
			QWORD temp = *(QWORD*)i;

			*(QWORD*)i = get_kernel_export(ntoskrnl_base, "ntoskrnl.exe", (PCSTR)temp);
			if (*(QWORD*)i == 0)
			{
				printf("[-] export %s not found\n", (PCSTR)temp);
				return 0;
			}
		}

		for (auto &i : global_pattern_list)
		{
			QWORD temp = *(QWORD*)i;

			QWORD pattern_len = strlen((const char*)temp);


			*(QWORD*)i = find_kernel_pattern(ntoskrnl_base, "ntoskrnl.exe", (UCHAR*)temp, pattern_len);
			if (*(QWORD*)i == 0)
			{
				printf("[-] pattern ");

				for (int i = 0; i < pattern_len; i++)
				{
					if (((UCHAR*)temp)[i] == 0xEC)
					{
						printf("? ");
					}
					else
					{
						printf("%02X ", ((UCHAR*)temp)[i]);
					}
				}

				printf("not found\n");

				return 0;
			}
		}

		driver_handle = CreateFileA("\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		if (driver_handle == INVALID_HANDLE_VALUE)
		{
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
				printf("[-] driver integrity check failed\n");
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

void FontColor(int color=0x07)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

BOOLEAN IsAddressEqual(QWORD address0, QWORD address2, INT64 cnt)
{
	INT64 res = abs(  (INT64)(address2 - address0)  );
	return res <= cnt;
}

void scan_section(DWORD diff, BOOL wow64, DWORD pid, CHAR *section_name, QWORD local_image, QWORD runtime_image, QWORD size, QWORD section_address, std::vector<DWORD> &wla)
{
	DWORD min_difference = MIN_DIFFERENCE;

	if (wla.size())
	{
		if (wow64)
			min_difference = 3;
		else
			min_difference = 1;
	} else {
		if (pid != 4)
		{
			if (wow64)
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

		if (cnt >= min_difference)
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
		printf("[+] driver: %s is succesfully dumped\n", file.name.c_str());

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

void scan_image(DWORD pid, FILE_INFO file, DWORD diff, BOOL use_cache)
{
	//
	// try to use existing memory dumps
	//

	HMODULE dll = 0;
	std::vector<DWORD> whitelist_addresses;

	if (use_cache)
	{
		dll = (HMODULE)LoadFileEx(("./dumps/" + file.name).c_str(), 0);
		if (dll == 0)
		{
			dll = (HMODULE)LoadFileEx(file.path.c_str(), 0);
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
		dll = (HMODULE)LoadFileEx(file.path.c_str(), 0);
	}




	if (dll)
	{
		QWORD target_base = vm_dump_module_ex(pid, file.base, 1);

		if (target_base == 0 || *(WORD*)target_base != IMAGE_DOS_SIGNATURE)
		{
			FreeFileEx(dll);
			vm_free_module(target_base);
			return;
		}

		printf("scanning image: %s\n", file.path.c_str());

		QWORD image_dos_header = (QWORD)dll;
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
					machine != 0x8664,
					pid,
					(CHAR*)section_name,
					(QWORD)((BYTE*)dll + section_raw_address),
					(QWORD)(target_base + section_raw_address),
					section_virtual_size,
					section_virtual_address,
					whitelist_addresses
				);
			}
		}

		vm_free_module(target_base);
		FreeFileEx(dll);
	} else {
		printf("failed to open %s\n", file.path.c_str());
	}
}

void scan_pcileech(void)
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
		printf("[+] [%02X:%02X:%02X] [%04X:%04X] (%d)\n", dev.bus, dev.slot, 0, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02), dev.blk);
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

	QWORD process_id = 0;
	if (process)
	{
		process_id = km::call(PsGetProcessId, process);
	}

	if (thread_id != 0)
	{
		QWORD lookup_object = 0;
		if (km::call(PsLookupThreadByThreadId, thread_id, (QWORD)&lookup_object) != 0)
		{
			printf("[+] [%lld][%lld][%llX] thread is unlinked\n", process_id, thread_id, thread_address);
			goto NXT;
		}

		if (lookup_object != thread_address)
		{
			printf("[+] [%lld][%lld][%llX] thread has wrong thread ID\n", process_id, thread_id, thread_address);
		}
	} else {
		static QWORD func = km::install_function((PVOID)IsThreadFoundKTHREAD, get_function_size((QWORD)IsThreadFoundKTHREAD));
		if (km::call(func, process, thread_address) == 0)
		{
			printf("[+] [%lld][%lld][%llX] thread is unlinked\n", process_id, thread_id, thread_address);
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
			printf("[+] [%lld][%lld][%llx] thread is attached to %d\n", process_id, thread_id, thread_address, attachpid);
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

#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
BOOL ResolveHalEfiBase(PVOID fn, QWORD address, QWORD* base, QWORD* size)
{
	BOOL result = 0;
	*base = 0;
	if (size)
		*size = 0;

	address = (QWORD)PAGE_ALIGN((QWORD)address);
	while (1)
	{
		address -= 0x1000;
		if (((QWORD(*)(QWORD))(fn))(address) == 0)
		{
			break;
		}

		if (*(unsigned short*)address == 0x5A4D)
		{
			IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)address;
			IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((char*)dos + dos->e_lfanew);
			if (nt->Signature != 0x00004550)
				continue;

			*base = address;
			if (size)
				*size = nt->OptionalHeader.SizeOfImage;

			result = 1;
			break;
		}
	}
	return result;
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

	QWORD resolve_base_fn = km::install_function((PVOID)ResolveHalEfiBase, get_function_size((QWORD)ResolveHalEfiBase));
	for (auto &rt : HalEfiRuntimeServicesTable)
	{
		//
		// resolve hal efi base, size
		//
		QWORD base,size;
		if (!km::call(resolve_base_fn, MmGetPhysicalAddress, rt, (QWORD)&base, (QWORD)&size))
		{
			continue;
		}

		if (rt < base || rt > (base + size))
		{
			printf("[+] EFI Runtime service (%llx) is not pointing at original Image: %llx\n", rt, base);
			continue;
		}

		DWORD begin = km::vm::read<DWORD>(0, rt);

		if (begin == 0xfa1e0ff3)
		{
			printf("[+] EFI Runtime service (%llx) is hooked with efi-memory: %llx\n", rt, base);
			//
			// 
			// QWORD dump_efi = vm_dump_module_ex(0, base, 1);
			//
			//
			continue;
		}

		if (((WORD*)&begin)[0] == 0x25ff)
		{
			printf("[+] EFI Runtime service (%llx) is hooked with byte patch: %llx\n", rt, base);
			//
			// 
			// QWORD dump_efi = vm_dump_module_ex(0, base, 1);
			//
			//
			continue;
		}
	}
	km::uninstall_function(resolve_base_fn);
}

int main(int argc, char **argv)
{
	if (!km::initialize())
	{
		printf("[-] intel driver is not running\n");
		printf("Press any key to continue . . .");
		return getchar();
	}
	
	if (argc < 2)
	{
		printf("[drvscan] --help\n");
		return getchar();
	}

	BOOL scan=0, pid = 4, cache = 0, pcileech = 0, diff = 0, use_cache = 0, scanthreads = 0, attachpid = 0,scanefi=0;

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
				"--pcileech                scan pcileech-fpga cards from the system (4.11 and lower)\n\n"
				"--scanthreads             scan system threads\n"
				"   --attachpid (optional) check if thread is attached to target process id\n\n"
				"--scanefi                 scan efi runtime services\n\n\n"
			);


			printf("\nExample (verifying modules integrity by using cache):\n"
				"1.			making sure Windows is not infected\n"
				"1.			drvscan.exe --savecache --pid 4\n"
				"2.			reboot the computer\n"
				"3.			load malware what is potentially modifying modules\n"
				"4.			drvscan.exe --scan --usecache --pid 4\n"
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

		else if (!strcmp(argv[i], "--pcileech"))
		{
			pcileech = 1;
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

	if (scanefi)
	{
		printf("[+] scanning EFI runtime services\n");
		scan_efi();
		printf("[+] EFI runtime services scan is complete\n");
	}

	if (scanthreads)
	{
		QWORD target_process = 0;
		if (attachpid)
		{
			if (km::call(PsLookupProcessByProcessId, attachpid, (QWORD)&target_process) != 0)
			{
				printf("[-] target process is not running\n");
				return 0;
			}
		}

		QWORD curr_thread = km::call(PsGetCurrentThread);

		printf("[+] scanning unlinked system threads\n");
		for (int i = 0; i < 10000; i++)
		{
			scan_threads(curr_thread, attachpid, target_process);
		}
		printf("[+] system thread scan is complete\n");
	}

	if (pcileech)
	{
		printf("[+] scanning PCIe devices\n");
		scan_pcileech();
		printf("[+] PCIe scan is complete\n");
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

		printf("\n[+] scanning modules\n");
		for (auto mod : modules)
		{
			scan_image(pid, mod, diff, use_cache);
		}

		printf("[+] scan is complete\n");
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
			printf("[+] uninstalling shellcode: %llx\n", pool.address);
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

		info.push_back({virtual_address, bigpool_info->AllocatedInfo[i].TagULong});
	}
	free(buffer);
	return info;
}

