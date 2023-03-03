#define _CRT_SECURE_NO_WARNINGS

/*
 * handy tool for scanning kernel driver patches
 */

#include <windows.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>

#define MIN_DIFFERENCE 9
#define IOCTL_READMEMORY 0xECAC00
#define IOCTL_READMEMORY_PROCESS 0xECAC02

typedef ULONG_PTR QWORD;

typedef struct {
	std::string path;
	QWORD       base;
	QWORD       size;
} FILE_INFO ;

std::vector<FILE_INFO> get_system_drivers(void);
std::vector<FILE_INFO> get_process_modules(PCSTR process_name, DWORD *process_id);

#pragma pack(1)
typedef struct {
	PVOID src;
	PVOID dst;
	SIZE_T length;
	ULONG virtual_memory;
} DRIVER_READMEMORY;


#pragma pack(1)
typedef struct {
	PVOID src;
	PVOID dst;
	ULONG_PTR length;
	ULONG pid;
} DRIVER_READMEMORY_PROCESS;

namespace drv
{
	HANDLE hDriver = 0;

	bool attach(void)
	{
		if (hDriver != 0)
		{
			return 1;
		}

		hDriver = CreateFileA("\\\\.\\memdriver", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		if (hDriver == INVALID_HANDLE_VALUE)
		{
			hDriver = 0;
		}

		return hDriver != 0;
	}

	BOOL memcpy(PVOID dst, PVOID src, SIZE_T length)
	{
		if (!drv::attach())
		{
			return 0;
		}
		DRIVER_READMEMORY io;
		io.src = src;
		io.dst = dst;
		io.length = length;
		io.virtual_memory = 1;
		return DeviceIoControl(hDriver, IOCTL_READMEMORY, &io, sizeof(io), &io, sizeof(io), 0, 0);
	}

	BOOL memcpy(DWORD pid, PVOID dst, PVOID src, SIZE_T length)
	{
		if (!drv::attach())
		{
			return 0;
		}
		DRIVER_READMEMORY_PROCESS io;
		io.src = src;
		io.dst = dst;
		io.length = length;
		io.pid = pid;
		return DeviceIoControl(hDriver, IOCTL_READMEMORY_PROCESS, &io, sizeof(io), &io, sizeof(io), 0, 0);
	}

	BOOL memcpy_physical(PVOID dst, PVOID src, SIZE_T length)
	{
		if (!drv::attach())
		{
			return 0;
		}
		DRIVER_READMEMORY io;
		io.src = src;
		io.dst = dst;
		io.length = length;
		io.virtual_memory = 0;
		return DeviceIoControl(hDriver, IOCTL_READMEMORY, &io, sizeof(io), &io, sizeof(io), 0, 0);
	}

	BOOL read(DWORD pid, ULONG_PTR address, PVOID buffer, QWORD length)
	{
		if (pid == 4)
			return drv::memcpy(buffer, (PVOID)address, length);
		else
			return drv::memcpy(pid, buffer, (PVOID)address, length);
	}

	BYTE read_i8(DWORD pid, ULONG_PTR address)
	{
		BYTE b;
		if (!drv::read(pid, address, &b, sizeof(b)))
		{
			b = 0;
		}
		return b;
	}

	WORD read_i16(DWORD pid, ULONG_PTR address)
	{
		WORD b;
		if (!drv::read(pid, address, &b, sizeof(b)))
		{
			b = 0;
		}
		return b;
	}

	DWORD read_i32(DWORD pid, ULONG_PTR address)
	{
		DWORD b;
		if (!drv::read(pid, address, &b, sizeof(b)))
		{
			b = 0;
		}
		return b;
	}

	QWORD read_i64(DWORD pid, ULONG_PTR address)
	{
		QWORD b;
		if (!drv::read(pid, address, &b, sizeof(b)))
		{
			b = 0;
		}
		return b;
	}
}

void scan_section(CHAR *section_name, QWORD local_image, QWORD runtime_image, QWORD size, QWORD section_address)
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

		if (cnt >= MIN_DIFFERENCE)
		{

			printf("%s:0x%llx is modified: ", section_name, section_address + i);

			for (DWORD j = 0; j < cnt; j++)
			{
				printf("%02X ", ((unsigned char*)local_image)[i + j]);
			}
			printf("-> ");

			for (DWORD j = 0; j < cnt; j++)
			{
				printf("%02X ", ((unsigned char*)runtime_image)[i + j]);
			}

			printf("\n");

		}

		i += cnt;	
	}
}

QWORD vm_dump_module_ex(DWORD pid, QWORD base, BOOL code_only)
{
	QWORD a0, a1, a2, a3 = 0;
	char *a4;

	a0 = base;
	if (a0 == 0)
		return 0;

	a1 = drv::read_i32(pid, a0 + 0x03C) + a0;
	if (a1 == a0)
	{
		return 0;
	}

	a2 = drv::read_i32(pid, a1 + 0x050);
	if (a2 < 8)
		return 0;

	a4 = (char *)malloc(a2+24);


	*(QWORD*)(a4)=base;
	*(QWORD*)(a4 + 8)=a2;
	*(QWORD*)(a4 + 16)=a3;

	a4 += 24;

	QWORD image_dos_header = base;
	QWORD image_nt_header = drv::read_i32(pid, image_dos_header + 0x03C) + image_dos_header;

	DWORD headers_size = drv::read_i32(pid, image_nt_header + 0x54);
	drv::read(pid, image_dos_header, a4, headers_size);

	unsigned short machine = drv::read_i16(pid, image_nt_header + 0x4);

	QWORD section_header = machine == 0x8664 ?
		image_nt_header + 0x0108 :
		image_nt_header + 0x00F8;

	
	for (WORD i = 0; i < drv::read_i16(pid, image_nt_header + 0x06); i++) {

		QWORD section = section_header + (i * 40);

		if (code_only)
		{
			DWORD section_characteristics = drv::read_i32(pid, section + 0x24);
			if (!(section_characteristics & 0x00000020))
				continue;

		}

		QWORD local_virtual_address = base + drv::read_i32(pid, section + 0x0c);
		DWORD local_virtual_size = drv::read_i32(pid, section + 0x8);
		QWORD target_virtual_address = (QWORD)a4 + drv::read_i32(pid, section + 0xc);
		drv::read(pid, local_virtual_address, (PVOID)target_virtual_address, local_virtual_size );
	}
	return (QWORD)a4;
}

void vm_free_module(QWORD dumped_module)
{
	dumped_module-=24;
	free((void *)dumped_module);
}

//
// implemented for x86 image load
//
HMODULE IMP_LoadLibraryEx(PCSTR path, DWORD a1, DWORD a2)
{
	(a1);
	(a2);

	VOID *ret = 0;

	FILE *f = fopen(path, "rb");
	if (f)
	{
		fseek(f, 0, SEEK_END);
		long len = ftell(f);
		fseek(f, 0, SEEK_SET);

		ret = malloc(len);

		if (fread(ret, len, 1, f) != 1)
		{
			free(ret);
			ret = 0;
		}

		fclose(f);
	}

	return (HMODULE)ret;
}

void IMP_FreeLibrary(HMODULE hMod)
{
	free(hMod);
}

void scan_image(DWORD pid, FILE_INFO file)
{
	HMODULE dll = (HMODULE)IMP_LoadLibraryEx(file.path.c_str(), 0, DONT_RESOLVE_DLL_REFERENCES);

	if (dll)
	{
		QWORD target_base = vm_dump_module_ex(pid, file.base, 1);

		if (target_base == 0 || *(WORD*)target_base != IMAGE_DOS_SIGNATURE)
		{
			FreeLibrary(dll);
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
			ULONG section_va = *(ULONG*)(section + 0x0C);
			ULONG section_pr = *(ULONG*)(section + 0x14);
			ULONG section_size = *(ULONG*)(section + 0x08);

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
					(CHAR*)section_name,
					(QWORD)((BYTE*)dll + section_pr),
					(QWORD)(target_base + section_va),
					section_size,
					section_va
				);
			}
		}

		vm_free_module(target_base);
		IMP_FreeLibrary(dll);
	} else {
		printf("failed to open %s\n", file.path.c_str());
	}
}

int main(void)
{
	std::vector<FILE_INFO> drivers = get_system_drivers();

	//
	// scan drivers
	// 
	for (auto driver : drivers)
	{
		//
		// system process id (4)
		//
		DWORD system_pid = 4;
		scan_image(system_pid, driver);
	}


	
	
	/*

	// 
	// you can uncomment this if you want to use it for process patch scanning (works both x86 and x64)
	// 

	DWORD pid=0;
	std::vector<FILE_INFO> modules = get_process_modules("explorer.exe", &pid);

	//
	// scan process modules
	//
	for (auto module : modules)
	{
		scan_image(pid, module);
	}

	*/
	
	

	getchar();

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

std::vector<FILE_INFO> get_system_drivers(void)
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

			
		if (sub_string)
		{
			std::string a0 = "C:\\Windows\\";
			std::string a1 = std::string(sub_string);

			std::string a2 = a0 + a1;


			FILE_INFO temp_information;
			temp_information.path = a2;
			temp_information.base = (QWORD)entry.ImageBase;
			temp_information.size = (QWORD)entry.ImageSize;


			driver_information.push_back(temp_information);
		}
	}
	
	VirtualFree(system_modules, 0, MEM_RELEASE);

	return driver_information;
}

#include <TlHelp32.h>


std::vector<FILE_INFO> get_process_modules(PCSTR process_name, DWORD *process_id)
{
	std::vector<FILE_INFO> info;

	DWORD pid = 0;

	HANDLE snp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(entry);

	while (Process32Next(snp, &entry))
	{
		if (!_strcmpi(entry.szExeFile, process_name))
		{
			pid = (DWORD)entry.th32ProcessID;
			break;
		}
	}

	CloseHandle(snp);


	if (pid == 0)
	{
		return info;
	}

	snp = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

	MODULEENTRY32 module_entry{};
	module_entry.dwSize = sizeof(module_entry);

	while (Module32Next(snp, &module_entry))
	{
		FILE_INFO temp;

		temp.base = (QWORD)module_entry.modBaseAddr;
		temp.size = module_entry.modBaseSize;
		temp.path = std::string(module_entry.szExePath);

		info.push_back(temp);
	}

	CloseHandle(snp);

	*process_id = pid;

	return info;
}

