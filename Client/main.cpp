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

typedef ULONG_PTR QWORD;

typedef struct {
	std::string path;
	QWORD       base;
	QWORD       size;
} DRIVER_INFO ;

std::vector<DRIVER_INFO> get_system_drivers(void);

#pragma pack(1)
typedef struct {
	PVOID src;
	PVOID dst;
	SIZE_T length;
	ULONG virtual_memory;
} DRIVER_READMEMORY;

class Driver
{
	HANDLE hDriver;
public:
	Driver(void)
	{
		hDriver = CreateFileA("\\\\.\\memdriver", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);


		if (hDriver == INVALID_HANDLE_VALUE)
		{
			hDriver = 0;
		}
	}
	~Driver(void)
	{
	}

	BOOL memcpy(PVOID dst, PVOID src, SIZE_T length)
	{
		if (!Attach())
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

	BOOL memcpy_physical(PVOID dst, PVOID src, SIZE_T length)
	{
		if (!Attach())
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

	BOOL read(ULONG_PTR address, PVOID buffer, QWORD length)
	{
		return this->memcpy(buffer, (PVOID)address, length);
	}

	BYTE read_i8(ULONG_PTR address)
	{
		BYTE b;
		if (!this->memcpy(&b, (PVOID)address, sizeof(b)))
		{
			b = 0;
		}
		return b;
	}

	WORD read_i16(ULONG_PTR address)
	{
		WORD b;
		if (!this->memcpy(&b, (PVOID)address, sizeof(b)))
		{
			b = 0;
		}
		return b;
	}

	DWORD read_i32(ULONG_PTR address)
	{
		DWORD b;
		if (!this->memcpy(&b, (PVOID)address, sizeof(b)))
		{
			b = 0;
		}
		return b;
	}

	QWORD read_i64(ULONG_PTR address)
	{
		QWORD b;
		if (!this->memcpy(&b, (PVOID)address, sizeof(b)))
		{
			b = 0;
		}
		return b;
	}

private:
	bool Attach(void)
	{
		if (hDriver != 0)
		{
			return 1;
		}

		hDriver = CreateFileA("\\\\.\\anticheat", GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		if (hDriver == INVALID_HANDLE_VALUE)
		{
			hDriver = 0;
		}

		return hDriver != 0;
	}

};

Driver drv = Driver();

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

QWORD vm_dump_module_ex(QWORD base, BOOL code_only)
{
	QWORD a0, a1, a2, a3 = 0;
	char *a4;

	a0 = base;
	if (a0 == 0)
		return 0;

	a1 = drv.read_i32(a0 + 0x03C) + a0;
	if (a1 == a0)
	{
		return 0;
	}

	a2 = drv.read_i32(a1 + 0x050);
	if (a2 < 8)
		return 0;

	a4 = (char *)malloc(a2+24);


	*(QWORD*)(a4)=base;
	*(QWORD*)(a4 + 8)=a2;
	*(QWORD*)(a4 + 16)=a3;

	a4 += 24;

	QWORD image_dos_header = base;
	QWORD image_nt_header = drv.read_i32(image_dos_header + 0x03C) + image_dos_header;

	DWORD headers_size = drv.read_i32(image_nt_header + 0x54);
	drv.read(image_dos_header, a4, headers_size);

	unsigned short machine = drv.read_i16(image_nt_header + 0x4);

	QWORD section_header = machine == 0x8664 ?
		image_nt_header + 0x0108 :
		image_nt_header + 0x00F8;

	
	for (WORD i = 0; i < drv.read_i16(image_nt_header + 0x06); i++) {

		QWORD section = section_header + (i * 40);

		if (code_only)
		{
			DWORD section_characteristics = drv.read_i32(section + 0x24);
			if (!(section_characteristics & 0x00000020))
				continue;

		}

		QWORD local_virtual_address = base + drv.read_i32(section + 0x0c);
		DWORD local_virtual_size = drv.read_i32(section + 0x8);
		QWORD target_virtual_address = (QWORD)a4 + drv.read_i32(section + 0xc);
		drv.read( local_virtual_address, (PVOID)target_virtual_address, local_virtual_size );
	}
	return (QWORD)a4;
}

void vm_free_module(QWORD dumped_module)
{
	dumped_module-=24;
	free((void *)dumped_module);
}

int main(void)
{

	std::vector<DRIVER_INFO> drivers = get_system_drivers();

	for (auto driver : drivers)
	{
		HMODULE dll = (HMODULE)LoadLibraryExA(driver.path.c_str(), 0, DONT_RESOLVE_DLL_REFERENCES);
		if (dll)
		{
			QWORD target_base = vm_dump_module_ex(driver.base, 1);

			if (target_base == 0 || *(WORD*)target_base != IMAGE_DOS_SIGNATURE)
			{
				FreeLibrary(dll);
				vm_free_module(target_base);
				continue;
			}
	
			printf("scanning image: %s\n", driver.path.c_str());

			IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)dll;
			IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)((char*)dll + dos->e_lfanew);

			IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt);
			for (QWORD i = 0; i != nt->FileHeader.NumberOfSections; ++i, ++section_header) {
				if (section_header->Characteristics & 0x00000020 && !(section_header->Characteristics & 0x02000000))
				{
					//
					// skip Warbird page
					//
					if (!strcmp((const char*)section_header->Name, "PAGEwx3"))
					{
						continue;
					}
		
					scan_section( (CHAR*)section_header->Name, (QWORD)((BYTE*)dll + section_header->VirtualAddress), (QWORD)(target_base + section_header->VirtualAddress), section_header->Misc.VirtualSize, section_header->VirtualAddress  );			
				}
			}

			vm_free_module(target_base);
			FreeLibrary(dll);
		} else {
			printf("failed to open %s\n",driver.path.c_str());
		}
	}

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

std::vector<DRIVER_INFO> get_system_drivers(void)
{
	std::vector<DRIVER_INFO> driver_information;


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


			DRIVER_INFO temp_information;
			temp_information.path = a2;
			temp_information.base = (QWORD)entry.ImageBase;
			temp_information.size = (QWORD)entry.ImageSize;


			driver_information.push_back(temp_information);
		}
	}
	
	VirtualFree(system_modules, 0, MEM_RELEASE);

	return driver_information;
}

