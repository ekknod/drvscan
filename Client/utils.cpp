#define _CRT_SECURE_NO_WARNINGS
#include "utils.h"

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

static BOOL is_wow_64(PCSTR path)
{
	FILE *f = fopen(path, "rb");

	if (f == 0)
	{
		return 0;
	}

	char buffer[0x1000]{};
	fread(buffer, sizeof(buffer), 1, f);

	fclose(f);

	return pe::nt::is_wow64(pe::get_nt_headers((QWORD)buffer));
}

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

	BOOL wow64_process = is_wow_64(module_entry.szExePath);

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
	};

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

#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)

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

PVOID LoadImageEx(PCSTR path, DWORD *out_len, QWORD current_base)
{
	VOID *file_pe = LoadFileEx(path, out_len);

	if (file_pe == 0)
		return 0;

	if (*(WORD*)(file_pe) != IMAGE_DOS_SIGNATURE)
	{
		free(file_pe);
		return 0;
	}

	QWORD nt  = pe::get_nt_headers((QWORD)file_pe);
	QWORD opt = pe::nt::get_optional_header(nt);

	DWORD image_size = pe::optional::get_image_size(opt);

	if (out_len)
		*out_len = image_size;

	QWORD local_base = pe::optional::get_image_base(pe::nt::get_optional_header(nt));

	VOID *new_image = malloc(image_size);



	memcpy(
		new_image,
		file_pe,
		pe::optional::get_headers_size(opt)
		);

	PIMAGE_SECTION_HEADER section = pe::nt::get_image_sections(nt);

	for (WORD i = 0; i < pe::nt::get_section_count(nt); i++)
	{
		if (section[i].SizeOfRawData)
		{
			memcpy (
				(void *)((QWORD)new_image + section[i].VirtualAddress),
				(void *)((QWORD)file_pe   + section[i].PointerToRawData),
				section[i].SizeOfRawData
			);
		}
	}

	free( file_pe ) ;

	nt = pe::get_nt_headers((QWORD)new_image);


	opt = pe::nt::get_optional_header(nt);

	BYTE *delta = current_base != 0 ? (BYTE*)current_base - (QWORD)local_base : (BYTE*)(QWORD)new_image - (QWORD)local_base;

	if (!delta)
		return new_image;

	
	
	IMAGE_DATA_DIRECTORY *relocation = pe::optional::get_data_directory(opt, 5);

	if (!relocation->Size)
		return new_image;

	if (!relocation->VirtualAddress)
		return new_image;
	
	IMAGE_BASE_RELOCATION* pRelocData = (IMAGE_BASE_RELOCATION*)((QWORD)new_image + relocation->VirtualAddress);
	if (pRelocData->VirtualAddress == 0xcdcdcdcd)
		return new_image;

	if (pRelocData->VirtualAddress == 0)
		return new_image;

	const IMAGE_BASE_RELOCATION* pRelocEnd = (IMAGE_BASE_RELOCATION*)((QWORD)(pRelocData) + relocation->Size);
	while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock)
	{
		QWORD count = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(UINT16);

		UINT16* pRelativeInfo = (UINT16*)(pRelocData + 1);
		for (QWORD i = 0; i != count; ++i, ++pRelativeInfo)
		{
			if (RELOC_FLAG64(*pRelativeInfo))
			{
				QWORD* pPatch = (QWORD*)((BYTE*)new_image + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
				*pPatch += (QWORD)(delta);
			}
			else if (RELOC_FLAG32(*pRelativeInfo))
			{
				DWORD* pPatch = (DWORD*)((BYTE*)new_image + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
				*pPatch += (DWORD)(QWORD)(delta);
			}
		}
		pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)(pRelocData) + pRelocData->SizeOfBlock);
	}

	return new_image;
}

void FreeImageEx(PVOID ImageBase)
{
	if (ImageBase)
	{
		free(ImageBase);
	}
}


