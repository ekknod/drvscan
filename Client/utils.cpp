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

	BOOL wow64_process = 0;
	BOOL wow64_test = 0;
	
	while(Module32Next(snp, &module_entry))
	{
		if (wow64_test == 0)
		{
			wow64_process = is_wow_64(module_entry.szExePath);
			wow64_test    = 1;
		}

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
	} ;

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
			process_info.push_back({entry.th32ProcessID, entry.szExeFile, get_kernel_modules()});
		else
			process_info.push_back({entry.th32ProcessID, entry.szExeFile, get_user_modules(entry.th32ProcessID)});
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

		/*
		for (int i = 0; i < len; i++)
		{
			if (fread((void *)((char*)ret + i), 1, 1, f) != 1)
			{
				free(ret);
				ret = 0;
			}
		}
		*/
		
		if (fread(ret, len, 1, f) != 1)
		{
			free(ret);
			ret = 0;
		}
		

		fclose(f);
	}

	return (PVOID)ret;
}

//
// https://github.com/mrexodia/portable-executable-library/blob/master/pe_lib/pe_checksum.cpp
//
uint32_t calculate_checksum(PVOID file, DWORD file_size)
{
	//Checksum value
	unsigned long long checksum = 0;

	//Read DOS header
	IMAGE_DOS_HEADER* header = (IMAGE_DOS_HEADER*)file;

	//Calculate PE checksum
	unsigned long long top = 0xFFFFFFFF;
	top++;

	//"CheckSum" field position in optional PE headers - it's always 64 for PE and PE+
	static const unsigned long checksum_pos_in_optional_headers = 64;
	//Calculate real PE headers "CheckSum" field position
	//Sum is safe here
	unsigned long pe_checksum_pos = header->e_lfanew + sizeof(IMAGE_FILE_HEADER) + sizeof(uint32_t) + checksum_pos_in_optional_headers;

	//Calculate checksum for each byte of file

	for (long long i = 0; i < file_size; i += 4)
	{
		unsigned long dw = *(unsigned long*)((char*)file + i);
		//Skip "CheckSum" DWORD
		if (i == pe_checksum_pos)
			continue;

		//Calculate checksum
		checksum = (checksum & 0xffffffff) + dw + (checksum >> 32);
		if (checksum > top)
			checksum = (checksum & 0xffffffff) + (checksum >> 32);
	}

	//Finish checksum
	checksum = (checksum & 0xffff) + (checksum >> 16);
	checksum = (checksum)+(checksum >> 16);
	checksum = checksum & 0xffff;

	checksum += static_cast<unsigned long>(file_size);
	return static_cast<uint32_t>(checksum);
}

PVOID LoadImageEx(PCSTR path, DWORD* out_len, QWORD current_base, QWORD memory_image)
{
	DWORD size    = 0;
	VOID* file_pe = LoadFileEx(path, &size);

	if (file_pe == 0)
		return 0;

	if (*(WORD*)(file_pe) != IMAGE_DOS_SIGNATURE)
	{
		free(file_pe);
		return 0;
	}

	QWORD nt  = pe::get_nt_headers((QWORD)file_pe);
	QWORD opt = pe::nt::get_optional_header(nt);
	DWORD sum = pe::optional::get_checksum(opt);

	//
	// savecache/usecache
	//
	if (sum && size != pe::optional::get_image_size(opt))
	{
		DWORD checksum = calculate_checksum(file_pe, size);
		if (sum != checksum)
		{
			printf("\ninvalid checksum: %s %lx, %lx\n\n", path, sum, checksum);
		}
	}

	DWORD image_size = pe::optional::get_image_size(opt);

	if (out_len)
		*out_len = image_size;

	QWORD local_base = pe::optional::get_image_base(pe::nt::get_optional_header(nt));

	VOID* new_image = malloc(image_size);

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
			memcpy(
				(void*)((QWORD)new_image + section[i].VirtualAddress),
				(void*)((QWORD)file_pe + section[i].PointerToRawData),
				section[i].SizeOfRawData
			);
		}
	}

	free(file_pe);

	nt = pe::get_nt_headers((QWORD)new_image);
	opt = pe::nt::get_optional_header(nt);

	BYTE* delta = current_base != 0 ? (BYTE*)current_base - (QWORD)local_base : (BYTE*)(QWORD)new_image - (QWORD)local_base;

	if (!delta)
		return new_image;



	IMAGE_DATA_DIRECTORY* relocation = pe::optional::get_data_directory(opt, 5);

	if (!relocation->Size)
		return new_image;

	if (!relocation->VirtualAddress)
		return new_image;

	IMAGE_BASE_RELOCATION* pRelocData = (IMAGE_BASE_RELOCATION*)((QWORD)new_image + relocation->VirtualAddress);
	if (pRelocData->VirtualAddress == 0)
		return new_image;

	const IMAGE_BASE_RELOCATION* pRelocEnd = (IMAGE_BASE_RELOCATION*)((QWORD)(pRelocData)+relocation->Size);
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
		pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)(pRelocData)+pRelocData->SizeOfBlock);
	}

	//
	// https://denuvosoftwaresolutions.github.io/DVRT/dvrt.html
	//
	IMAGE_DATA_DIRECTORY* data_dir = (IMAGE_DATA_DIRECTORY*)pe::optional::get_data_directory(opt, 10);

	if (data_dir->VirtualAddress == 0 || data_dir->Size < 0x108 || data_dir->VirtualAddress > image_size)
		return new_image;

	IMAGE_LOAD_CONFIG_DIRECTORY* dir = (IMAGE_LOAD_CONFIG_DIRECTORY*)((QWORD)new_image + data_dir->VirtualAddress);
	if (dir->Size != data_dir->Size)
		return new_image;
		
	if (dir->DynamicValueRelocTableOffset == 0)
		return new_image;

	typedef struct
	{
		uint32_t version;
		uint32_t size;
	} ImageDynamicRelocationTable;

#pragma pack(push, 1)
	typedef struct
	{
		uint64_t symbol;
		uint32_t baseRelocSize;
	} ImageDynamicRelocation;
#pragma pack(pop)

	typedef struct
	{
		uint32_t virtualAddress;
		uint32_t sizeOfBlock;
	} PEBaseRelocation;



	union ImageSwitchtableBranchDynamicRelocation
	{
		struct Parts
		{
			uint16_t pageRelativeOffset : 12;
			uint16_t registerNumber : 4;
		};
		Parts asParts;
		uint16_t asNumber;
	};

	union ImageIndirControlTransferDynamicRelocation
	{
		struct Parts
		{
			uint16_t pageRelativeOffset : 12;
			uint16_t isCall : 1;
			uint16_t rexWPrefix : 1;
			uint16_t cfgCheck : 1;
			uint16_t reserved : 1;
		};

		Parts asParts;
		uint16_t asNumber;
	};

	union ImageImportControlTransferDynamicRelocation
	{
		struct Parts
		{
			uint32_t pageRelativeOffset : 12;
			uint32_t isCall : 1;
			uint32_t iatIndex : 19;
		};
		Parts asParts;
		uint32_t asNumber;
	};

	ImageDynamicRelocationTable* tbl = (ImageDynamicRelocationTable*)(
		(QWORD)new_image +
		relocation->VirtualAddress +
		dir->DynamicValueRelocTableOffset);

	ImageDynamicRelocation* reloc_data = (ImageDynamicRelocation*)(tbl + 1);
	ImageDynamicRelocation* reloc_data_end = (ImageDynamicRelocation*)((char*)tbl + tbl->size);
	while (reloc_data < reloc_data_end)
	{
		if (reloc_data->symbol == 0)
		{
			break;
		}
		else if (reloc_data->symbol == 7)
		{
		}
		else if (reloc_data->symbol == 5)
		{
			PEBaseRelocation* base_reloc = (PEBaseRelocation*)(reloc_data + 1);
			PEBaseRelocation* base_reloc_end = (PEBaseRelocation*)((char*)base_reloc + reloc_data->baseRelocSize);
			while (base_reloc < base_reloc_end)
			{
				if (base_reloc->virtualAddress == 0)
					break;

				ImageSwitchtableBranchDynamicRelocation* data =
					(ImageSwitchtableBranchDynamicRelocation*)(base_reloc + 1);

				ImageSwitchtableBranchDynamicRelocation* data_end =
					(ImageSwitchtableBranchDynamicRelocation*)((char*)base_reloc + base_reloc->sizeOfBlock);

				while (data < data_end)
				{
					QWORD rip = (QWORD)new_image + base_reloc->virtualAddress + data->asParts.pageRelativeOffset;
					QWORD dva = (QWORD)memory_image + base_reloc->virtualAddress + data->asParts.pageRelativeOffset;
					memcpy((void*)rip, (const void*)dva, 5);
					data++;
				}
				base_reloc = (PEBaseRelocation*)((char*)base_reloc + base_reloc->sizeOfBlock);
			}
		}
		else if (reloc_data->symbol == 4)
		{
			PEBaseRelocation* base_reloc = (PEBaseRelocation*)(reloc_data + 1);
			PEBaseRelocation* base_reloc_end = (PEBaseRelocation*)((char*)base_reloc + reloc_data->baseRelocSize);
			while (base_reloc < base_reloc_end)
			{
				if (base_reloc->virtualAddress == 0 || base_reloc->sizeOfBlock == 0)
					break;
				ImageIndirControlTransferDynamicRelocation* data =
					(ImageIndirControlTransferDynamicRelocation*)(base_reloc + 1);

				ImageIndirControlTransferDynamicRelocation* data_end =
					(ImageIndirControlTransferDynamicRelocation*)((char*)base_reloc + base_reloc->sizeOfBlock);

				while (data < data_end)
				{
					QWORD rip = (QWORD)new_image + base_reloc->virtualAddress + data->asParts.pageRelativeOffset;
					QWORD dva = (QWORD)memory_image + base_reloc->virtualAddress + data->asParts.pageRelativeOffset;
					memcpy((void*)rip, (const void*)dva, 6);
					data++;
				}
				base_reloc = (PEBaseRelocation*)((char*)base_reloc + base_reloc->sizeOfBlock);
			}
		}
		else if (reloc_data->symbol == 3)
		{
			PEBaseRelocation* base_reloc = (PEBaseRelocation*)(reloc_data + 1);
			PEBaseRelocation* base_reloc_end = (PEBaseRelocation*)((char*)base_reloc + reloc_data->baseRelocSize);
			while (base_reloc < base_reloc_end)
			{
				if (base_reloc->virtualAddress == 0 || base_reloc->sizeOfBlock == 0)
					break;
				ImageImportControlTransferDynamicRelocation* data =
					(ImageImportControlTransferDynamicRelocation*)(base_reloc + 1);

				ImageImportControlTransferDynamicRelocation* data_end =
					(ImageImportControlTransferDynamicRelocation*)((char*)data + base_reloc->sizeOfBlock);

				while (data < data_end)
				{
					QWORD rip = (QWORD)new_image + base_reloc->virtualAddress + data->asParts.pageRelativeOffset;
					QWORD dva = (QWORD)memory_image + base_reloc->virtualAddress + data->asParts.pageRelativeOffset;
					memcpy((void*)rip, (const void*)dva, 12);
					data++;
				}
				base_reloc = (PEBaseRelocation*)((char*)base_reloc + base_reloc->sizeOfBlock);
			}
		}
		else
		{
			PEBaseRelocation* base_reloc = (PEBaseRelocation*)(reloc_data + 1);
			PEBaseRelocation* base_reloc_end = (PEBaseRelocation*)((char*)base_reloc + reloc_data->baseRelocSize);

			while (base_reloc < base_reloc_end)
			{
				if (base_reloc->virtualAddress == 0 || base_reloc->sizeOfBlock == 0)
					break;
				WORD* data = (WORD*)(base_reloc + 1);
				WORD* data_end = (WORD*)((char*)base_reloc + base_reloc->sizeOfBlock);
				while (data < data_end)
				{
					*(QWORD*)((QWORD)new_image + base_reloc->virtualAddress + *data)
						=
						*(QWORD*)((QWORD)memory_image + base_reloc->virtualAddress + *data);

					data++;
				}
				base_reloc = (PEBaseRelocation*)((char*)base_reloc + base_reloc->sizeOfBlock);
			}
		}
		reloc_data = (ImageDynamicRelocation*)((BYTE*)(reloc_data)+reloc_data->baseRelocSize
			+ sizeof(ImageDynamicRelocation)
			);
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

#include <setupapi.h>
#include <devpkey.h>
#pragma comment(lib, "SetupAPI.lib")

const DEVPROPKEY DEVPKEY_Device_InstanceId = {
0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57, 256 }; // DEVPROP_TYPE_UINT32

inline void convert_location(PCSTR location_str, unsigned char *bus, unsigned char *slot, unsigned char *func)
{
	*bus = 0; *slot = 0; *func = 0;

	while (1)
	{
		if (*location_str == 0)
			return;

		if ((*location_str >= '0') && (*location_str <= '9'))
			break;

		location_str++;
	}

	*bus = (BYTE)atoi(location_str);

	location_str = strchr(location_str, ' ') + 1;
	if (location_str == (PCSTR)1) return;

	if (location_str && (location_str = strchr(location_str, ' ')))
	{
		location_str = location_str + 1;
		*slot = (BYTE)atoi(location_str);
	}

	location_str = strchr(location_str, ' ') + 1;
	if (location_str == (PCSTR)1) return;

	if (location_str && (location_str = strchr(location_str, ' ')))
	{
		location_str = location_str + 1;
		*func = (BYTE)atoi(location_str);
	}
}

std::vector<PNP_ADAPTER> get_pnp_adapters()
{
	std::vector<PNP_ADAPTER> adapters{};

	HDEVINFO device_info = SetupDiGetClassDevs(NULL, TEXT("PCI"), NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);	

	int i = 0;
	while (1)
	{
		SP_DEVINFO_DATA data{};
		CHAR buffer[1024]{};
		DWORD len, data_type;


		data.cbSize = sizeof(data);

		//
		// get device info by index
		//
		if (!SetupDiEnumDeviceInfo(device_info, i, &data))
		{
			break;
		}

		SetupDiGetDeviceRegistryProperty(device_info, &data, SPDRP_LOCATION_INFORMATION, &data_type, (BYTE*)buffer, sizeof(buffer), &len);

		unsigned char bus,slot,func;
		convert_location(buffer, &bus, &slot, &func);

		SetupDiGetDevicePropertyW(device_info, &data, &DEVPKEY_Device_InstanceId, &data_type, (BYTE*)buffer, sizeof(buffer), &len, 0);

		
		std::string pnp_id;
		wchar_t *buf_ptr = (wchar_t*)buffer;
		for (DWORD j = 0; j < len / 2; j++)
		{
			pnp_id.push_back( (char)buf_ptr[j] );
		}


		PNP_ADAPTER adapter{};
		adapter.bus           = bus;
		adapter.slot          = slot;
		adapter.func          = func;
		adapter.pnp_id        = pnp_id;
		adapters.push_back(adapter);

		i++;
	}

	//
	// free system resources
	//
	SetupDiDestroyDeviceInfoList(device_info);


	return adapters;
}

#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

namespace wmi
{
	IWbemServices *svc = NULL;

	static void initialize(void);
}

static void wmi::initialize(void)
{
	static BOOL initialized = 0;
	if (initialized == 0)
	{
		CoInitializeEx(0, COINIT_MULTITHREADED);
		CoInitializeSecurity(
			NULL,
			-1,                          // COM authentication
			NULL,                        // Authentication services
			NULL,                        // Reserved
			RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
			RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
			NULL,                        // Authentication info
			EOAC_NONE,                   // Additional capabilities
			NULL                         // Reserved
		);

		IWbemLocator* pLoc = NULL;

		CoCreateInstance(
			CLSID_WbemLocator,
			0,
			CLSCTX_INPROC_SERVER,
			IID_IWbemLocator, (LPVOID*)&pLoc);

		// Connect to the root\cimv2 namespace with
		// the current user and obtain pointer pSvc
		// to make IWbemServices calls.
		pLoc->ConnectServer(
			_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
			NULL,                    // User name. NULL = current user
			NULL,                    // User password. NULL = current
			0,                       // Locale. NULL indicates current
			NULL,                    // Security flags.
			0,                       // Authority (for example, Kerberos)
			0,                       // Context object
			&svc                     // pointer to IWbemServices proxy
		);


		CoSetProxyBlanket(
			svc,                        // Indicates the proxy to set
			RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
			RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
			NULL,                        // Server principal name
			RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
			RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
			NULL,                        // client identity
			EOAC_NONE                    // proxy capabilities
		);

		initialized = 1;
	}
}

QWORD wmi::open_table(PCSTR name)
{
	//
	// init server
	//
	initialize();


	IEnumWbemClassObject* table = NULL;
	HRESULT res = svc->ExecQuery(
		bstr_t("WQL"),
		bstr_t(name),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&table);

	if (FAILED(res))
	{
		return 0;
	}

	return (QWORD)table;
}

void  wmi::close_table(QWORD table)
{
	if (table)
		((IEnumWbemClassObject*)table)->Release();
}

QWORD wmi::next_entry(QWORD table, QWORD prev)
{
	if (table == 0)
	{
		return 0;
	}

	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;
	IEnumWbemClassObject* pEnumerator = (IEnumWbemClassObject *)table;

	if (prev)
	{
		IWbemClassObject *pclsObj = (IWbemClassObject *)prev;
		pclsObj->Release();
	}
	else
	{
		pEnumerator->Reset();
	}

	pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
	if (0 == uReturn)
	{
		return 0;
	}
	return (QWORD)pclsObj;
}

std::string wmi::get_string(QWORD table_entry, PCSTR value)
{
	std::string res{};


	wchar_t prop_name[260]{};
	for (size_t i = strlen(value); i--;)
	{
		prop_name[i] = value[i];
	}


	IWbemClassObject *pclsObj = (IWbemClassObject *)table_entry;


	VARIANT vtProp;
	VariantInit(&vtProp);
	if (pclsObj->Get(prop_name, 0, &vtProp, 0, 0) == 0)
	{
		std::wstring ws(vtProp.bstrVal);
		for (size_t i = 0; i < ws.size(); i++)
		{
			res.push_back((const char)ws[i]);
		}
	}
	VariantClear(&vtProp);
	return res;
}

int wmi::get_int(QWORD table_entry, PCSTR value)
{
	int res = 0;

	wchar_t prop_name[260]{};
	for (size_t i = strlen(value); i--;)
	{
		prop_name[i] = value[i];
	}

	IWbemClassObject *pclsObj = (IWbemClassObject *)table_entry;

	VARIANT vtProp;
	VariantInit(&vtProp);
	if (pclsObj->Get(prop_name, 0, &vtProp, 0, 0) == 0)
	{
		res = vtProp.intVal;
	}
	VariantClear(&vtProp);
	return res;
}

bool wmi::get_bool(QWORD table_entry, PCSTR value)
{
	short res = 0;

	wchar_t prop_name[260]{};
	for (size_t i = strlen(value); i--;)
	{
		prop_name[i] = value[i];
	}

	IWbemClassObject *pclsObj = (IWbemClassObject *)table_entry;

	VARIANT vtProp;
	VariantInit(&vtProp);
	if (pclsObj->Get(prop_name, 0, &vtProp, 0, 0) == 0)
	{
		res = vtProp.boolVal;
	}
	VariantClear(&vtProp);
	return res!=0;
}
