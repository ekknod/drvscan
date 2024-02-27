#include "km.h"

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

NTOSKRNL_EXPORT(HalPrivateDispatchTable);
NTOSKRNL_EXPORT(PsInitialSystemProcess);
NTOSKRNL_EXPORT(PsGetProcessId);
NTOSKRNL_EXPORT(KeQueryPrcbAddress);
NTOSKRNL_EXPORT(HalEnumerateEnvironmentVariablesEx);
NTOSKRNL_EXPORT(MmGetVirtualForPhysical);

QWORD ntoskrnl_base;

namespace km
{
	HANDLE hDriver = 0;

	QWORD HalpPciMcfgTableCount;
	QWORD HalpPciMcfgTable;

	QWORD MmPfnDatabase;
	QWORD MmPteBase;

	namespace efi
	{
		static PVOID __get_memory_map(QWORD *size);
		static PVOID __get_memory_pages(QWORD* size);
	}
}

#pragma pack(push, 1)
typedef struct {
	PVOID address;
	PVOID buffer;
	ULONG_PTR length;
} DRIVER_READMEMORY;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	PVOID buffer;
	QWORD buffer_size;
} DRIVER_REQUEST_MAP;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	PVOID src;
	PVOID dst;
	ULONG_PTR length;
	ULONG pid;
} DRIVER_READMEMORY_PROCESS;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	PVOID InOutPhysical;
} DRIVER_GET_PHYSICAL;
#pragma pack(pop)

#define IOCTL_READMEMORY 0xECAC00
#define IOCTL_IO_READ 0xECAC02
#define IOCTL_IO_WRITE 0xECAC12
#define IOCTL_REQUEST_MMAP 0xECAC04
#define IOCTL_REQUEST_PAGES 0xECAC06
#define IOCTL_READMEMORY_PROCESS 0xECAC08
#define IOCTL_GET_PHYSICAL 0xECAC10

#pragma comment(lib, "ntdll.lib")
extern "C" __kernel_entry NTSYSCALLAPI NTSTATUS NtFreeVirtualMemory(
	HANDLE  ProcessHandle,
	PVOID   *BaseAddress,
	PSIZE_T RegionSize,
	ULONG   FreeType
);

static QWORD get_kernel_export(PCSTR export_name)
{
	HMODULE ntos = LoadLibraryA("ntoskrnl.exe");

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
	export_address = export_address + ntoskrnl_base;

cleanup:
	FreeLibrary(ntos);
	return export_address;
}

BOOL km::initialize(void)
{
	if (hDriver != 0)
	{
		return 1;
	}

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
		return 0;
	}

	for (auto &i : global_export_list)
	{
		QWORD temp = *(QWORD*)i;

		*(QWORD*)i = get_kernel_export((PCSTR)temp);
		if (*(QWORD*)i == 0)
		{
			printf("export %s not found\n", (PCSTR)temp);
			return 0;
		}
	}

	hDriver = CreateFileA("\\\\.\\drvscan", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
		hDriver = 0;
	}

	if (hDriver != 0)
	{
		//
		// resolve HalpPciMcfgTableCount/HalpPciMcfgTable addresses
		//
		QWORD table_entry = HalPrivateDispatchTable;
		table_entry       = vm::read<QWORD>(table_entry + 0xA0);
		table_entry       = table_entry + 0x1B;
		table_entry       = (table_entry + 5) + vm::read<INT>(table_entry + 1);
		while (1)
		{
			if (vm::read<BYTE>(table_entry) == 0xE8 && vm::read<WORD>(table_entry + 5) == 0xFB83)
			{
				break;
			}
			table_entry++;
		}
		table_entry = (table_entry + 5) + vm::read<INT>(table_entry + 1);
		while (1)
		{
			if (vm::read<DWORD>(table_entry) == 0xCCB70F41 && vm::read<BYTE>(table_entry + 4) == 0xE8)
			{
				table_entry += 0x04;
				break;
			}
			table_entry++;
		}
		table_entry = (table_entry + 5) + vm::read<INT>(table_entry + 1);
		table_entry = table_entry + 0x47;
		table_entry = (table_entry + 5) + vm::read<INT>(table_entry + 1);

		HalpPciMcfgTableCount = vm::get_relative_address(4, table_entry + 0x07, 2, 6);
		HalpPciMcfgTable      = vm::get_relative_address(4, table_entry + 0x11, 3, 7);

		MmPfnDatabase         = vm::read<QWORD>(MmGetVirtualForPhysical + 0x0E + 0x02);
		MmPteBase             = vm::read<QWORD>(MmGetVirtualForPhysical + 0x20 + 0x02);
	}

	return hDriver != 0;
}

BOOL km::vm::read(DWORD pid, QWORD address, PVOID buffer, QWORD length)
{
	if (!km::initialize())
	{
		return 0;
	}

	if (pid == 4 || pid == 0)
	{
		DRIVER_READMEMORY io{};
		io.address = (PVOID)address;

		PVOID tmp_buffer = (PVOID)malloc(length);

		io.buffer = tmp_buffer;
		io.length = length;

		BOOL status = DeviceIoControl(hDriver, IOCTL_READMEMORY, &io, sizeof(io), &io, sizeof(io), 0, 0);

		if (status)
		{
			memcpy(buffer, tmp_buffer, length);
		}
		else
		{
			memset(buffer, 0, length);
		}

		free(tmp_buffer);

		return status;
	}
	else
	{
		DRIVER_READMEMORY_PROCESS io{};
		io.src = (PVOID)address;

		PVOID tmp_buffer = (PVOID)malloc(length);

		io.dst = tmp_buffer;
		io.length = length;
		io.pid = pid;

		BOOL status = DeviceIoControl(hDriver, IOCTL_READMEMORY_PROCESS, &io, sizeof(io), &io, sizeof(io), 0, 0);

		if (status)
		{
			memcpy(buffer, tmp_buffer, length);
		}
		else
		{
			memset(buffer, 0, length);
		}

		free(tmp_buffer);

		return status;
	}
	return 0;
}

QWORD km::vm::get_physical_address(QWORD virtual_address)
{
	DRIVER_GET_PHYSICAL io{};
	io.InOutPhysical = (PVOID)&virtual_address;
	if (!DeviceIoControl(hDriver, IOCTL_GET_PHYSICAL, &io, sizeof(io), &io, sizeof(io), 0, 0))
		return 0;
	return virtual_address;
}

PVOID km::vm::dump_module(DWORD pid, QWORD base, DWORD dmp_type)
{
	if (base == 0)
	{
		return 0;
	}

	if (read<WORD>(base, pid) != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	QWORD nt_header = (QWORD)read<DWORD>(base + 0x03C, pid) + base;
	if (nt_header == base)
	{
		return 0;
	}

	DWORD image_size = read<DWORD>(nt_header + 0x050, pid);
	if (image_size == 0)
	{
		return 0;
	}

	BYTE* new_base = (BYTE*)malloc((QWORD)image_size + 16);
	if (new_base == 0)
		return 0;

	*(QWORD*)(new_base + 0) = base;
	*(QWORD*)(new_base + 8) = image_size;
	new_base += 16;
	memset(new_base, 0, image_size);

	DWORD headers_size = read<DWORD>(nt_header + 0x54, pid);
	vm::read(pid, base, new_base, headers_size);

	WORD machine = read<WORD>(nt_header + 0x4, pid);
	QWORD section_header = machine == 0x8664 ?
		nt_header + 0x0108 :
		nt_header + 0x00F8;


	for (WORD i = 0; i < read<WORD>(nt_header + 0x06, pid); i++) {
		QWORD section = section_header + ((QWORD)i * 40);

		DWORD section_characteristics = read<DWORD>(section + 0x24, pid);
		//
		// skip discardable memory
		//
		if ((section_characteristics & 0x02000000))
			continue;


		if (dmp_type & DMP_CODEONLY)
		{
			if (!(section_characteristics & 0x00000020))
				continue;
		}

		else if (dmp_type & DMP_READONLY)
		{
			if (!(section_characteristics & 0x40000000)) // IMAGE_SCN_MEM_READ
			{
				continue;
			}
			if ((section_characteristics & 0x80000000)) // IMAGE_SCN_MEM_WRITE
			{
				continue;
			}
			if ((section_characteristics & 0x20000000)) // IMAGE_SCN_MEM_EXECUTE
			{
				continue;
			}
			if ((section_characteristics & 0x02000000)) // IMAGE_SCN_MEM_DISCARDABLE
			{
				continue;
			}
		}
		QWORD target_address = (QWORD)new_base + km::vm::read<DWORD>(section + ((dmp_type & DMP_RAW) ? 0x14 : 0x0c), pid);
		QWORD virtual_address = base + (QWORD)read<DWORD>(section + 0x0C, pid);
		DWORD virtual_size = read<DWORD>(section + 0x08, pid);
		vm::read(pid, virtual_address, (PVOID)target_address, virtual_size);
	}
	return (PVOID)new_base;
}

void km::vm::free_module(PVOID dumped_module)
{
	if (dumped_module)
	{
		QWORD a0 = (QWORD)dumped_module;
		a0 -= 16;
		free((void*)a0);
	}
}

BOOL km::io::read(QWORD address, PVOID buffer, QWORD length)
{
	if (!km::initialize())
	{
		return 0;
	}
	DRIVER_READMEMORY io;
	io.address = (PVOID)address;
	io.buffer = buffer;
	io.length = length;
	return DeviceIoControl(hDriver, IOCTL_IO_READ, &io, sizeof(io), &io, sizeof(io), 0, 0);
}

BOOL km::io::write(QWORD address, PVOID buffer, QWORD length)
{
	if (!km::initialize())
	{
		return 0;
	}
	DRIVER_READMEMORY io;
	io.address = (PVOID)address;
	io.buffer = buffer;
	io.length = length;
	return DeviceIoControl(hDriver, IOCTL_IO_WRITE, &io, sizeof(io), &io, sizeof(io), 0, 0);
}

QWORD km::pci::get_physical_address(ULONG bus, ULONG slot)
{
	DWORD v3; // r10d
	unsigned __int8* i; // r9

	v3 = 0;

	QWORD table = vm::read<QWORD>(HalpPciMcfgTable);
	DWORD table_count = vm::read<DWORD>(HalpPciMcfgTableCount);

	if (!table)
		return 0i64;

	if (!table_count)
		return 0i64;

	for (i = (unsigned __int8*)(table + 54);

		(bus >> 8) != vm::read<WORD>((QWORD)(i - 1)) ||
		bus < vm::read<BYTE>((QWORD)i) ||
		bus > vm::read<BYTE>((QWORD)i + 1);

		i += 16
		)
	{
		if (++v3 >= (unsigned int)table_count)
			return 0i64;
	}
	return vm::read<QWORD>((QWORD)(i - 10)) + (((slot >> 5) + 8 * ((slot & 0x1F) + 32i64 * bus)) << 12);
}

BOOL km::pci::read(BYTE bus, BYTE slot, BYTE offset, PVOID buffer, QWORD size)
{
	QWORD device = get_physical_address(bus, slot);

	if (device == 0)
		return 0;

	return io::read(device + offset, buffer, size);
}

BOOL km::pci::write(BYTE bus, BYTE slot, BYTE offset, PVOID buffer, QWORD size)
{
	QWORD device = get_physical_address(bus, slot);

	if (device == 0)
		return 0;

	return io::write(device + offset, buffer, size);
}

static PVOID km::efi::__get_memory_map(QWORD* size)
{
	if (!km::initialize())
	{
		return 0;
	}

	PVOID buffer = 0;
	QWORD buffer_size = 0;
	DRIVER_REQUEST_MAP io{};

	io.buffer = (PVOID)&buffer;
	io.buffer_size = (QWORD)&buffer_size;

	if (!DeviceIoControl(hDriver, IOCTL_REQUEST_MMAP, &io, sizeof(io), &io, sizeof(io), 0, 0))
	{
		return 0;
	}

	*size = buffer_size;

	return buffer;
}

static PVOID km::efi::__get_memory_pages(QWORD* size)
{
	if (!km::initialize())
	{
		return 0;
	}

	PVOID buffer = 0;
	QWORD buffer_size = 0;
	DRIVER_REQUEST_MAP io{};

	io.buffer = (PVOID)&buffer;
	io.buffer_size = (QWORD)&buffer_size;

	if (!DeviceIoControl(hDriver, IOCTL_REQUEST_PAGES, &io, sizeof(io), &io, sizeof(io), 0, 0))
	{
		return 0;
	}

	*size = buffer_size;

	return buffer;
}

std::vector<EFI_PAGE_TABLE_ALLOCATION> km::efi::get_page_table_allocations()
{
	std::vector<EFI_PAGE_TABLE_ALLOCATION> table;


	QWORD efi_page_table_size = 0;
	PVOID efi_page_tables = km::efi::__get_memory_pages(&efi_page_table_size);

	for (DWORD i = 0; i < *(DWORD*)efi_page_tables; i++)
	{
		QWORD temp = ((QWORD)efi_page_tables + (i * 16)) + 0x04;
		QWORD address = *(QWORD*)((QWORD)temp + 0x00);
		QWORD page_cnt = *(QWORD*)((QWORD)temp + 0x08);

		table.push_back({ address, page_cnt });
	}

	NtFreeVirtualMemory(GetCurrentProcess(), &efi_page_tables, &efi_page_table_size, MEM_RELEASE);

	return table;
}

std::vector<EFI_MEMORY_DESCRIPTOR> km::efi::get_memory_map()
{
	std::vector<EFI_MEMORY_DESCRIPTOR> table;


	QWORD memory_map_size = 0;
	PVOID memory_map = km::efi::__get_memory_map(&memory_map_size);

	DWORD descriptor_size = sizeof(EFI_MEMORY_DESCRIPTOR) + 0x08;
	QWORD descriptor_count = memory_map_size / descriptor_size;

	for (QWORD i = 0; i < descriptor_count; i++)
	{
		EFI_MEMORY_DESCRIPTOR* entry =
			(EFI_MEMORY_DESCRIPTOR*)((char*)memory_map + (i * descriptor_size));

		table.push_back(*entry);
	}

	NtFreeVirtualMemory(GetCurrentProcess(), &memory_map, &memory_map_size, MEM_RELEASE);

	return table;
}

std::vector<EFI_MODULE_INFO> km::efi::get_dxe_modules(std::vector<EFI_MEMORY_DESCRIPTOR>& memory_map)
{
	std::vector<EFI_MODULE_INFO> modules;

	for (auto& page : memory_map)
	{
		if (page.Type != 5)
		{
			continue;
		}

		if (modules.size())
		{
			break;
		}

		for (DWORD page_num = 0; page_num < page.NumberOfPages; page_num++)
		{
			QWORD module_base = page.VirtualStart + (page_num * 0x1000);
			if (vm::read<WORD>(module_base) == IMAGE_DOS_SIGNATURE)
			{
				QWORD nt = vm::read<DWORD>(module_base + 0x03C) + module_base;
				if (vm::read<WORD>(nt) != IMAGE_NT_SIGNATURE)
				{
					continue;
				}
				QWORD module_base_phys = page.PhysicalStart + (page_num * 0x1000);
				modules.push_back({ module_base, module_base_phys, vm::read<DWORD>(nt + 0x050) });
			}
		}

		if (modules.size() < 4)
		{
			modules.clear();
		}
	}

	return modules;
}

EFI_PAGE_TABLE_ALLOCATION km::efi::get_dxe_range(
	EFI_MODULE_INFO module,
	std::vector<EFI_PAGE_TABLE_ALLOCATION>& page_table_list
)
{
	for (auto& ptentry : page_table_list)
	{
		if (module.physical_address >= ptentry.PhysicalStart &&
			module.physical_address <= (ptentry.PhysicalStart + (ptentry.NumberOfPages * 0x1000)))
		{
			return ptentry;
		}
	}
	return {};
}

std::vector<QWORD> km::efi::get_runtime_table(void)
{
	QWORD HalEfiRuntimeServicesTableAddr = km::vm::get_relative_address(4, HalEnumerateEnvironmentVariablesEx + 0xC, 1, 5);
	HalEfiRuntimeServicesTableAddr       = km::vm::get_relative_address(4, HalEfiRuntimeServicesTableAddr + 0x69, 3, 7);
	HalEfiRuntimeServicesTableAddr       = km::vm::read<QWORD>(HalEfiRuntimeServicesTableAddr);
	if (!HalEfiRuntimeServicesTableAddr)
	{
		return {};
	}

	QWORD HalEfiRuntimeServicesTable[9];
	km::vm::read(4, HalEfiRuntimeServicesTableAddr, &HalEfiRuntimeServicesTable, sizeof(HalEfiRuntimeServicesTable));

	std::vector<QWORD> table{};
	for (int i = 9; i--;)
		table.push_back(HalEfiRuntimeServicesTable[i]);

	return table;
}

