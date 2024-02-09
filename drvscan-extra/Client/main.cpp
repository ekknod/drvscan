#define _CRT_SECURE_NO_WARNINGS

/*
 * handy tool for testing
 */

#include <windows.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
#include <stdlib.h>
#include <TlHelp32.h>

#define IOCTL_READMEMORY 0xECAC00
#define IOCTL_IO_READ 0xECAC02
#define IOCTL_REQUEST_MMAP 0xECAC04
#define IOCTL_REQUEST_PAGES 0xECAC06

#define DEBUG
#define LOG(...) printf("[Client.exe] "  __VA_ARGS__)
#ifdef DEBUG
#define DEBUG_LOG(...) printf("[Client.exe] " __VA_ARGS__)
#else
#define DEBUG_LOG(...) // __VA_ARGS__
#endif

typedef ULONG_PTR QWORD;
#pragma pack(1)
typedef struct {
	PVOID address;
	PVOID buffer;
	QWORD length;
} DRIVER_READMEMORY;

#pragma pack(1)
typedef struct {
	PVOID *buffer;
	QWORD *buffer_size;
} DRIVER_REQUEST_MAP;

typedef struct {
  QWORD                Type;
  QWORD                 PhysicalStart;
  QWORD                 VirtualStart;
  UINT64                NumberOfPages;
  UINT64                Attribute;
} EFI_MEMORY_DESCRIPTOR;

typedef struct
{
	QWORD PhysicalStart;
	QWORD NumberOfPages;
} EFI_PAGE_TABLE_ALLOCATION;

typedef struct {
	QWORD                  virtual_address;
	QWORD                  physical_address;
	DWORD                  size;
} EFI_MODULE_INFO;

#pragma comment(lib, "ntdll.lib")
extern "C" __kernel_entry NTSYSCALLAPI NTSTATUS NtFreeVirtualMemory(
	HANDLE  ProcessHandle,
	PVOID   *BaseAddress,
	PSIZE_T RegionSize,
	ULONG   FreeType
);

namespace km
{
	HANDLE hDriver = 0;

	static bool initialize(void)
	{
		if (hDriver != 0)
		{
			return 1;
		}

		hDriver = CreateFileA("\\\\.\\acdriver", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		if (hDriver == INVALID_HANDLE_VALUE)
		{
			hDriver = 0;
		}

		return hDriver != 0;
	}


	namespace vm
	{
		static BOOL read(ULONG_PTR address, PVOID buffer, QWORD length)
		{
			if (!km::initialize())
			{
				return 0;
			}
			DRIVER_READMEMORY io;
			io.address = (PVOID)address;
			io.buffer = buffer;
			io.length = length;
			return DeviceIoControl(hDriver, IOCTL_READMEMORY, &io, sizeof(io), &io, sizeof(io), 0, 0);
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
		static BOOL read(ULONG_PTR address, PVOID buffer, QWORD length)
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

	namespace efi
	{
		static PVOID __get_memory_map(QWORD *size)
		{
			if (!km::initialize())
			{
				return 0;
			}

			PVOID buffer=0;
			QWORD buffer_size=0;
			DRIVER_REQUEST_MAP io{};

			io.buffer = &buffer;
			io.buffer_size = &buffer_size;

			if (!DeviceIoControl(hDriver, IOCTL_REQUEST_MMAP, &io, sizeof(io), &io, sizeof(io), 0, 0))
			{
				return 0;
			}

			*size = buffer_size;

			return buffer;
		}

		static PVOID __get_memory_pages(QWORD *size)
		{
			if (!km::initialize())
			{
				return 0;
			}

			PVOID buffer=0;
			QWORD buffer_size=0;
			DRIVER_REQUEST_MAP io{};

			io.buffer = &buffer;
			io.buffer_size = &buffer_size;

			if (!DeviceIoControl(hDriver, IOCTL_REQUEST_PAGES, &io, sizeof(io), &io, sizeof(io), 0, 0))
			{
				return 0;
			}

			*size = buffer_size;

			return buffer;
		}

		std::vector<EFI_PAGE_TABLE_ALLOCATION> get_efi_page_table_allocations()
		{
			std::vector<EFI_PAGE_TABLE_ALLOCATION> table;


			QWORD efi_page_table_size = 0;
			PVOID efi_page_tables     = km::efi::__get_memory_pages(&efi_page_table_size);

			for (DWORD i = 0; i < *(DWORD*)efi_page_tables; i++)
			{
				QWORD temp      = ((QWORD)efi_page_tables + (i*16)) + 0x04;
				QWORD address   = *(QWORD*)((QWORD)temp + 0x00);
				QWORD page_cnt  = *(QWORD*)((QWORD)temp + 0x08);

				table.push_back({address, page_cnt});
			}
		
			NtFreeVirtualMemory(GetCurrentProcess(), &efi_page_tables, &efi_page_table_size, MEM_RELEASE);

			return table;
		}

		std::vector<EFI_MEMORY_DESCRIPTOR> get_efi_memory_map()
		{
			std::vector<EFI_MEMORY_DESCRIPTOR> table;


			QWORD memory_map_size  = 0;
			PVOID memory_map       = km::efi::__get_memory_map(&memory_map_size);

			DWORD descriptor_size  = sizeof(EFI_MEMORY_DESCRIPTOR) + 0x08;
			QWORD descriptor_count = memory_map_size / descriptor_size;

			for (QWORD i = 0; i < descriptor_count; i++)
			{
				EFI_MEMORY_DESCRIPTOR *entry =
					(EFI_MEMORY_DESCRIPTOR*)((char *)memory_map + (i*descriptor_size));
	
				table.push_back(*entry);
			}

			NtFreeVirtualMemory(GetCurrentProcess(), &memory_map, &memory_map_size, MEM_RELEASE);

			return table;
		}

		std::vector<EFI_MODULE_INFO> get_efi_modules(std::vector<EFI_MEMORY_DESCRIPTOR> &memory_map)
		{
			std::vector<EFI_MODULE_INFO> modules;

			for (auto &page : memory_map)
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
						modules.push_back({module_base, module_base_phys, vm::read<DWORD>(nt + 0x050)});
					}
				}

				if (modules.size() < 4)
				{
					modules.clear();
				}
			}

			return modules;
		}

		EFI_PAGE_TABLE_ALLOCATION get_dxe_range(
			EFI_MODULE_INFO module,
			std::vector<EFI_PAGE_TABLE_ALLOCATION> &page_table_list
			)
		{
			for (auto &ptentry : page_table_list)
			{
				if (module.physical_address >= ptentry.PhysicalStart &&
					module.physical_address <= (ptentry.PhysicalStart + (ptentry.NumberOfPages * 0x1000)))
				{
					return ptentry;
				}
			}
			return {};
		}
	}
}

void unlink_detection(std::vector<EFI_PAGE_TABLE_ALLOCATION> &page_table_list, std::vector<EFI_MEMORY_DESCRIPTOR> &memory_map)
{
	for (auto &ptentry : page_table_list)
	{
		BOOL found = 0;

		for (auto &mmentry : memory_map)
		{
			if (ptentry.PhysicalStart >= mmentry.PhysicalStart && ptentry.PhysicalStart <= (mmentry.PhysicalStart + (mmentry.NumberOfPages * 0x1000)))
			{
				found = 1;
				break;
			}
		}

		if (!found)
		{
			LOG("unlinked page allocation!!! [%llx - %llx]\n",
				ptentry.PhysicalStart,
				ptentry.PhysicalStart + (ptentry.NumberOfPages * 0x1000)
			);
		}
	}
}

void invalid_range_detection(std::vector<EFI_MEMORY_DESCRIPTOR> &memory_map, EFI_PAGE_TABLE_ALLOCATION &dxe_range)
{
	for (auto &entry : memory_map)
	{
		if (entry.PhysicalStart >= dxe_range.PhysicalStart &&
			(entry.PhysicalStart + (entry.NumberOfPages * 0x1000)) <=
			(dxe_range.PhysicalStart + (dxe_range.NumberOfPages * 0x1000))
			)
		{
			continue;
		}

		if (entry.Type == 5 || entry.Type == 6 || entry.Attribute == 0x800000000000000f)
		{
			//
			// vmware
			//
			if (entry.PhysicalStart != 0x1000)
				LOG("DXE is found from invalid range!!! [%llx - %llx] 0x%llx\n",
					entry.PhysicalStart,
					entry.PhysicalStart + (entry.NumberOfPages * 0x1000),
					entry.VirtualStart
				);
		}
	}
}

int main(int argc, char **argv)
{
	if (!km::initialize())
	{
		printf("[-] acdrv is not running\n");
		printf("Press any key to continue . . .");
		return getchar();
	}

	std::vector<EFI_MEMORY_DESCRIPTOR> memory_map = km::efi::get_efi_memory_map();
	if (!memory_map.size())
	{
		return 0;
	}

	std::vector<EFI_MODULE_INFO> dxe_modules = km::efi::get_efi_modules(memory_map);
	if (!dxe_modules.size())
	{
		return 0;
	}

	std::vector<EFI_PAGE_TABLE_ALLOCATION> table_allocations = km::efi::get_efi_page_table_allocations();
	if (!table_allocations.size())
	{
		return 0;
	}

	EFI_PAGE_TABLE_ALLOCATION dxe_range = km::efi::get_dxe_range(dxe_modules[0], table_allocations) ;
	if (dxe_range.PhysicalStart == 0)
	{
		return 0;
	}
	
	//
	// print everything
	//
	for (auto &entry : memory_map)
	{
		LOG("0x%llx, %lld [%llx - %llx] 0x%llx\n",
			entry.Attribute,
			entry.Type,
			entry.PhysicalStart,
			entry.PhysicalStart + (entry.NumberOfPages * 0x1000),
			entry.VirtualStart
		);
	}
	

	printf("\n");

	invalid_range_detection(memory_map, dxe_range);
	unlink_detection(table_allocations, memory_map);

	//
	// later runtime checks
	// 
	// if (is_efi_address(rip) && !is_inside(dxe_range))
	//	printf("say: your push to talk is not bound to mouse5\n");
	//


	printf("Press Any Key to continue . . .\n");
	return getchar();
}

