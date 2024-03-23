#include "scan.h"

namespace scan
{
	static BOOL unlink_detection(
		std::vector<EFI_PAGE_TABLE_ALLOCATION>& page_table_list,
		std::vector<EFI_MEMORY_DESCRIPTOR>& memory_map,
		EFI_PAGE_TABLE_ALLOCATION *out
		);

	static BOOL invalid_range_detection(
		std::vector<EFI_MEMORY_DESCRIPTOR>& memory_map,
		EFI_PAGE_TABLE_ALLOCATION& dxe_range,
		EFI_MEMORY_DESCRIPTOR *out
		);

	static void runtime_detection(std::vector<EFI_MODULE_INFO> &dxe_modules);
	static void dump_to_file(PCSTR filename, QWORD physical_address, QWORD size);
}

//
// later runtime checks
// 
// if (is_efi_address(rip) && !is_inside(rip, dxe_range))
//	printf("wssu doing m8???\n");
//
void scan::efi(BOOL dump)
{
	std::vector<EFI_MEMORY_DESCRIPTOR> memory_map = cl::efi::get_memory_map();
	if (!memory_map.size())
	{
		return;
	}

	std::vector<EFI_MODULE_INFO> dxe_modules = cl::efi::get_dxe_modules(memory_map);
	if (!dxe_modules.size())
	{
		return;
	}

	std::vector<EFI_PAGE_TABLE_ALLOCATION> table_allocations = cl::efi::get_page_table_allocations();
	if (!table_allocations.size())
	{
		return;
	}

	EFI_PAGE_TABLE_ALLOCATION dxe_range = cl::efi::get_dxe_range(dxe_modules[0], table_allocations) ;
	if (dxe_range.PhysicalStart == 0)
	{
		return;
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

	runtime_detection(dxe_modules);

	EFI_MEMORY_DESCRIPTOR eout_0{};
	if (invalid_range_detection(memory_map, dxe_range, &eout_0) && dump)
	{
		dump_to_file("eout_0.bin", eout_0.PhysicalStart, eout_0.NumberOfPages*0x1000);
	}
	EFI_PAGE_TABLE_ALLOCATION eout_1{};
	if (unlink_detection(table_allocations, memory_map, &eout_1) && dump)
	{
		dump_to_file("eout_1.bin", eout_1.PhysicalStart, eout_1.NumberOfPages*0x1000);
	}
}

static BOOL scan::unlink_detection(
	std::vector<EFI_PAGE_TABLE_ALLOCATION>& page_table_list,
	std::vector<EFI_MEMORY_DESCRIPTOR>& memory_map,
	EFI_PAGE_TABLE_ALLOCATION *out
	)
{
	BOOL status = 0;
	for (auto& ptentry : page_table_list)
	{
		BOOL found = 0;

		for (auto& mmentry : memory_map)
		{
			if (ptentry.PhysicalStart >= mmentry.PhysicalStart && ptentry.PhysicalStart <= (mmentry.PhysicalStart + (mmentry.NumberOfPages * 0x1000)))
			{
				found = 1;
				break;
			}
		}

		if (!found)
		{
			printf("\n");
			LOG("unlinked page allocation!!! [%llx - %llx]\n",
				ptentry.PhysicalStart,
				ptentry.PhysicalStart + (ptentry.NumberOfPages * 0x1000)
			);
			*out = ptentry;
			status = 1;
		}
	}

	return status;
}

static BOOL scan::invalid_range_detection(
	std::vector<EFI_MEMORY_DESCRIPTOR>& memory_map,
	EFI_PAGE_TABLE_ALLOCATION& dxe_range,
	EFI_MEMORY_DESCRIPTOR *out
	)
{
	BOOL status=0;
	for (auto& entry : memory_map)
	{
		if (entry.PhysicalStart >= dxe_range.PhysicalStart &&
			(entry.PhysicalStart + (entry.NumberOfPages * 0x1000)) <=
			(dxe_range.PhysicalStart + (dxe_range.NumberOfPages * 0x1000))
			)
		{
			continue;
		}

		if ((entry.Type == 5 || entry.Type == 6) && entry.Attribute == 0x800000000000000f &&
			entry.PhysicalStart > dxe_range.PhysicalStart)
		{
			printf("\n");
			LOG("DXE is found from invalid range!!! [%llx - %llx] 0x%llx\n",
				entry.PhysicalStart,
				entry.PhysicalStart + (entry.NumberOfPages * 0x1000),
				entry.VirtualStart
			);

			*out   = entry;
			status = 1;
		}
	}

	return status;
}


static void scan::runtime_detection(std::vector<EFI_MODULE_INFO> &dxe_modules)
{
	std::vector<QWORD> HalEfiRuntimeServicesTable = cl::efi::get_runtime_table();
	if (!HalEfiRuntimeServicesTable.size())
	{
		return;
	}

	for (int i = 0; i < HalEfiRuntimeServicesTable.size(); i++)
	{
		QWORD rt_func = HalEfiRuntimeServicesTable[i];
		if (cl::vm::read<WORD>(4, rt_func) == 0x25ff)
		{
			LOG_RED("EFI Runtime service [%d] is hooked with byte patch: %llx\n", i, rt_func);
			continue;
		}

		QWORD physical_address = cl::get_physical_address(rt_func);
		BOOL found = 0;
		for (auto& base : dxe_modules)
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

static void scan::dump_to_file(PCSTR filename, QWORD physical_address, QWORD size)
{
	LOG("dumping out: [%llX - %llX]\n", physical_address, physical_address + size);
	PVOID buffer = malloc(size);
	cl::io::read(physical_address, buffer, size);
	if (*(WORD*)(buffer) == IMAGE_DOS_SIGNATURE)
	{
		QWORD nt = pe::get_nt_headers((QWORD)buffer);
		PIMAGE_SECTION_HEADER section = pe::nt::get_image_sections(nt);
		for (WORD i = 0; i < pe::nt::get_section_count(nt); i++)
		{
			section[i].PointerToRawData = section[i].VirtualAddress;
			section[i].SizeOfRawData    = section[i].Misc.VirtualSize;
		}
	}
	FILE *f = fopen(filename, "wb");
	fwrite(buffer, size, 1, f);
	fclose(f);
	free(buffer);
}

