#include "scan.h"

namespace scan
{
	static BOOL invalid_range_detection(
		std::vector<EFI_MEMORY_DESCRIPTOR>& memory_map,
		EFI_MEMORY_DESCRIPTOR& dxe_range,
		EFI_MEMORY_DESCRIPTOR *out
		);

	std::vector<EFI_MODULE_INFO> get_runtime_modules(std::vector<QWORD> &runtime_table, EFI_MEMORY_DESCRIPTOR &dxe_range);
	std::vector<EFI_MODULE_INFO> get_dxe_modules(std::vector<EFI_MEMORY_DESCRIPTOR>& memory_map);
	static void runtime_detection(EFI_MEMORY_DESCRIPTOR &dxe_range);
	static void umap_detect(void);
	static void dump_to_file(PCSTR filename, QWORD physical_address, QWORD size);
}

//
// later runtime checks
// 
// if (is_efi_address(rip) && !is_inside(rip, dxe_range))
//	printf("wssu doing m8???\n");
//

inline PCSTR get_efi_type(QWORD type)
{
	if (11  == type) return "MIO";
	if (609 == type) return "VMWARE";
	return "DXE";
}

void scan::efi(BOOL dump)
{
	std::vector<EFI_MEMORY_DESCRIPTOR> memory_map = cl::efi::get_memory_map();
	if (!memory_map.size())
	{
		return;
	}

	std::vector<QWORD> runtime_table = cl::efi::get_runtime_table();
	if (runtime_table.size() == 0)
	{
		for (auto &entry : memory_map)
		{
			if (entry.Type != 11)
			{
				LOG_RED("did you touch FirmwareTypeUefi boot time?\n");
				break;
			}
		}
		return;
	}


	EFI_MEMORY_DESCRIPTOR dxe_range{};
	for (auto &page : memory_map)
	{
		if (runtime_table[0] >= page.VirtualStart &&
			runtime_table[0] <= (page.VirtualStart + (page.NumberOfPages * PAGE_SIZE))
			)
		{
			dxe_range = page;
			break;
		}
	}

	if (dxe_range.VirtualStart == 0)
	{
		LOG_RED("????????????????????????????????\n");
		return;
	}

	for (auto &entry : memory_map)
	{
		if (entry.VirtualStart == dxe_range.VirtualStart || entry.Type == 11)
		{
			LOG("%s [%llx - %llx] %llx\n",
				// entry.Attribute,
				get_efi_type(entry.Type),
				entry.PhysicalStart,
				entry.PhysicalStart + (entry.NumberOfPages * 0x1000),
				entry.VirtualStart
			);
		}
		else
		{
			LOG_RED("%s [%llx - %llx] %llx\n",
				// entry.Attribute,
				get_efi_type(entry.Type),
				entry.PhysicalStart,
				entry.PhysicalStart + (entry.NumberOfPages * 0x1000),
				entry.VirtualStart
			);
		}
	}

	runtime_detection(dxe_range);
	umap_detect();

	EFI_MEMORY_DESCRIPTOR eout_0{};
	if (invalid_range_detection(memory_map, dxe_range, &eout_0) && dump)
	{
		dump_to_file("eout_0.bin", eout_0.PhysicalStart, eout_0.NumberOfPages*0x1000);
	}

	//
	// dump modules from EFI range (driver.sys)
	//
	std::vector<EFI_MODULE_INFO> modules = get_dxe_modules(memory_map);
	if (modules.size() == 0)
	{
		//
		// dump modules from runtime range (rtcore.sys)
		//
		modules = get_runtime_modules(runtime_table, dxe_range);
	}

	if (modules.size() < 3)
	{
		LOG_RED("????????????????????????????????\n");
		return;
	}

	for (auto &entry : modules)
	{
		printf("DXE module [%llx - %llx] %llx\n",
			// entry.Attribute,
			entry.physical_address,
			entry.physical_address + (entry.size),
			entry.virtual_address
		);
	}
}

static BOOL scan::invalid_range_detection(
	std::vector<EFI_MEMORY_DESCRIPTOR>& memory_map,
	EFI_MEMORY_DESCRIPTOR& dxe_range,
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
			entry.PhysicalStart != dxe_range.PhysicalStart)
		{
			printf("\n");
			LOG("DXE is found from invalid range!!! [%llx - %llx]\n",
				entry.PhysicalStart,
				entry.PhysicalStart + (entry.NumberOfPages * 0x1000)
			);

			*out   = entry;
			status = 1;
		}
	}

	return status;
}


static void scan::runtime_detection(EFI_MEMORY_DESCRIPTOR &dxe_range)
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

		BOOL found = 0;
		if (rt_func >= dxe_range.VirtualStart &&
			rt_func <= (dxe_range.VirtualStart + (dxe_range.NumberOfPages * PAGE_SIZE))
			)
		{
			found = 1;
		}
		
		if (!found)
		{
			LOG_RED("EFI Runtime service [%d] is hooked with pointer swap: %llx, %llx\n",
				i, rt_func, cl::get_physical_address(rt_func));
		}
	}
}

static void scan::umap_detect(void)
{
	auto  modules = get_kernel_modules();
	QWORD hal     = 0;
	for (auto &mod : modules)
	{
		if (!_strcmpi(mod.name.c_str(), "hal.dll"))
		{
			hal = mod.base;
			break;
		}
	}

	QWORD entry = hal;
	QWORD fbase = 0;
	QWORD lbase = 0;

	while (1)
	{
		BOOL found = 0;
		for (auto& mod : modules)
		{
			if (entry >= mod.base && entry <= (mod.base + mod.size))
			{
				fbase = mod.base;
				found = 1;
				break;
			}
		}

		if (!found)
		{
			entry += 0x10000;
			break;
		}

		entry -= 0x10000;
	}

	while (1)
	{
		BOOL found = 0;
		for (auto& mod : modules)
		{
			if (entry >= mod.base && entry <= (mod.base + mod.size))
			{
				lbase = mod.base;
				found = 1;
				break;
			}
		}

		if (!found)
			break;

		entry += 0x10000;
	}

	if (fbase == lbase)
	{
		LOG_RED("umap detected (this is just public troll bro) get shrekt from UM\n");
	}
}

EFI_MODULE_INFO get_module_from_address(QWORD virtual_address, EFI_MEMORY_DESCRIPTOR &dxe_range)
{
	EFI_MODULE_INFO mod{};

	virtual_address = (QWORD)PAGE_ALIGN(virtual_address);

	while (1)
	{
		virtual_address -= PAGE_SIZE;

		if (virtual_address < dxe_range.VirtualStart)
		{
			break;
		}

		if (virtual_address > (dxe_range.VirtualStart + dxe_range.NumberOfPages * PAGE_SIZE))
		{
			break;
		}

		if (cl::vm::read<WORD>(0, virtual_address) != IMAGE_DOS_SIGNATURE)
		{
			continue;
		}

		QWORD nt = cl::vm::read<DWORD>(0, virtual_address + 0x03C) + virtual_address;
		if (cl::vm::read<WORD>(0, nt) != IMAGE_NT_SIGNATURE)
		{
			continue;
		}

		QWORD delta = virtual_address - dxe_range.VirtualStart;
		mod.physical_address = dxe_range.PhysicalStart + delta;
		mod.virtual_address  = dxe_range.VirtualStart  + delta;
		mod.size             = cl::vm::read<DWORD>(0, nt + 0x050);
		break;
	}

	return mod;
}

std::vector<EFI_MODULE_INFO> scan::get_runtime_modules(std::vector<QWORD> &runtime_table, EFI_MEMORY_DESCRIPTOR &dxe_range)
{
	std::vector<EFI_MODULE_INFO> modules{};

	for (int i = 0; i < runtime_table.size(); i++)
	{
		QWORD rt_func = runtime_table[i];

		if (rt_func > dxe_range.VirtualStart &&
			rt_func < dxe_range.VirtualStart + (dxe_range.NumberOfPages * PAGE_SIZE))
		{
			EFI_MODULE_INFO mod = get_module_from_address(rt_func, dxe_range);

			if (mod.virtual_address == 0)
			{
				LOG("should not happen [2] ???\n");
				return {};
			}

			BOOL found = 0;
			for (auto &entry : modules)
			{
				if (entry.physical_address == mod.physical_address)
				{
					found = 1;
					break;
				}
			}

			if (!found) modules.push_back(mod);
		}
		else
		{
			LOG("should not happen [1] ???\n");
			return {};
		}
	}
	return modules;
}

std::vector<EFI_MODULE_INFO> scan::get_dxe_modules(std::vector<EFI_MEMORY_DESCRIPTOR>& memory_map)
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
			QWORD module_base = page.PhysicalStart + (page_num * 0x1000);
			if (cl::io::read<WORD>(module_base) == IMAGE_DOS_SIGNATURE)
			{
				QWORD nt = cl::io::read<DWORD>(module_base + 0x03C) + module_base;
				if (cl::io::read<WORD>(nt) != IMAGE_NT_SIGNATURE)
				{
					continue;
				}
				QWORD module_base_virt = page.VirtualStart  + (page_num * 0x1000);
				QWORD module_base_phys = page.PhysicalStart + (page_num * 0x1000);
				modules.push_back({ module_base_virt, module_base_phys, cl::io::read<DWORD>(nt + 0x050) });
			}
		}

		if (modules.size() < 4)
		{
			modules.clear();
		}
	}

	return modules;
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

