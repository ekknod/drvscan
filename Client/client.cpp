#include "client.h"
#include "clkm/clkm.h"
#include "clint/clint.h"
#include "clum/clum.h"
#include <chrono>

QWORD cl::ntoskrnl_base;
std::vector<QWORD> cl::global_export_list;


//
// NTOSKRNL_EXPORT define variables are automatically resolved in cl::initialize
//
NTOSKRNL_EXPORT(HalPrivateDispatchTable);
NTOSKRNL_EXPORT(HalEnumerateEnvironmentVariablesEx);
NTOSKRNL_EXPORT(MmGetVirtualForPhysical);

namespace cl
{
	client *controller;

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
	export_address = export_address + cl::ntoskrnl_base;

cleanup:
	FreeLibrary(ntos);
	return export_address;
}

BOOL cl::initialize(void)
{
	if (controller != 0)
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
	
	clkm *km = new clkm();
	clint *intel = new clint();
	clum *um = new clum();
	if (controller == 0 && km->initialize())
	{
		controller = km;
	}
	else
	{
		delete km; km = 0;
	}

	if (controller == 0 && intel->initialize())
	{
		controller = intel;
	}
	else
	{
		delete intel; intel = 0;
	}

	if (controller == 0 && um->initialize())
	{
		controller = um;
	}
	else
	{
		delete um; um = 0;
	}
	
	if ((km || intel))
	{
		//
		// resolve HalpPciMcfgTableCount/HalpPciMcfgTable addresses
		//
		QWORD table_entry = HalPrivateDispatchTable;
		table_entry       = vm::read<QWORD>(4, table_entry + 0xA0);
		table_entry       = table_entry + 0x1B;
		table_entry       = (table_entry + 5) + vm::read<INT>(4, table_entry + 1);
		while (1)
		{
			if (vm::read<BYTE>(4, table_entry) == 0xE8 && vm::read<WORD>(4, table_entry + 5) == 0xFB83)
			{
				break;
			}
			table_entry++;
		}
		table_entry = (table_entry + 5) + vm::read<INT>(4, table_entry + 1);
		while (1)
		{
			if (vm::read<DWORD>(4, table_entry) == 0xCCB70F41 && vm::read<BYTE>(4, table_entry + 4) == 0xE8)
			{
				table_entry += 0x04;
				break;
			}
			table_entry++;
		}
		table_entry = (table_entry + 5) + vm::read<INT>(4, table_entry + 1);
		table_entry = table_entry + 0x47;
		table_entry = (table_entry + 5) + vm::read<INT>(4, table_entry + 1);

		HalpPciMcfgTableCount = vm::get_relative_address(4, table_entry + 0x07, 2, 6);
		HalpPciMcfgTable      = vm::get_relative_address(4, table_entry + 0x11, 3, 7);

		MmPfnDatabase         = vm::read<QWORD>(4, MmGetVirtualForPhysical + 0x0E + 0x02);
		MmPteBase             = vm::read<QWORD>(4, MmGetVirtualForPhysical + 0x20 + 0x02);
	}
	return 1;
}

QWORD cl::get_physical_address(QWORD virtual_address)
{
	return controller->get_physical_address(virtual_address);
}

BOOL cl::vm::read(DWORD pid, QWORD address, PVOID buffer, QWORD length)
{
	return controller->read_virtual(pid, address, buffer, length);
}

PVOID cl::vm::dump_module(DWORD pid, QWORD base, DWORD dmp_type)
{
	if (base == 0)
	{
		return 0;
	}

	if (read<WORD>(pid, base) != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	QWORD nt_header = (QWORD)read<DWORD>(pid, base + 0x03C) + base;
	if (nt_header == base)
	{
		return 0;
	}

	DWORD image_size = read<DWORD>(pid, nt_header + 0x050);
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

	DWORD headers_size = read<DWORD>(pid, nt_header + 0x54);
	vm::read(pid, base, new_base, headers_size);

	WORD machine = read<WORD>(pid, nt_header + 0x4);
	QWORD section_header = machine == 0x8664 ?
		nt_header + 0x0108 :
		nt_header + 0x00F8;


	for (WORD i = 0; i < read<WORD>(pid, nt_header + 0x06); i++) {
		QWORD section = section_header + ((QWORD)i * 40);

		DWORD section_characteristics = read<DWORD>(pid, section + 0x24);
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
		QWORD target_address = (QWORD)new_base + cl::vm::read<DWORD>(pid, section + ((dmp_type & DMP_RAW) ? 0x14 : 0x0c));
		QWORD virtual_address = base + (QWORD)read<DWORD>(pid, section + 0x0C);
		DWORD virtual_size = read<DWORD>(pid, section + 0x08);
		vm::read(pid, virtual_address, (PVOID)target_address, virtual_size);
	}
	return (PVOID)new_base;
}

void cl::vm::free_module(PVOID dumped_module)
{
	if (dumped_module)
	{
		QWORD a0 = (QWORD)dumped_module;
		a0 -= 16;
		free((void*)a0);
	}
}

BOOL cl::io::read(QWORD address, PVOID buffer, QWORD length)
{
	return controller->read_mmio(address, buffer, length);
}

BOOL cl::io::write(QWORD address, PVOID buffer, QWORD length)
{
	return controller->write_mmio(address, buffer, length);
}

QWORD cl::pci::get_physical_address(ULONG bus, ULONG slot)
{
	DWORD v3; // r10d
	unsigned __int8* i; // r9

	v3 = 0;

	QWORD table = vm::read<QWORD>(4, HalpPciMcfgTable);
	DWORD table_count = vm::read<DWORD>(4, HalpPciMcfgTableCount);

	if (!table)
		return 0i64;

	if (!table_count)
		return 0i64;

	for (i = (unsigned __int8*)(table + 54);

		(bus >> 8) != vm::read<WORD>(4, (QWORD)(i - 1)) ||
		bus < vm::read<BYTE>(4, (QWORD)i) ||
		bus > vm::read<BYTE>(4, (QWORD)i + 1);

		i += 16
		)
	{
		if (++v3 >= (unsigned int)table_count)
			return 0i64;
	}
	return vm::read<QWORD>(4, (QWORD)(i - 10)) + (((slot >> 5) + 8 * ((slot & 0x1F) + 32i64 * bus)) << 12);
}

BOOL cl::pci::read(BYTE bus, BYTE slot, BYTE offset, PVOID buffer, QWORD size)
{
	QWORD device = get_physical_address(bus, slot);

	if (device == 0)
		return 0;

	return io::read(device + offset, buffer, size);
}

BOOL cl::pci::write(BYTE bus, BYTE slot, BYTE offset, PVOID buffer, QWORD size)
{
	QWORD device = get_physical_address(bus, slot);

	if (device == 0)
		return 0;

	return io::write(device + offset, buffer, size);
}

static BOOL is_bridge_device(ROOT_DEVICE_INFO& dev)
{
	using namespace pci;

	//
	// validate if its real bridge
	//
	if (class_code(dev.d.cfg) != 0x060400)
	{
		return 0;
	}

	//
	// type0 endpoint device
	//
	if (GET_BITS(header_type(dev.d.cfg), 6, 0) == 0)
	{
		return 0;
	}

	return 1;
}

static std::vector<DEVICE_INFO> get_devices_by_class(unsigned char bus, DWORD class_code)
{
	std::vector<DEVICE_INFO> devices;
	for (unsigned char slot = 0; slot < 32; slot++)
	{
		QWORD physical_address = cl::pci::get_physical_address(bus, slot);
		if (physical_address == 0)
		{
			goto E0;
		}

		for (unsigned char func = 0; func < 8; func++)
		{
			QWORD entry = physical_address + (func << 12l);

			if (class_code)
			{
				DWORD cd = 0;
				((unsigned char*)&cd)[0] = cl::io::read<BYTE>(entry + 0x09 + 0);
				((unsigned char*)&cd)[1] = cl::io::read<BYTE>(entry + 0x09 + 1);
				((unsigned char*)&cd)[2] = cl::io::read<BYTE>(entry + 0x09 + 2);

				if (class_code != cd)
				{
					continue;
				}
			}
			int invalid_cnt = 0;
			for (int i = 0; i < 8; i++)
			{
				if (cl::io::read<BYTE>(entry + 0x04 + i) == 0xFF)
				{
					invalid_cnt++;
				}
			}

			if (invalid_cnt == 8)
			{
				if (func == 0)
				{
					break;
				}
				continue;
			}

			DEVICE_INFO device;
			device.bus = bus;
			device.slot = slot;
			device.func = func;
			device.physical_address = entry;

			UINT64 current_ms = std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::high_resolution_clock::now().time_since_epoch())
				.count();

			//
			// do not even ask... intel driver problem
			//
			for (int i = 0; i < sizeof(device.cfg); i+= 2)
			{
				*(WORD*)((PBYTE)device.cfg + i) = cl::io::read<WORD>(entry + i);
			}


			current_ms = std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::high_resolution_clock::now().time_since_epoch())
				.count() - current_ms;

			device.cfg_time = current_ms;


			devices.push_back(device);
		}
	}
E0:
	return devices;
}

static std::vector<ROOT_DEVICE_INFO> get_root_bridge_devices(void)
{
	std::vector<ROOT_DEVICE_INFO> devices;
	for (auto &dev : get_devices_by_class(0, 0x060400)) devices.push_back({dev});
	return devices;
}

static std::vector<DEVICE_INFO> get_devices_by_bus(unsigned char bus)
{
	return get_devices_by_class(bus, 0);
}

static std::vector<ROOT_DEVICE_INFO> get_inner_devices(std::vector<ROOT_DEVICE_INFO> &devices)
{
	using namespace pci;


	std::vector<ROOT_DEVICE_INFO> devs;


	for (auto &entry : devices)
	{
		if (!is_bridge_device(entry))
		{
			continue;
		}
		BYTE max_bus = type1::subordinate_bus_number(entry.d.cfg);
		auto bridge_devices = get_devices_by_bus(type1::secondary_bus_number(entry.d.cfg));

		for (auto &bridge : bridge_devices)
		{
			if (bridge.bus > max_bus)
			{
				continue;
			}
			devs.push_back({bridge, entry.d});
		}
	}
	return devs;
}

std::vector<PORT_DEVICE_INFO> cl::pci::get_port_devices(void)
{
	using namespace pci;

	std::vector<ROOT_DEVICE_INFO> root_devices = get_root_bridge_devices();
	std::vector<PORT_DEVICE_INFO> port_devices;
	while (1)
	{
		std::vector<ROOT_DEVICE_INFO> bridge_devices;
		for (auto &dev : root_devices)
		{
			if (!is_bridge_device(dev))
			{
				for (auto &port : port_devices)
				{
					if (port.self.bus == dev.p.bus &&
						port.self.slot == dev.p.slot &&
						port.self.func == dev.p.func
						)
					{
						port.devices.push_back(dev.d);
						break;
					}
				}
			}
			else
			{
				bridge_devices.push_back(dev);
			}
		}

		//
		// get new devices
		//
		root_devices = get_inner_devices(root_devices);
		if (!root_devices.size())
		{
			//
			// append new fake devices
			//
			for (auto &dev : bridge_devices)
			{
				for (auto &port : port_devices)
				{
					if (port.self.bus == dev.p.bus &&
						port.self.slot == dev.p.slot &&
						port.self.func == dev.p.func
						)
					{
						port.devices.push_back(dev.d);
						break;
					}
				}
			}
			break;
		}
		else
		{
			//
			// append new port devices
			//
			for (auto &dev : bridge_devices)
			{
				port_devices.push_back({0, 0, dev.d});
			}
		}
	}

	std::vector<PORT_DEVICE_INFO> ports;
	for (auto& port : port_devices)
	{
		if (!port.devices.empty())
		{
			ports.push_back(port);
		}
	}

	return ports;
}

static PVOID cl::efi::__get_memory_map(QWORD* size)
{
	return controller->__get_memory_map(size);
}

static PVOID cl::efi::__get_memory_pages(QWORD* size)
{
	return controller->__get_memory_pages(size);
}

std::vector<EFI_PAGE_TABLE_ALLOCATION> cl::efi::get_page_table_allocations()
{
	std::vector<EFI_PAGE_TABLE_ALLOCATION> table;


	QWORD efi_page_table_size = 0;
	PVOID efi_page_tables = cl::efi::__get_memory_pages(&efi_page_table_size);

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

std::vector<EFI_MEMORY_DESCRIPTOR> cl::efi::get_memory_map()
{
	std::vector<EFI_MEMORY_DESCRIPTOR> table;


	QWORD memory_map_size = 0;
	PVOID memory_map = cl::efi::__get_memory_map(&memory_map_size);

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

std::vector<EFI_MODULE_INFO> cl::efi::get_dxe_modules(std::vector<EFI_MEMORY_DESCRIPTOR>& memory_map)
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
			if (vm::read<WORD>(4, module_base) == IMAGE_DOS_SIGNATURE)
			{
				QWORD nt = vm::read<DWORD>(4, module_base + 0x03C) + module_base;
				if (vm::read<WORD>(4, nt) != IMAGE_NT_SIGNATURE)
				{
					continue;
				}
				QWORD module_base_phys = page.PhysicalStart + (page_num * 0x1000);
				modules.push_back({ module_base, module_base_phys, vm::read<DWORD>(4, nt + 0x050) });
			}
		}

		if (modules.size() < 4)
		{
			modules.clear();
		}
	}

	return modules;
}

EFI_PAGE_TABLE_ALLOCATION cl::efi::get_dxe_range(
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

std::vector<QWORD> cl::efi::get_runtime_table(void)
{
	QWORD HalEfiRuntimeServicesTableAddr = cl::vm::get_relative_address(4, HalEnumerateEnvironmentVariablesEx + 0xC, 1, 5);
	HalEfiRuntimeServicesTableAddr       = cl::vm::get_relative_address(4, HalEfiRuntimeServicesTableAddr + 0x69, 3, 7);
	HalEfiRuntimeServicesTableAddr       = cl::vm::read<QWORD>(4, HalEfiRuntimeServicesTableAddr);
	if (!HalEfiRuntimeServicesTableAddr)
	{
		return {};
	}

	QWORD HalEfiRuntimeServicesTable[9];
	cl::vm::read(4, HalEfiRuntimeServicesTableAddr, &HalEfiRuntimeServicesTable, sizeof(HalEfiRuntimeServicesTable));

	std::vector<QWORD> table{};
	for (int i = 9; i--;)
		table.push_back(HalEfiRuntimeServicesTable[i]);

	return table;
}

