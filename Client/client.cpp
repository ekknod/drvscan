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

	//
	// if drvscan would be less retarded, it would use
	// \Driver\pci & \Driver\acpi instead
	//
	QWORD PciDriverObject;
	QWORD AcpiDriverObject;

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

static int CheckMask(unsigned char* base, unsigned char* pattern, unsigned char* mask)
{
	for (; *mask; ++base, ++pattern, ++mask)
		if (*mask == 'x' && *base != *pattern)
			return 0;
	return 1;
}

void *FindPatternEx(unsigned char* base, QWORD size, unsigned char* pattern, unsigned char* mask)
{
	size -= strlen((const char *)mask);
	for (QWORD i = 0; i <= size; ++i) {
		void* addr = &base[i];
		if (CheckMask((unsigned char *)addr, pattern, mask))
			return addr;
	}
	return 0;
}

QWORD FindPattern(QWORD base, unsigned char* pattern, unsigned char* mask)
{
	if (base == 0)
	{
		return 0;
	}

	QWORD nt_header = (QWORD)*(DWORD*)(base + 0x03C) + base;
	if (nt_header == base)
	{
		return 0;
	}

	WORD machine = *(WORD*)(nt_header + 0x4);
	QWORD section_header = machine == 0x8664 ?
		nt_header + 0x0108 :
		nt_header + 0x00F8;

	for (WORD i = 0; i < *(WORD*)(nt_header + 0x06); i++) {
		QWORD section = section_header + ((QWORD)i * 40);

		DWORD section_characteristics = *(DWORD*)(section + 0x24);

		if (section_characteristics & 0x00000020 && !(section_characteristics & 0x02000000))
		{
			QWORD virtual_address = base + (QWORD)*(DWORD*)(section + 0x0C);
			DWORD virtual_size = *(DWORD*)(section + 0x08);

			void *found_pattern = FindPatternEx( (unsigned char*)virtual_address, virtual_size, pattern, mask);
			if (found_pattern)
			{
				return (QWORD)found_pattern;
			}
		}
	}
	return 0;
}

static QWORD get_kernel_pattern(PCSTR name, QWORD kernel_base, unsigned char* pattern, unsigned char* mask)
{
	HMODULE ntos = LoadLibraryA(name);

	if (ntos == 0)
	{
		return 0;
	}

	QWORD export_address = (QWORD)FindPattern((QWORD)ntos, pattern, mask);
	if (export_address == 0)
	{
		goto cleanup;
	}

	export_address = export_address - (QWORD)ntos;
	export_address = export_address + kernel_base;

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

	QWORD pci_base = 0, acpi_base = 0;
	std::string pci_path, acpi_path;

	for (auto &drv : get_kernel_modules())
	{
		if (!_strcmpi(drv.name.c_str(), "ntoskrnl.exe"))
		{
			ntoskrnl_base = drv.base;
		}
		if (!_strcmpi(drv.name.c_str(), "pci.sys"))
		{
			pci_base = drv.base;
			pci_path = drv.path;
		}
		if (!_strcmpi(drv.name.c_str(), "acpi.sys"))
		{
			acpi_base = drv.base;
			acpi_path = drv.path;
		}
	}

	if (ntoskrnl_base == 0 || pci_base == 0 || acpi_base == 0)
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

	PciDriverObject = get_kernel_pattern(
		pci_path.c_str(), pci_base, (BYTE*)"\x48\x8B\x1D\x00\x00\x00\x00\x75", (BYTE*)"xxx????x");

	AcpiDriverObject = get_kernel_pattern(
		acpi_path.c_str(), acpi_base, (BYTE*)"\x48\x8B\x0D\x00\x00\x00\x00\xB2\x00\x48\xFF\x15", (BYTE*)"xxx????x?xxx");

	if (PciDriverObject == 0 || AcpiDriverObject == 0)
	{
		LOG("OS is not currently supported\n");
		return 0;
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

		AcpiDriverObject      = vm::read<QWORD>(4, vm::get_relative_address(4, AcpiDriverObject, 3, 7));
		PciDriverObject       = vm::read<QWORD>(4, vm::get_relative_address(4, PciDriverObject, 3, 7));
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

BOOL cl::pci::read(BYTE bus, BYTE slot, DWORD offset, PVOID buffer, DWORD size)
{
	QWORD device = get_physical_address(bus, slot);

	if (device == 0)
		return 0;

	return io::read(device + offset, buffer, size);
}

BOOL cl::pci::write(BYTE bus, BYTE slot, DWORD offset, PVOID buffer, DWORD size)
{
	QWORD device = get_physical_address(bus, slot);

	if (device == 0)
		return 0;

	return io::write(device + offset, buffer, size);
}

static BOOL is_port_device(DEVICE_INFO &dev, BYTE max_bus)
{
	if (dev.cfg.class_code() != 0x060400)
	{
		return 0;
	}

	if (dev.cfg.header().type() == 0)
	{
		return 0;
	}

	if (dev.bus != dev.cfg.bus_number())
	{
		return 0;
	}

	if (dev.bus >= dev.cfg.secondary_bus())
	{
		return 0;
	}

	if (dev.cfg.secondary_bus() > max_bus)
	{
		return 0;
	}

	if (dev.cfg.subordinate_bus() > max_bus)
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
				DWORD cd = cl::io::read<BYTE>(entry + 0x09 + 2) << 16 |
					cl::io::read<BYTE>(entry + 0x09 + 1) << 8 |
					cl::io::read<BYTE>(entry + 0x09 + 0);
				if (class_code != cd)
				{
					continue;
				}
			}
			else
			{
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
			}

			DEVICE_INFO device{};
			device.bus = bus;
			device.slot = slot;
			device.func = func;
			device.physical_address = entry;


			//
			// just in case empty the cfg buffer
			//
			memset(device.cfg.raw, 0, sizeof(device.cfg.raw));


			WORD optimize_ptr = 0x100 + 2;
			WORD max_size     = sizeof(device.cfg.raw);
			for (WORD i = 0; i < max_size; i+= 2)
			{
				*(WORD*)((PBYTE)device.cfg.raw + i) = cl::io::read<WORD>(entry + i);
				if (i >= optimize_ptr)
				{
					optimize_ptr = GET_BITS(*(WORD*)((PBYTE)device.cfg.raw + optimize_ptr), 15, 4);
					if (optimize_ptr)
					{
						optimize_ptr += 2;
					}
					else
					{
						optimize_ptr = 0x1000;   // disable
						max_size     = i + 0x30; // max data left 0x30
						if (max_size > sizeof(device.cfg.raw))
						{
							max_size = sizeof(device.cfg.raw);
						}
					}
				}
			}

			devices.push_back(device);
		}
	}
E0:
	return devices;
}

static std::vector<DEVICE_INFO> get_devices_by_bus(unsigned char bus)
{
	//
	// skip invalid ports
	//
	if (bus > 255) return {};

	//
	// skip root ports
	//
	if (bus < 1)  return {};
	return get_devices_by_class(bus, 0);
}

std::vector<PORT_DEVICE_INFO> cl::pci::get_port_devices(void)
{
	typedef struct _BUS_DEVICES {
		BYTE max_bus;
		std::vector<DEVICE_INFO> devices;
	} BUS_DEVICES;

	std::vector<BUS_DEVICES> bus_devices;
	for (auto &port : get_devices_by_class(0, 0x060400))
	{
		if (port.cfg.subordinate_bus() == 0)
			continue;

		BUS_DEVICES bus_entry{};
		bus_entry.max_bus = port.cfg.subordinate_bus();
		bus_entry.devices.push_back( port );

		for (BYTE bus = port.cfg.secondary_bus(); bus < port.cfg.subordinate_bus() + 1; bus++)
		{
			for (auto &dev : get_devices_by_bus(bus))
			{
				bus_entry.devices.push_back(dev);
			}
		}
		bus_devices.push_back(bus_entry);
	}

	std::vector<PORT_DEVICE_INFO> port_list;
	for (auto &bus    : bus_devices)
	for (auto &device : bus.devices)
	{
		if (is_port_device(device, bus.max_bus))
		{
			port_list.push_back({ 0, 0,device });
		}

		//
		// add device to parent port
		//
		for (auto& port : port_list)
		{
			if (port.self.cfg.secondary_bus() == device.bus)
			{
				port.devices.push_back(device);
			}
		}
	}

	//
	// remove mitm switches
	// e.g. port->port(removed)->port->device
	//
	std::vector<PORT_DEVICE_INFO> ports;
	for (auto& port : port_list)
	{
		BOOL contains_port = 0;

		for (auto& dev : port.devices)
		{
			for (auto& port2 : port_list)
			{
				if (
					dev.bus  == port2.self.bus  &&
					dev.slot == port2.self.slot &&
					dev.func == port2.self.func
					)
				{
					contains_port = 1;
					break;
				}
			}
		}

		if (!contains_port)
		{
			ports.push_back(port);
		}
	}

	typedef struct _PCI_SLOT_NUMBER {
		union {
		struct {
			ULONG   DeviceNumber:5;
			ULONG   FunctionNumber:3;
			ULONG   Reserved:24;
		} bits;
		ULONG   AsULONG;
		} u;
	} PCI_SLOT_NUMBER, *PPCI_SLOT_NUMBER;

	//
	// add device objects
	//
	QWORD pci = PciDriverObject;
	QWORD pci_dev = vm::read<QWORD>(4, pci + 0x08);
	while (pci_dev)
	{
		QWORD pci_ext = vm::read<QWORD>(4, pci_dev + 0x40);
		if (pci_ext && vm::read<DWORD>(4, pci_ext) == 0x44696350)
		{
			DWORD bus = vm::read<DWORD>(4, pci_ext + 0x1C);
			PCI_SLOT_NUMBER slot{};
			slot.u.AsULONG = vm::read<DWORD>(4, pci_ext + 0x20);

			for (auto &port : ports)
			{
				if (port.self.bus == bus &&
					port.self.slot == slot.u.bits.DeviceNumber &&
					port.self.func == slot.u.bits.FunctionNumber)
				{
					port.self.pci_device_object = pci_dev;
					QWORD attached_device = cl::vm::read<QWORD>(4, port.self.pci_device_object + 0x18);
					if (!attached_device)
						goto next_device;

					QWORD driver_object = cl::vm::read<QWORD>(4, attached_device + 0x08);
					if (driver_object == AcpiDriverObject)
						attached_device = cl::vm::read<QWORD>(4, attached_device + 0x18);

					port.self.drv_device_object = attached_device;

					goto next_device;
				}
				for (auto &dev  : port.devices)
				{
					if (dev.bus == bus &&
						dev.slot == slot.u.bits.DeviceNumber &&
						dev.func == slot.u.bits.FunctionNumber)
					{
						dev.pci_device_object = pci_dev;

						QWORD attached_device = cl::vm::read<QWORD>(4, dev.pci_device_object + 0x18);
						if (!attached_device)
							goto next_device;

						QWORD driver_object = cl::vm::read<QWORD>(4, attached_device + 0x08);
						if (driver_object == AcpiDriverObject)
							attached_device = cl::vm::read<QWORD>(4, attached_device + 0x18);

						dev.drv_device_object = attached_device;

						goto next_device;
					}
				}
			}
		}
	next_device:
		pci_dev = vm::read<QWORD>(4, pci_dev + 0x10);
	}

	return ports;
}

void cl::pci::get_pci_latency(BYTE bus, BYTE slot, BYTE func, BYTE offset, DWORD loops, DRIVER_TSC *out)
{
	cl::controller->get_pci_latency(bus, slot, func, offset, loops, out);
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
			QWORD module_base = page.PhysicalStart + (page_num * 0x1000);
			if (io::read<WORD>(module_base) == IMAGE_DOS_SIGNATURE)
			{
				QWORD nt = io::read<DWORD>(module_base + 0x03C) + module_base;
				if (io::read<WORD>(nt) != IMAGE_NT_SIGNATURE)
				{
					continue;
				}
				QWORD module_base_virt = page.VirtualStart  + (page_num * 0x1000);
				QWORD module_base_phys = page.PhysicalStart + (page_num * 0x1000);
				modules.push_back({ module_base_virt, module_base_phys, io::read<DWORD>(nt + 0x050) });
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

