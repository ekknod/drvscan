#include "client.h"
#include "clkm/clkm.h"
#include "clint/clint.h"
#include "clrt/clrt.h"
#include "clum/clum.h"
#include <chrono>
#pragma warning (disable: 4201)
#pragma warning (disable: 4996)
#include "..\Driver\ia32.hpp"

QWORD cl::ntoskrnl_base;



std::vector<QWORD> cl::global_export_list;


//
// NTOSKRNL_EXPORT define variables are automatically resolved in cl::initialize
//
NTOSKRNL_EXPORT(HalPrivateDispatchTable);
NTOSKRNL_EXPORT(HalEnumerateEnvironmentVariablesEx);
NTOSKRNL_EXPORT(MmGetVirtualForPhysical);
NTOSKRNL_EXPORT(KeQueryPrcbAddress);
NTOSKRNL_EXPORT(ExAllocatePool2);
NTOSKRNL_EXPORT(ExFreePool);
NTOSKRNL_EXPORT(MmGetPhysicalAddress);
NTOSKRNL_EXPORT(MmIsAddressValid);
NTOSKRNL_EXPORT(PsInitialSystemProcess);

namespace kernel
{
	NTOSKRNL_EXPORT(memcpy);
}

namespace cl
{
	client *controller;

	QWORD HalpPciMcfgTableCount;
	QWORD HalpPciMcfgTable;


	QWORD PciIoAddressPhysical;
	QWORD PciIoAddressVirtual;


	QWORD MmPfnDatabase;
	QWORD MmPteBase;

	QWORD wdf01000_base, wdf01000_size;
	QWORD dxgkrnl_base,  dxgkrnl_size;

	QWORD system_cr3;
	BOOL  has_io_access = 0;

	//
	// if drvscan would be less retarded, it would use
	// \Driver\pci & \Driver\acpi instead
	//
	QWORD PciDriverObject;
	QWORD AcpiDriverObject;

	#define MiGetVirtualAddressMappedByPte(PteAddress) (PVOID)((LONG_PTR)(((LONG_PTR)(PteAddress) - (ULONG_PTR)(MmPteBase)) << 25L) >> 16)
	QWORD get_virtual_address(QWORD physical_address)
	{
		QWORD index     = physical_address >> PAGE_SHIFT;
		QWORD pfn_entry = (MmPfnDatabase + (index * 0x30));
		QWORD pte       = vm::read<QWORD>(0, pfn_entry + 0x08);
		if (pte == 0)
		{
			return 0;
		}
		QWORD va = (QWORD)MiGetVirtualAddressMappedByPte((QWORD)pte);
		return (physical_address & 0xFFF) + va;
	}
}

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
	std::string pci_path, acpi_path, ntoskrnl_path;

	for (auto &drv : get_kernel_modules())
	{
		if (!_strcmpi(drv.name.c_str(), "ntoskrnl.exe"))
		{
			ntoskrnl_base = drv.base;
			ntoskrnl_path = drv.path;
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
		if (!_strcmpi(drv.name.c_str(), "wdf01000.sys"))
		{
			wdf01000_base = drv.base;
			wdf01000_size = drv.size;
		}
		if (!_strcmpi(drv.name.c_str(), "dxgkrnl.sys"))
		{
			dxgkrnl_base = drv.base;
			dxgkrnl_size = drv.size;
		}
	}

	if (ntoskrnl_base == 0 || pci_base == 0 || acpi_base == 0 || wdf01000_base == 0 || dxgkrnl_base == 0)
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
	clrt  *rt = new clrt();
	clum *um = new clum();
	if (controller == 0 && km->initialize())
	{
		controller = km;
	}
	else
	{
		delete km; km = 0;
	}

	if (controller == 0 && rt->initialize())
	{
		controller = rt;
	}
	else
	{
		delete rt; rt = 0;
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

	if (km || intel || um) has_io_access = 1;
	
	if ((km || intel || rt))
	{
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

		HalpPciMcfgTableCount  = vm::get_relative_address(4, table_entry + 0x07, 2, 6);
		HalpPciMcfgTable       = vm::get_relative_address(4, table_entry + 0x11, 3, 7);

		MmPfnDatabase          = vm::read<QWORD>(4, MmGetVirtualForPhysical + 0x0E + 0x02) - 0x08;
		MmPteBase              = vm::read<QWORD>(4, MmGetVirtualForPhysical + 0x20 + 0x02);

		AcpiDriverObject       = vm::read<QWORD>(4, vm::get_relative_address(4, AcpiDriverObject, 3, 7));
		PciDriverObject        = vm::read<QWORD>(4, vm::get_relative_address(4, PciDriverObject, 3, 7));

		system_cr3             = vm::read<QWORD>(4, vm::read<QWORD>(4, PsInitialSystemProcess) + 0x28);
		PciIoAddressPhysical = pci::get_physical_address(0, 0);
		QWORD tabl = (QWORD)PAGE_ALIGN(efi::get_runtime_table()[0]);
		while (1)
		{
			QWORD temp = get_physical_address(tabl);
			if (PAGE_ALIGN(temp))
			{
				if (PciIoAddressPhysical == temp)
				{
					PciIoAddressVirtual = tabl;
					break;
				}
				tabl += PAGE_SIZE;
			}
			else
			{
				break;
			}
		}
	}

	return 1;
}

QWORD cl::get_physical_address(QWORD virtual_address)
{
	if (has_io_access)
		return controller->get_physical_address(virtual_address);

	QWORD pte_address  = MmPteBase + ((virtual_address >> 9) & 0x7FFFFFFFF8);
	QWORD pde_address  = MmPteBase + ((pte_address >> 9) & 0x7FFFFFFFF8);
	QWORD pdpt_address = MmPteBase + ((pde_address >> 9) & 0x7FFFFFFFF8);
	QWORD pml4_address = MmPteBase + ((pdpt_address >> 9) & 0x7FFFFFFFF8);

	pml4e_64 pml4{};
	vm::read(4, pml4_address, &pml4, sizeof(pml4));
	if (!pml4.present)
	{
		return 0;
	}

	pdpte_64 pdpt{};
	vm::read(4, pdpt_address, &pdpt, sizeof(pdpt));
	if (!pdpt.present)
	{
		return 0;
	}

	//
	// 1gb
	//
	if (pdpt.large_page)
	{
		return (pdpt.page_frame_number << PAGE_SHIFT) + (virtual_address & 0x3FFFFFFF);
	}

	pde_64 pde{};
	vm::read(4, pde_address, &pde, sizeof(pde));
	if (!pde.present)
	{
		return 0;
	}

	//
	// 2mb
	//
	if (pde.large_page)
	{
		return (pde.page_frame_number << PAGE_SHIFT) + (virtual_address & 0x1FFFFF);
	}

	pte_64 pte{};
	vm::read(4, pte_address, &pte, sizeof(pte));
	if (!pte.present)
	{
		return 0;
	}

	//
	// 4kb
	//
	return (pte.page_frame_number << PAGE_SHIFT) + (virtual_address & 0xFFF);
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

		(bus >> 8) != vm::read<WORD>(0, (QWORD)(i - 1)) ||
		bus < vm::read<BYTE>(0, (QWORD)i) ||
		bus > vm::read<BYTE>(0, (QWORD)i + 1);

		i += 16
		)
	{
		if (++v3 >= (unsigned int)table_count)
			return 0i64;
	}
	return vm::read<QWORD>(0, (QWORD)(i - 10)) + (((slot >> 5) + 8 * ((slot & 0x1F) + 32i64 * bus)) << 12);
}

BOOL cl::pci::read(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD size)
{
	if (PciIoAddressVirtual)
	{
		QWORD device = get_physical_address(bus, slot);
		device = device + (func << 12l);

		QWORD delta = device - PciIoAddressPhysical;
		QWORD virtu = PciIoAddressVirtual + delta;

		if (size == 0x100 || size == 0xF00)
		{
			for (DWORD i = 0; i < size; i+= 4)
			{
				if (!controller->read_virtual(0, virtu + offset + i, (PVOID)((QWORD)buffer + i), sizeof(DWORD)))
					return 0;
			}
			return 1;
		}
		return controller->read_virtual(0, virtu + offset, buffer, size);
	}

	if (!has_io_access)
	{
		return controller->read_pci(bus, slot, func, offset, buffer, size);
	}

	QWORD device = get_physical_address(bus, slot);

	if (device == 0)
		return 0;

	device = device + (func << 12l);
	return io::read(device + offset, buffer, size);
}

BOOL cl::pci::write(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD size)
{
	if (PciIoAddressVirtual)
	{
		QWORD device = get_physical_address(bus, slot);
		device = device + (func << 12l);

		QWORD delta = device - PciIoAddressPhysical;
		QWORD virtu = PciIoAddressVirtual + delta;

		return controller->write_virtual(0, virtu + offset, buffer, size);
	}

	if (!has_io_access)
	{
		return controller->write_pci(bus, slot, func, offset, buffer, size);
	}

	QWORD device = get_physical_address(bus, slot);

	if (device == 0)
		return 0;

	device = device + (func << 12l);
	return io::write(device + offset, buffer, size);
}

typedef struct {
	DEVICE_INFO data;
	DWORD       device_class;
} RAW_PCIENUM_OBJECT;

std::vector<RAW_PCIENUM_OBJECT> get_raw_pci_objects()
{
	std::vector<RAW_PCIENUM_OBJECT> objects{};

	using namespace cl;

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
			DWORD device_class = vm::read<BYTE>(4, pci_ext + 0x29 + 0) << 16 |
				vm::read<BYTE>(4, pci_ext + 0x29 + 1) << 8 | vm::read<BYTE>(4, pci_ext + 0x29 + 2);

			DWORD bus = vm::read<DWORD>(4, pci_ext + 0x1C);
			PCI_SLOT_NUMBER slot{};
			slot.u.AsULONG = vm::read<DWORD>(4, pci_ext + 0x20);


			QWORD attached_device = cl::vm::read<QWORD>(4, pci_dev + 0x18);
			if (attached_device)
			{
				QWORD driver_object = cl::vm::read<QWORD>(4, attached_device + 0x08);
				if (driver_object == AcpiDriverObject)
					attached_device = cl::vm::read<QWORD>(4, attached_device + 0x18);

			}
									
			RAW_PCIENUM_OBJECT object{};
			object.data.bus  = bus & 0xFF;
			object.data.slot = slot.u.bits.DeviceNumber;
			object.data.func = slot.u.bits.FunctionNumber;
			object.data.pci_device_object = pci_dev;
			object.data.drv_device_object = attached_device;
			object.device_class = device_class;
			objects.push_back(object);
		}
		pci_dev = vm::read<QWORD>(4, pci_dev + 0x10);
	}
	return objects;
}

std::vector<DEVICE_INFO> get_devices_by_bus(std::vector<RAW_PCIENUM_OBJECT> &pci_devices, BYTE bus)
{
	std::vector<DEVICE_INFO> objects{};
	for (auto &dev : pci_devices) if (dev.data.bus == bus) objects.push_back(dev.data);
	return objects;
}

static void pci_initialize_cfg(DEVICE_INFO &dev)
{
	memset(dev.cfg.raw, 0, sizeof(dev.cfg.raw));
	cl::pci::read(dev.bus, dev.slot, dev.func, 0, dev.cfg.raw, 0x100);
}

std::vector<PORT_DEVICE_INFO> cl::pci::get_port_devices(void)
{
	auto pci_devices = get_raw_pci_objects();

	std::vector<PORT_DEVICE_INFO> objects{};

	using namespace cl;

	for (auto &devf : pci_devices)
	{
		auto &dev = devf.data;
		if (devf.device_class != 0x00060400)
		{
			continue;
		}

		DWORD businfo = pci::read<DWORD>(dev.bus, dev.slot, dev.func, 0x18);
		BYTE  bus = ((BYTE*)&businfo)[0];
		BYTE  secondary_bus = ((BYTE*)&businfo)[1];
		BYTE  subordinate_bus = ((BYTE*)&businfo)[2];

		if (dev.bus != bus || dev.bus >= secondary_bus || dev.bus >= subordinate_bus)
			continue;

		BOOL endpoint_port = 0;
		if (secondary_bus == subordinate_bus)
		{
			endpoint_port = 1;
		}

		else if (secondary_bus < subordinate_bus)
		{
			if (get_devices_by_bus(pci_devices, subordinate_bus).size() == 0)
			{
				endpoint_port = 1;
			}
		}

		if (!endpoint_port)
		{
			continue;
		}

		PORT_DEVICE_INFO object{};
		object.self    = dev;
		object.devices = get_devices_by_bus(pci_devices, secondary_bus);

		//
		// option 1 BEGIN
		//
		BOOL is_empty = 0;
		if (object.devices.size() == 0 && pci::read<WORD>(dev.bus, dev.slot, dev.func, 0x04) == 0x404)
		{
			is_empty = 1;
		}

		if (!is_empty)
		{
			objects.push_back(object);
		}
		//
		// option 1 END
		//

		/*
		
		//
		// option 2 BEGIN
		//
		if (object.devices.size() == 0)
		{
			DWORD fixup = pci::read<DWORD>(secondary_bus, 0, 0, 0x04);
			if (fixup != 0 && fixup != 0xffffffff)
			{
				DEVICE_INFO pciobj{};
				pciobj.bus = secondary_bus;
				object.devices.push_back(pciobj);
			}
		}
		objects.push_back(object);
		//
		// option 2 END
		//
		*/
	}
	for (auto &obj : objects)
	{
		pci_initialize_cfg(obj.self);
		for (auto &dev : obj.devices)
		{
			pci_initialize_cfg(dev);
		}
	}
	return objects;
}

namespace func
{
	typedef union _virt_addr_t
	{
		QWORD value;
		struct
		{
			QWORD offset : 12;
			QWORD pt_index : 9;
			QWORD pd_index : 9;
			QWORD pdpt_index : 9;
			QWORD pml4_index : 9;
			QWORD reserved : 16;
		};
	} virt_addr_t, * pvirt_addr_t;

	pml4e_64 pml4[512]{};
	pdpte_64 pdpt[512]{};
	pde_64   pde[512]{};
	pte_64   pte[512]{};
}

static std::vector<EFI_MEMORY_DESCRIPTOR> get_memory_map_ex()
{
	using namespace cl;
	/*
	auto memory_map = controller->get_memory_map();

	if (memory_map.size())
		return memory_map;*/

	using namespace func;
	std::vector<EFI_MEMORY_DESCRIPTOR> map;

	static QWORD page_table = cl::get_virtual_address(system_cr3);
	if (!cl::vm::read(0, page_table, pml4, sizeof(pml4)))
	{
		return {};
	}

	//
	// qualifers
	//
	DWORD page_accessed  = 0;
	DWORD cache_enable   = 0;
	DWORD page_count     = 0;

	//
	// tables
	//
	int   pml4_index = 0;
	int   pdpt_index = 0;
	int   pde_index  = 0;
	int   pte_index  = 0;

	//
	// page info
	//
	QWORD physical_address  = 0;
	QWORD physical_previous = 0;
	virt_addr_t virtual_address{};
	virt_addr_t virtual_previous{};
	virt_addr_t virt{};

	for (pml4_index = 256; pml4_index < 512; pml4_index++) {
		physical_address         = pml4[pml4_index].page_frame_number << PAGE_SHIFT;
		virtual_address.value    = page_table;
		virtual_address.pt_index = pml4_index;

		if (!pml4[pml4_index].present || !cl::vm::read(0, virtual_address.value, pdpt, sizeof(pdpt)))
		{
			if (page_count) goto add_page;
			continue;
		}
		for (pdpt_index = 0; pdpt_index < 512; pdpt_index++) {
			physical_address         = pdpt[pdpt_index].page_frame_number << PAGE_SHIFT;
			virtual_address.value    = page_table;
			virtual_address.pd_index = pml4_index;
			virtual_address.pt_index = pdpt_index;
			if (!pdpt[pdpt_index].present || pdpt[pdpt_index].large_page)
			{
				if (page_count) goto add_page;
				continue;
			}

			if (get_virtual_address(physical_address) != virtual_address.value)
			{
				if (page_count) goto add_page;
				continue;
			}
			
			if (!cl::vm::read(0, virtual_address.value, pde, sizeof(pde)))
			{
				if (page_count) goto add_page;
				continue;
			}

			for (pde_index = 0; pde_index < 512; pde_index++) {
				physical_address           = pde[pde_index].page_frame_number << PAGE_SHIFT;
				virtual_address.value      = page_table;
				virtual_address.pdpt_index = pml4_index;
				virtual_address.pd_index   = pdpt_index;
				virtual_address.pt_index   = pde_index;
				if (!pde[pde_index].present || pde[pde_index].large_page)
				{
					if (page_count) goto add_page;
					continue;
				}

				if (get_virtual_address(physical_address) != virtual_address.value)
				{
					if (page_count) goto add_page;
					continue;
				}

				if (!cl::vm::read(0, virtual_address.value, pte, sizeof(pte)))
				{
					if (page_count) goto add_page;
					continue;
				}

				for (pte_index = 0; pte_index < 512; pte_index++)
				{
					physical_address           = pte[pte_index].page_frame_number << PAGE_SHIFT;
					virtual_address.value      = page_table;
					virtual_address.pml4_index = pml4_index;
					virtual_address.pdpt_index = pdpt_index;
					virtual_address.pd_index   = pde_index;
					virtual_address.pt_index   = pte_index;
					if (!pte[pte_index].present || physical_address == 0 || pte[pte_index].execute_disable)
					{
						if (page_count) goto add_page;
						continue;
					}

					if (PAGE_ALIGN(cl::get_virtual_address(physical_address)) != 0)
					{
						if (page_count) goto add_page;
						continue;
					}

					if ((physical_address - physical_previous) == 0x1000)
					{
						page_count++;
						if (pte[pte_index].accessed)
						{
							page_accessed++;
						}
						if (!pte[pte_index].page_level_cache_disable)
						{
							cache_enable++;
						}
						if (page_count == 1)
						{
							virt = virtual_previous;
						}
					}
					else
					{
					add_page:
						if (page_count)
						{
							//
							// these we dont need, lets log them still to look cool
							//
							if (page_accessed)
							{
								QWORD dphys = physical_previous - (page_count * 0x1000);
								DWORD dnump = page_count + 1;
								QWORD dvirt = virt.value;
								LOG_DEBUG("[%llx:%llx] %llx\n", dphys, dphys + (dnump * 0x1000), dvirt);
							}
						}
						if (page_count > 0 && page_accessed && (page_count == cache_enable))
						{
							EFI_MEMORY_DESCRIPTOR descriptor{};
							descriptor.Attribute     = 0x800000000000000f;
							descriptor.Type          = 5;
							descriptor.VirtualStart  = virt.value;
							descriptor.PhysicalStart = physical_previous - (page_count * 0x1000);
							descriptor.NumberOfPages = page_count + 1;
							map.push_back(descriptor);
						}
						page_count    = 0;
						page_accessed = 0;
						cache_enable  = 0;
					}
					physical_previous = physical_address;
					virtual_previous  = virtual_address;
				}
			}
		}
	}
	return map;
}

std::vector<EFI_MEMORY_DESCRIPTOR> cl::efi::get_memory_map()
{
	auto memory_map = get_memory_map_ex();

	for (auto &map : memory_map)
	{
		if (PciIoAddressPhysical >= map.PhysicalStart &&
			PciIoAddressPhysical <= (map.PhysicalStart + (map.NumberOfPages * 0x1000))
			)
		{
			map.Type = 11;
		}

		else if (map.PhysicalStart >= PciIoAddressPhysical && map.PhysicalStart <= 0x100000000)
		{
			map.Type = 11;
		}
	}

	return memory_map;
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

EFI_MEMORY_DESCRIPTOR cl::efi::get_dxe_range(
	EFI_MODULE_INFO module,
	std::vector<EFI_MEMORY_DESCRIPTOR>& page_table_list
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

