#include "client.h"
#include "clrt/clrt.h"
#include <chrono>
#pragma warning (disable: 4996)
#include "ia32.hpp"

QWORD cl::ntoskrnl_base;

std::vector<QWORD> cl::global_export_list;

//
// NTOSKRNL_EXPORT define variables are automatically resolved in cl::initialize
//
NTOSKRNL_EXPORT(MmMapIoSpace);
NTOSKRNL_EXPORT(MmUnmapIoSpace);
NTOSKRNL_EXPORT(HalPrivateDispatchTable);
NTOSKRNL_EXPORT(MmGetVirtualForPhysical);
NTOSKRNL_EXPORT(PsInitialSystemProcess);
NTOSKRNL_EXPORT(HalEnumerateEnvironmentVariablesEx);
NTOSKRNL_EXPORT(KeQueryPrcbAddress);

static void unsupported_error(void)
{
	LOG_RED(
		"Usermode connector is not supported,\n"
		"please launch driver or change your target action\n"
	);
}

namespace cl
{
	clrt   *clrtptr = 0;

	BOOL   initialized;
	BOOL   kernel_access;

	QWORD  win32k_memmove;


	QWORD  Offset_InterruptObject;
	QWORD  PciDriverObject;
	QWORD  AcpiDriverObject;
	QWORD  UsbccgpDriverObject;
	QWORD  HidUsbBase;
	QWORD  HidUsbDriverObject;
	QWORD  MouHidBase;
	QWORD  MouhidDriverObject;


	DWORD  PciClassIdOffset;
	DWORD  PciBusLocationOffset;


	QWORD HalpPciMcfgTableCount;
	QWORD HalpPciMcfgTable;
	QWORD MmPfnDatabase;
	QWORD MmPteBase;
	QWORD system_cr3;
	QWORD PciIoAddressPhysical;
	QWORD PciIoAddressVirtual;


	QWORD  kernel_memcpy;          // nekoswap mode
	QWORD  kernel_memcpy_table;    // nekoswap mode
	QWORD  kernel_memcpy_original; // nekoswap mode

	QWORD  kernel_swapfn;          // nekoswap mode
	QWORD  kernel_swapfn_table;    // nekoswap mode
	QWORD  kernel_swapfn_original; // nekoswap mode

	static QWORD get_processor_block(int index)
	{
		DWORD eax              = index;
		QWORD KiProcessorBlock = vm::get_relative_address(4, KeQueryPrcbAddress + 2, 3, 7);
		QWORD prcb             = vm::read<QWORD>(4, KiProcessorBlock + (eax*8));
		return prcb;
	}
}

static QWORD get_kernel_export(PCSTR path, QWORD base, PCSTR export_name)
{
	HMODULE mod = LoadLibraryA(path);

	if (mod == 0)
	{
		return 0;
	}

	QWORD export_address = (QWORD)GetProcAddress(mod, export_name);
	if (export_address == 0)
	{
		goto cleanup;
	}

	export_address = export_address - (QWORD)mod;
	export_address = export_address + base;

cleanup:
	FreeLibrary(mod);
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

		if (section_characteristics & 0x00000020)
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

QWORD get_win32_table_ptr(cl::client *controller, PCSTR function_name, QWORD function_address, QWORD *original)
{
	using namespace cl;

	QWORD table_ptr     = 0;
	QWORD nt_user_func  = 0;
	QWORD nt_user_table = 0;
	QWORD W32GetSessionState = 0;
	
	for (auto &entry : get_kernel_modules())
	{
		if (!_strcmpi(entry.name.c_str(), "win32k.sys"))
		{
			nt_user_table = get_kernel_export(entry.path.c_str(), entry.base, "ext_ms_win_moderncore_win32k_base_sysentry_l1_table");
			if (nt_user_table)
			{
				nt_user_table = nt_user_table + 0x70;
			}
			W32GetSessionState = get_kernel_export(entry.path.c_str(), entry.base, "W32GetSessionState");
		}

		if (!_strcmpi(entry.name.c_str(), "win32kfull.sys"))
		{
			nt_user_func = get_kernel_export(entry.path.c_str(), entry.base, function_name);
			*original = nt_user_func;
		}

		if (nt_user_table && nt_user_func)
		{
			break;
		}
	}

	//
	// 24H2
	//
	if (W32GetSessionState)
	{
		DWORD session_id = *(DWORD*)(__readgsqword(0x60) + 0x2c0);
		QWORD tmp        = vm::get_relative_address(4, W32GetSessionState + 0xB, 1, 5);

		if (session_id)
		{
			tmp = vm::get_relative_address(4, tmp + 0x14, 3, 7);
			tmp = vm::read<QWORD>(4, tmp);
			session_id = session_id - 1;
			tmp = vm::read<QWORD>(4, tmp + (session_id * sizeof(QWORD)));
		}
		else
		{
			tmp = vm::get_relative_address(4, tmp + 0x07, 3, 7);
			tmp = vm::read<QWORD>(4, tmp);
		}

		QWORD rdx,rax;
		rdx = km::read<QWORD>(tmp + 0x88);

		if (!_strcmpi(function_name, "NtGdiGetEmbUFI"))
		{
			rax = km::read<QWORD>(rdx + 0x138);
			rax = rax + 0x04B8;
		}
		else if (!_strcmpi(function_name, "NtGdiGetUFI"))
		{
			rax = km::read<QWORD>(rdx + 0x138);
			rax = rax + 0x0600;
		}
		else
		{
			rax = 0;
		}

		table_ptr = rax;
	}

	if (nt_user_func == 0 || nt_user_table == 0)
	{
		return table_ptr;
	}

	typedef struct {
		QWORD  table_address;
		QWORD* table_names;
		QWORD  unk; // win11 only
	} TABLE_ENTRY;

	DWORD next_off = sizeof(TABLE_ENTRY);

	QWORD buffer   = 0;
	controller->read_kernel(nt_user_table + 0x10, &buffer, sizeof(buffer));
	if (buffer != 0)
	{
		next_off -= 8;
	}

	QWORD table_entry = nt_user_table;
	while (1)
	{
		TABLE_ENTRY entry{};
		controller->read_kernel(table_entry, &entry, next_off);
		if (!entry.table_address)
		{
			break;
		}

		QWORD num_entries = 0;
		controller->read_kernel((QWORD)(entry.table_names + 3), &num_entries, sizeof(num_entries));

		for (QWORD i = 0; i < num_entries; i++)
		{
			QWORD func = 0;
			controller->read_kernel(entry.table_address + (i * sizeof(QWORD)), &func, sizeof(func));

			if (func == nt_user_func)
			{
				table_ptr = entry.table_address + (i * sizeof(QWORD));
				break;
			}

			if (function_address && func == function_address)
			{
				table_ptr = entry.table_address + (i * sizeof(QWORD));
				break;
			}
		}

		if (table_ptr) break;

		table_entry = table_entry + next_off;
	}

	return table_ptr;
}

bool EnablePrivilege(const char* Privilege)
{
	HANDLE Token;
	if (!OpenProcessToken(HANDLE(-1), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
		return false;

	LUID Luid;
	if (!LookupPrivilegeValueA(0, Privilege, &Luid))
		return false;

	TOKEN_PRIVILEGES TokenState = { 1, { Luid, SE_PRIVILEGE_ENABLED } };
	if (!AdjustTokenPrivileges(Token, 0, &TokenState, sizeof(TOKEN_PRIVILEGES), 0, 0))
		return false;

	CloseHandle(Token);
	return true;
}

BOOL cl::initialize(void)
{
	if (initialized != 0)
	{
		return 1;
	}

	EnablePrivilege("SeDebugPrivilege");

	for (auto &entry : get_kernel_modules())
	{
		if (!_strcmpi(entry.name.c_str(), "ntoskrnl.exe"))
		{
			ntoskrnl_base = entry.base;
			for (auto& i : global_export_list)
			{
				QWORD temp = *(QWORD*)i;

				*(QWORD*)i = get_kernel_export(entry.path.c_str(), entry.base, (PCSTR)temp);
				if (*(QWORD*)i == 0)
				{
					LOG_RED("ntoskrnl.exe export %s not found\n", (PCSTR)temp);
					return 0;
				}
			}

			Offset_InterruptObject = get_kernel_pattern(
				entry.path.c_str(), entry.base,
				(BYTE*)"\x65\x48\x8B\x14\x25\x20\x00\x00\x00\x48\x81\xC2",
				(BYTE*)"xxxxxxxxxxxx"
			);

			if (Offset_InterruptObject == 0)
			{
				LOG_RED("ntoskrnl.exe Offset_InterruptObject not found\n");
				return 0;
			}

			Offset_InterruptObject = Offset_InterruptObject + 0x09;
			Offset_InterruptObject = Offset_InterruptObject + 0x03;
		}

		if (!_strcmpi(entry.name.c_str(), "pci.sys"))
		{
			HMODULE local_module = LoadLibraryA(entry.path.c_str());
			QWORD temp_address = FindPattern((QWORD)local_module, (BYTE*)"\x48\x8B\xCF\x48\x09\x87", (BYTE*)"xxxxxx");
			if (temp_address == 0)
			{
				goto cleanup2;
			}
			temp_address = temp_address + 0x0A;
			temp_address = (temp_address + 5) + *(int*)(temp_address + 1);
			temp_address = temp_address + 0x07;
			temp_address = (temp_address + 5) + *(int*)(temp_address + 1);
			while (*(BYTE*)(temp_address) != 0x41) temp_address++;
			PciClassIdOffset = *(BYTE*)(temp_address + 1);

			temp_address = FindPattern((QWORD)local_module, (BYTE*)"\x8B\x45\x00\x0F\xB6\xC8\x41", (BYTE*)"xx?xxxx");
			if (temp_address == 0)
			{
				goto cleanup2;
			}

			PciBusLocationOffset = *(BYTE*)(temp_address + 2);

			temp_address = FindPattern((QWORD)local_module, (BYTE*)"\x48\x8B\x1D\x00\x00\x00\x00\x75", (BYTE*)"xxx????x");
			if (temp_address == 0)
			{
				goto cleanup2;
			}

			temp_address    = temp_address - (QWORD)local_module;
			temp_address    = temp_address + entry.base;
			PciDriverObject = temp_address;
		cleanup2:
			FreeLibrary(local_module);
			if (temp_address == 0)
			{
				LOG_RED("pci.sys DriverObject not found\n");
				return 0;
			}
		}

		if (!_strcmpi(entry.name.c_str(), "acpi.sys"))
		{
			AcpiDriverObject = get_kernel_pattern(
				entry.path.c_str(), entry.base, (BYTE*)"\x48\x8B\x0D\x00\x00\x00\x00\xB2\x00\x48\xFF\x15", (BYTE*)"xxx????x?xxx");

			if (AcpiDriverObject == 0)
			{
				LOG_RED("acpi.sys AcpiDriverObject not found\n");
				return 0;
			}
		}

		if (!_strcmpi(entry.name.c_str(), "usbccgp.sys"))
		{
			HMODULE ntos = LoadLibraryA(entry.path.c_str());

			QWORD export_address = FindPattern((QWORD)ntos, (BYTE*)"\x48\x8B\x1D\x00\x00\x00\x00\x48\x8D\x15", (BYTE*)"xxx????xxx");
			if (export_address == 0)
			{
				export_address = (QWORD)FindPattern((QWORD)ntos, (BYTE*)"\x48\x8B\xD3\x48\x89\x1D\x00\x00\x00\x00\x48\x8D\x0D", (BYTE*)"xxxxxx????xxx");
				if (export_address == 0)
				{
					goto cleanup;
				}
				export_address += 0x03;
			}
			export_address = (export_address + 7) + *(int*)(export_address + 3);
			export_address = export_address - (QWORD)ntos;
			export_address = export_address + entry.base;
		cleanup:
			FreeLibrary(ntos);
			if (export_address == 0)
			{
				LOG_RED("usbccgp.sys UsbccgpDriverObject not found\n");
				return 0;
			}
			UsbccgpDriverObject = export_address;
		}

		if (!_strcmpi(entry.name.c_str(), "hidusb.sys"))
		{
			HidUsbBase = entry.base;
		}

		if (!_strcmpi(entry.name.c_str(), "mouhid.sys"))
		{
			MouHidBase = entry.base;
		}

		if (!_strcmpi(entry.name.c_str(), "win32kfull.sys"))
		{
			win32k_memmove = get_kernel_export(entry.path.c_str(), entry.base, "memmove");
		}
	}

	client *controller = 0;
	clrt  *rt = new clrt();

	if (controller == 0 && rt->initialize())
	{
		controller = rt;
		clrtptr    = rt;
	}
	else
	{
		delete rt; rt = 0;
	}

	initialized = 1;
		
	if (rt)
	{
		if (ntoskrnl_base == 0)
		{
			LOG_RED("Run as Administrator\n");
			return 0;
		}

		if (PciDriverObject == 0 || AcpiDriverObject == 0 || win32k_memmove == 0 || UsbccgpDriverObject == 0)
		{
			return 0;
		}



		LoadLibraryA("user32.dll");
		kernel_swapfn_table = get_win32_table_ptr(controller, "NtGdiGetUFI", 0, &kernel_swapfn_original);
		kernel_memcpy_table = get_win32_table_ptr(controller, "NtGdiGetEmbUFI", win32k_memmove, &kernel_memcpy_original);
		kernel_memcpy = (QWORD)GetProcAddress(LoadLibraryA("win32u.dll"), "NtGdiGetEmbUFI");
		kernel_swapfn = (QWORD)GetProcAddress(LoadLibraryA("win32u.dll"), "NtGdiGetUFI");

		if (kernel_swapfn_table == 0 || kernel_memcpy_table == 0)
		{
			LOG_RED("Failed to locate win32k functions\n");
			return 0;
		}
		else
		{
			controller->write_kernel(kernel_memcpy_table, &win32k_memmove, sizeof(win32k_memmove));
			kernel_access = 1;

			if (rt) delete rt;
			rt = 0;
			controller = 0;
			clrtptr = 0;
		}

		kernel_access = 1;

		QWORD table_entry = HalPrivateDispatchTable;
		table_entry       = vm::read<QWORD>(4, table_entry + 0xA0);
		table_entry       = table_entry + 0x1B;
		table_entry       = (table_entry + 5) + vm::read<INT>(4, table_entry + 1);

		while (1)
		{
			QWORD data     = vm::read<QWORD>(4, table_entry);
			PBYTE data_ptr = (PBYTE)&data;
			if (data_ptr[0] == 0xE8 && *(WORD*)(data_ptr+5) == 0xC084)
			{
				break;
			}
			table_entry++;
		}
		table_entry = (table_entry + 5) + vm::read<INT>(4, table_entry + 1);
		while (1)
		{
			DWORD data     = vm::read<DWORD>(4, table_entry);
			PBYTE data_ptr = (PBYTE)&data;
			if (data_ptr[0] == 0x4C && *(WORD*)(data_ptr+1) == 0x0d8b)
			{
				break;
			}
			table_entry++;
		}


		HalpPciMcfgTable       = vm::get_relative_address(4, table_entry, 3, 7);
		HalpPciMcfgTableCount  = HalpPciMcfgTable - 0x18;

		MmPfnDatabase          = vm::read<QWORD>(4, MmGetVirtualForPhysical + 0x0E + 0x02) - 0x08;
		MmPteBase              = vm::read<QWORD>(4, MmGetVirtualForPhysical + 0x20 + 0x02);

		AcpiDriverObject       = vm::read<QWORD>(4, vm::get_relative_address(4, AcpiDriverObject, 3, 7));
		PciDriverObject        = vm::read<QWORD>(4, vm::get_relative_address(4, PciDriverObject, 3, 7));
		UsbccgpDriverObject    = vm::read<QWORD>(4, UsbccgpDriverObject);
		Offset_InterruptObject = vm::read<DWORD>(4, Offset_InterruptObject);

		system_cr3             = vm::read<QWORD>(4, vm::read<QWORD>(4, PsInitialSystemProcess) + 0x28);

		PciIoAddressPhysical   = pci::get_physical_address(0, 0);

		std::vector<QWORD> table = efi::get_runtime_table();

		QWORD efi_func = 0;
		if (table.size()) efi_func = (QWORD)PAGE_ALIGN(table[0]);
				
		while (1)
		{
			QWORD temp = get_physical_address(efi_func);
			if (PAGE_ALIGN(temp))
			{
				if (PciIoAddressPhysical == temp)
				{
					PciIoAddressVirtual = efi_func;
					break;
				}
				efi_func += PAGE_SIZE;
			}
			else
			{
				break;
			}
		}

		//
		// resolve mouhid driver object
		//
		QWORD usb_device_object = km::read<QWORD>(UsbccgpDriverObject + 0x08);
		do
		{
			QWORD attached_device = cl::vm::read<QWORD>(4, usb_device_object + 0x18);
			QWORD device_object = 0;
			while (attached_device)
			{
				device_object = attached_device;
				attached_device = cl::vm::read<QWORD>(4, attached_device + 0x18);
			}

			if (device_object)
			{
				QWORD drv_obj = km::read<QWORD>(device_object + 0x08);
				QWORD drv_start = km::read<QWORD>(drv_obj + 0x18);
				if (drv_start == HidUsbBase)
				{
					HidUsbDriverObject = drv_obj;
					break;
				}
			}

			usb_device_object = km::read<QWORD>(usb_device_object + 0x10);
		} while (usb_device_object);


		QWORD hidusb_dev = km::read<QWORD>(HidUsbDriverObject + 0x08);
		do
		{
			QWORD mouhid = km::read<QWORD>(hidusb_dev + 0x18);
			if (mouhid)
			{
				QWORD drv_obj = km::read<QWORD>(mouhid + 0x08);
				QWORD drv_start = km::read<QWORD>(drv_obj + 0x18);

				if (drv_start == MouHidBase)
				{
					MouhidDriverObject = drv_obj;
					break;
				}
			}
			hidusb_dev = km::read<QWORD>(hidusb_dev + 0x10);
		} while (hidusb_dev);
	}
	return 1;
}

void cl::terminate(void)
{
	if (!initialized)
	{
		return;
	}

	if (!kernel_access)
	{
		return;
	}

	km::write<QWORD>(kernel_swapfn_table, kernel_swapfn_original);
	km::write<QWORD>(kernel_memcpy_table, kernel_memcpy_original);

	initialized = 0;
}

QWORD cl::get_physical_address(QWORD virtual_address)
{
	if (!kernel_access)
	{
		unsupported_error();
		return 0;
	}

	if (virtual_address == 0) return 0;

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

#define MiGetVirtualAddressMappedByPte(PteAddress) (PVOID)((LONG_PTR)(((LONG_PTR)(PteAddress) - (ULONG_PTR)(MmPteBase)) << 25L) >> 16)
QWORD cl::get_virtual_address(QWORD physical_address)
{
	if (!kernel_access)
	{
		unsupported_error();
		return 0;
	}

	QWORD index = physical_address >> PAGE_SHIFT;
	QWORD pfn_entry = (MmPfnDatabase + (index * 0x30));
	QWORD pte = vm::read<QWORD>(0, pfn_entry + 0x08);
	if (pte == 0)
	{
		return 0;
	}
	QWORD va = (QWORD)MiGetVirtualAddressMappedByPte((QWORD)pte);
	return (physical_address & 0xFFF) + va;
}

QWORD cl::get_pci_driver_object(void)
{
	return PciDriverObject;
}

DWORD cl::get_pci_class_id(QWORD pci_extension)
{
	return vm::read<BYTE>(4, pci_extension + PciClassIdOffset + 0) << 16 |
		vm::read<BYTE>(4, pci_extension + PciClassIdOffset + 1) << 8 | vm::read<BYTE>(4, pci_extension + PciClassIdOffset + 2);
}

void cl::get_pci_location(QWORD pci_extension, BYTE* bus, BYTE* slot, BYTE* func)
{
	typedef struct _PCI_SLOT_NUMBER {
		union {
			struct {
				ULONG   DeviceNumber : 5;
				ULONG   FunctionNumber : 3;
				ULONG   Reserved : 24;
			} bits;
			ULONG   AsULONG;
		} u;
	} PCI_SLOT_NUMBER, * PPCI_SLOT_NUMBER;

	*bus = km::read<DWORD>(pci_extension + PciBusLocationOffset) & 0xFF;

	PCI_SLOT_NUMBER temp{};
	temp.u.AsULONG = km::read<DWORD>(pci_extension + PciBusLocationOffset + 0x04);

	*slot = temp.u.bits.DeviceNumber;
	*func = temp.u.bits.FunctionNumber;
}

QWORD cl::get_acpi_driver_object(void)
{
	return AcpiDriverObject;
}

QWORD cl::get_mouhid_driver_object(void)
{
	return MouhidDriverObject;
}

QWORD cl::get_hidusb_driver_object(void)
{
	return HidUsbDriverObject;
}

QWORD cl::get_interrupt_object(DWORD index)
{
	QWORD rdx;
	rdx = get_processor_block(0);
	rdx = rdx + Offset_InterruptObject;
	return vm::read<QWORD>(4, (rdx + (index * 8)));
}

BOOL cl::vm::read(DWORD pid, QWORD address, PVOID buffer, QWORD length)
{
	if (!initialize()) return 0;

	if (pid == 0 || pid == 4)
	{
		return km::read(address, buffer, length);
	}

	HANDLE process_handle = OpenProcess(PROCESS_VM_READ, 0, pid);

	//
	// access denied / process not found
	//
	if (!process_handle)
	{
		return 0;
	}

	BOOL status = ReadProcessMemory(process_handle, (LPCVOID)address, buffer, length, 0);

	//
	// close process object and return read status
	//
	CloseHandle(process_handle);
	return status;
}

BOOL cl::vm::write(DWORD pid, QWORD address, PVOID buffer, QWORD length)
{
	if (!initialize()) return 0;

	if (pid == 0 || pid == 4)
	{
		return km::write(address, buffer, length);
	}

	HANDLE process_handle = OpenProcess(PROCESS_VM_READ, 0, pid);

	//
	// access denied / process not found
	//
	if (!process_handle)
	{
		return 0;
	}

	BOOL status = WriteProcessMemory(process_handle, (LPVOID)address, buffer, length, 0);

	//
	// close process object and return read status
	//
	CloseHandle(process_handle);
	return status;
}

BOOL cl::km::read(QWORD address, PVOID buffer, QWORD length)
{
	if (clrtptr)
	{
		return clrtptr->read_kernel(address, buffer, length);
	}

	if (!kernel_access)
	{
		unsupported_error();
		return 0;
	}

	void* (__fastcall * func)(PVOID, PVOID, QWORD);
	*(QWORD*)&func = kernel_memcpy;
	func(buffer, (PVOID)address, length);
	return 1;
}

BOOL cl::km::write(QWORD address, PVOID buffer, QWORD length)
{
	if (clrtptr)
	{
		return clrtptr->write_kernel(address, buffer, length);
	}

	if (!kernel_access)
	{
		unsupported_error();
		return 0;
	}

	void* (*func)(PVOID, PVOID, QWORD);
	*(QWORD*)&func = kernel_memcpy;
	func((PVOID)address, (PVOID)buffer, length);
	return 1;
}

QWORD cl::km::call(QWORD kernel_address, QWORD r1, QWORD r2, QWORD r3, QWORD r4, QWORD r5, QWORD r6, QWORD r7)
{
	if (!kernel_access)
	{
		unsupported_error();
		return 0;
	}

	km::write<QWORD>(kernel_swapfn_table, kernel_address);
	QWORD (*func)(QWORD, QWORD, QWORD, QWORD, QWORD, QWORD, QWORD);
	*(QWORD*)&func = kernel_swapfn;
	QWORD ret = func(r1, r2, r3, r4, r5, r6, r7);
	km::write<QWORD>(kernel_swapfn_table, kernel_swapfn_original);
	return ret;
}

BOOL cl::io::read(QWORD address, PVOID buffer, QWORD length)
{
	if (!kernel_access)
	{
		unsupported_error();
		return 0;
	}

	PVOID mem = (PVOID)km::call(MmMapIoSpace, address, length, 0);
	if (mem)
	{
		km::read((QWORD)mem, buffer, length);
		km::call(MmUnmapIoSpace, (QWORD)mem, length);
		return 1;
	}
	return 0;
}

BOOL cl::io::write(QWORD address, PVOID buffer, QWORD length)
{
	if (!kernel_access)
	{
		unsupported_error();
		return 0;
	}

	PVOID mem = (PVOID)km::call(MmMapIoSpace, address, length, 0);
	if (mem)
	{
		km::write((QWORD)mem, buffer, length);
		km::call(MmUnmapIoSpace, (QWORD)mem, length);
		return 1;
	}
	return 0;
}

QWORD cl::pci::get_physical_address(ULONG bus, ULONG slot)
{
	if (!kernel_access)
	{
		unsupported_error();
		return 0;
	}

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

template <typename t>
t read_io_phys_virt(BOOL phys, QWORD address)
{
	using namespace cl;
	if (phys)
		return io::read<t>(address);
	return vm::read<t>(0, address);
}

template <typename t>
BOOL write_io_phys_virt(BOOL phys, QWORD address, t value)
{
	using namespace cl;
	if (phys)
	{
		return io::write<t>(address, value);
	}
	return vm::write<t>(0, address, value);
}

static BOOL read_io_address(BOOL phys, QWORD address, PVOID buffer, DWORD length)
{
	using namespace cl;
	using namespace pci;

	DWORD location = 0;
	DWORD data_left = length;

	while (data_left)
	{
		if (data_left >= 4)
		{
			DWORD data = read_io_phys_virt<DWORD>(phys, address + location);
			*(DWORD*)((PBYTE)buffer + location) = data;
			location += 4;
		}
		else if (data_left >= 2)
		{
			WORD data = read_io_phys_virt<WORD>(phys, address + location);
			*(WORD*)((PBYTE)buffer + location) = data;
			location += 2;
		}
		else
		{
			BYTE data = read_io_phys_virt<BYTE>(phys, address + location);
			*(BYTE*)((PBYTE)buffer + location) = data;
			location += 1;
		}
		data_left = length - location;
	}
	return 1;
}

static BOOL write_io_address(BOOL phys, QWORD address, PVOID buffer, DWORD length)
{
	using namespace cl;
	using namespace pci;

	DWORD location = 0;
	DWORD data_left = length;

	while (data_left)
	{
		if (data_left >= 4)
		{
			write_io_phys_virt<DWORD>(phys, address + location, *(DWORD*)((PBYTE)buffer + location));
			location += 4;
		}
		else if (data_left >= 2)
		{
			write_io_phys_virt<WORD>(phys, address + location, *(WORD*)((PBYTE)buffer + location));
			location += 2;
		}
		else
		{
			write_io_phys_virt<BYTE>(phys, address + location, *(BYTE*)((PBYTE)buffer + location));
			location += 1;
		}
		data_left = length - location;
	}
	return 1;
}

BOOL cl::pci::read(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD size)
{
	if (!kernel_access)
	{
		unsupported_error();
		return 0;
	}

	if (PciIoAddressVirtual)
	{
		QWORD device = get_physical_address(bus, slot);
		device = device + (func << 12l);

		QWORD delta = device - PciIoAddressPhysical;
		QWORD virtu = PciIoAddressVirtual + delta;

		return read_io_address(0, virtu + offset, buffer, size);
	}

	QWORD device = get_physical_address(bus, slot);

	if (device == 0)
		return 0;

	device = device + (func << 12l);
	return read_io_address(1, device + offset, buffer, size);
}

BOOL cl::pci::write(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD size)
{
	if (!kernel_access)
	{
		unsupported_error();
		return 0;
	}

	if (PciIoAddressVirtual)
	{
		QWORD device = get_physical_address(bus, slot);
		device = device + (func << 12l);

		QWORD delta = device - PciIoAddressPhysical;
		QWORD virtu = PciIoAddressVirtual + delta;

		return write_io_address(0, virtu + offset, buffer, size);
	}

	QWORD device = get_physical_address(bus, slot);

	if (device == 0)
		return 0;

	device = device + (func << 12l);
	return write_io_address(1, device + offset, buffer, size);
}

namespace memory_map
{
	pml4e_64 pml4[512]{};
	pdpte_64 pdpt[512]{};
	pde_64   pde[512]{};
	pte_64   pte[512]{};
}

std::vector<EFI_MEMORY_DESCRIPTOR> cl::efi::get_memory_map()
{
	if (!kernel_access)
	{
		unsupported_error();
		return {};
	}


	using namespace memory_map;

	std::vector<EFI_MEMORY_DESCRIPTOR> map;

	static QWORD page_table = cl::get_virtual_address(system_cr3);

	if (page_table == 0) return {};

	if (!cl::vm::read(0, page_table, pml4, sizeof(pml4)))
	{
		return {};
	}

	//
	// qualifers
	//
	DWORD page_accessed = 0;
	DWORD cache_enable = 0;
	DWORD page_count = 0;

	//
	// tables
	//
	int   pml4_index = 0;
	int   pdpt_index = 0;
	int   pde_index = 0;
	int   pte_index = 0;

	//
	// page info
	//
	QWORD physical_address = 0;
	QWORD physical_previous = 0;
	virt_addr_t virtual_address{};
	virt_addr_t virtual_previous{};
	virt_addr_t virt{};

	virt.value = ntoskrnl_base;
	for (pml4_index = virt.pml4_index; pml4_index < 512; pml4_index++) {
		physical_address = pml4[pml4_index].page_frame_number << PAGE_SHIFT;
		virtual_address.value = page_table;
		virtual_address.pt_index = pml4_index;

		if (!pml4[pml4_index].present || !cl::vm::read(0, virtual_address.value, pdpt, sizeof(pdpt)))
		{
			if (page_count) goto add_page;
			continue;
		}
		for (pdpt_index = 0; pdpt_index < 512; pdpt_index++) {
			physical_address = pdpt[pdpt_index].page_frame_number << PAGE_SHIFT;
			virtual_address.value = page_table;
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
				physical_address = pde[pde_index].page_frame_number << PAGE_SHIFT;
				virtual_address.value = page_table;
				virtual_address.pdpt_index = pml4_index;
				virtual_address.pd_index = pdpt_index;
				virtual_address.pt_index = pde_index;
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
					physical_address = pte[pte_index].page_frame_number << PAGE_SHIFT;
					virtual_address.value = page_table;
					virtual_address.pml4_index = pml4_index;
					virtual_address.pdpt_index = pdpt_index;
					virtual_address.pd_index = pde_index;
					virtual_address.pt_index = pte_index;
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
							/*
							if (page_accessed)
							{
								QWORD dphys = physical_previous - (page_count * 0x1000);
								DWORD dnump = page_count + 1;
								QWORD dvirt = virt.value;
								LOG_DEBUG("[%llx:%llx] %llx [accessed: %d, cached: %d]\n", dphys, dphys + (dnump * 0x1000), dvirt, page_accessed, (page_count == cache_enable));
							}
							*/
						}
						if (page_count > 0 && page_accessed && (page_count == cache_enable))
						{
							EFI_MEMORY_DESCRIPTOR descriptor{};
							descriptor.Attribute = 0x800000000000000f;
							descriptor.Type = 5;
							descriptor.VirtualStart = virt.value;
							descriptor.PhysicalStart = physical_previous - (page_count * 0x1000);
							descriptor.NumberOfPages = page_count + 1;
							map.push_back(descriptor);
						}
						page_count = 0;
						page_accessed = 0;
						cache_enable = 0;
					}
					physical_previous = physical_address;
					virtual_previous = virtual_address;
				}
			}
		}
	}

	for (auto &entry : map)
	{
		if (PciIoAddressPhysical >= entry.PhysicalStart &&
			PciIoAddressPhysical <= (entry.PhysicalStart + (entry.NumberOfPages * 0x1000))
			)
		{
			entry.Type = 11;
		}

		else if (entry.PhysicalStart >= PciIoAddressPhysical && entry.PhysicalStart <= 0x100000000)
		{
			entry.Type = 11;
		}

		if (entry.PhysicalStart == 0)
		{
			entry.Type = 609;
		}
	}

	return map;
}

std::vector<QWORD> cl::efi::get_runtime_table(void)
{
	if (!kernel_access)
	{
		unsupported_error();
		return {};
	}

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

