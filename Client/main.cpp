#define _CRT_SECURE_NO_WARNINGS
#include "client.h"

#define DEBUG
#define LOG(...) printf("[drvscan] "  __VA_ARGS__)
#ifdef DEBUG
#define DEBUG_LOG(...) printf("[drvscan] " __VA_ARGS__)
#else
#define DEBUG_LOG(...) // __VA_ARGS__
#endif

inline void FontColor(int color=0x07) { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color); }

#define LOG_RED(...) \
printf("[drvscan] "); \
FontColor(4); \
printf(__VA_ARGS__); \
FontColor(7); \

#define LOG_YELLOW(...) \
printf("[drvscan] "); \
FontColor(14); \
printf(__VA_ARGS__); \
FontColor(7); \

#define PRINT_RED(...) \
FontColor(4); \
printf(__VA_ARGS__); \
FontColor(7); \

#define PRINT_GREEN(...) \
FontColor(2); \
printf(__VA_ARGS__); \
FontColor(7); \

static void scan_efi(BOOL dump);
static BOOL dump_module_to_file(std::vector<FILE_INFO> modules, DWORD pid, FILE_INFO file);
static void scan_image(std::vector<FILE_INFO> modules, DWORD pid, FILE_INFO file, BOOL use_cache);
static void scan_pci(BOOL pcileech, BOOL dump_cfg, BOOL dump_bar);

int main(int argc, char **argv)
{
	//
	// reset font
	//
	FontColor(7);

	if (!cl::initialize())
	{
		LOG("driver is not running\n");
		printf("Press any key to continue . . .");
		return getchar();
	}

	if (argc < 2)
	{
		LOG("--help\n");
		return getchar();
	}
	
	DWORD scan = 0, pid = 4, savecache = 0, scanpci = 0, pcileech=0, cfg=0, bar=0, use_cache = 0, scanefi = 0, dump = 0;
	for (int i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "--help"))
		{
			printf(
				"\n\n"

				"--scan                 scan target process memory changes\n"
				"    --pid              target process id\n"
				"    --usecache         (optional) we use local cache instead of original PE files\n"
				"    --savecache        (optional) dump target process modules to disk\n\n"
				"--scanefi              scan abnormals from efi memory map\n"
				"    --dump             (optional) dump found abnormal to disk\n\n"
				"--scanpci              scan pci cards from the system\n"
				"    --pcileech         search pcileech-fpga cards\n"
				"    --cfg              print out every card cfg space\n"
				"    --bar              print out every card bar space\n\n\n"
			);

			printf("\nExample (verifying modules integrity by using cache):\n"
				"1.                     load malware\n"
				"1.                     drvscan.exe --scan --savecache --pid 4\n"
				"2.                     reboot the computer\n"
				"3.                     load windows without malware\n"
				"4.                     drvscan.exe --scan --usecache --pid 4\n"
				"all malware patches should be now visible\n\n"
			);
		}

		else if (!strcmp(argv[i], "--scan"))
		{
			scan = 1;
		}

		else if (!strcmp(argv[i], "--pid"))
		{
			pid = atoi(argv[i + 1]);
		}

		else if (!strcmp(argv[i], "--savecache"))
		{
			savecache = 1;
		}

		else if (!strcmp(argv[i], "--scanpci"))
		{
			scanpci = 1;
		}

		else if (!strcmp(argv[i], "--pcileech"))
		{
			pcileech = 1;
		}

		else if (!strcmp(argv[i], "--cfg"))
		{
			cfg = 1;
		}

		else if (!strcmp(argv[i], "--bar"))
		{
			bar = 1;
		}

		else if (!strcmp(argv[i], "--scanefi"))
		{
			scanefi = 1;
		}

		else if (!strcmp(argv[i], "--dump"))
		{
			dump = 1;
		}

		else if (!strcmp(argv[i], "--usecache"))
		{
			use_cache = 1;
		}
	}

	if (scanpci)
	{
		if (pcileech+cfg+bar!=0)
		{
			LOG("scanning PCIe devices\n");
			scan_pci(pcileech, cfg, bar);
			LOG("scan is complete\n");
		}
	}

	if (scan)
	{
		std::vector<FILE_INFO> modules;

		if (pid == 4)
		{
			modules = get_kernel_modules();
		}
		else
		{
			modules = get_user_modules(pid);
		}

		LOG("scanning modules\n");
		for (auto mod : modules)
		{
			if (savecache)
			{
				dump_module_to_file(modules, pid, mod);
			}
			else
			{
				scan_image(modules, pid, mod, use_cache);
			}
		}
		LOG("scan is complete\n");
	}

	if (scanefi)
	{
		LOG("scanning EFI\n");
		scan_efi(dump);
		LOG("scan is complete\n");
	}
	return 0;
}

const char *blkinfo(unsigned char info)
{
	switch (info)
	{
	case 1: return "pcileech";
	case 2: return "BME off";
	case 3: return "xilinx";
	case 4: return "invalid bridge";
	case 5: return "Hidden";
	}
	return "OK";
}

void PrintPcieConfiguration(unsigned char *cfg, int size)
{
	printf("\n>    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n\n");
	int line_counter=0;
	for (int i = 0; i < size; i++)
	{
		if (line_counter == 0)
		{
			if (i < 0xFF)
				printf("%02X   ", i);
			else
				printf("%02X  ", i);
		}
		line_counter++;
		printf("%02X ", cfg[i]);
		if (line_counter == 16)
		{
			printf("\n");
			line_counter=0;
		}	
	}
	printf("\n");
}

void PrintPcieBarSpace(DWORD bar)
{
	int line_counter=0;
	int row_max_count=0;
	for (int i = 0; i < 0x1000; i+=4)
	{
		unsigned int cfg = cl::io::read<unsigned int>(bar + i);
		line_counter++;
		printf("%08X,", cfg);
		if (line_counter == 4)
		{
			printf("\n");
			line_counter=0;
		}
		row_max_count++;

		if (row_max_count == (16*4))
		{
			printf("\n");
			row_max_count=0;
		}
	}
	printf("\n");
}

typedef struct _PCI_CAPABILITIES_HEADER {
  UCHAR CapabilityID;
  UCHAR Next;
} PCI_CAPABILITIES_HEADER, *PPCI_CAPABILITIES_HEADER;

typedef union _PCI_EXPRESS_CAPABILITIES_REGISTER {
	struct {
	USHORT CapabilityVersion  :4;
	USHORT DeviceType  :4;
	USHORT SlotImplemented  :1;
	USHORT InterruptMessageNumber  :5;
	USHORT Rsvd  :2;
	};
	USHORT AsUSHORT;
} PCI_EXPRESS_CAPABILITIES_REGISTER, *PPCI_EXPRESS_CAPABILITIES_REGISTER;

typedef struct _PCI_EXPRESS_CAPABILITY {
	PCI_CAPABILITIES_HEADER                    Header;
	PCI_EXPRESS_CAPABILITIES_REGISTER          ExpressCapabilities;
} PCI_EXPRESS_CAPABILITY, *PPCI_EXPRESS_CAPABILITY;

typedef enum {

    PciExpressEndpoint = 0,
    PciExpressLegacyEndpoint,
    PciExpressRootPort = 4,
    PciExpressUpstreamSwitchPort,
    PciExpressDownstreamSwitchPort,
    PciExpressToPciXBridge,
    PciXToExpressBridge,
    PciExpressRootComplexIntegratedEndpoint,
    PciExpressRootComplexEventCollector
} PCI_EXPRESS_DEVICE_TYPE;

DWORD get_port_type(unsigned char *cfg)
{
	BYTE cap = *(BYTE*)(cfg + 0x34);
	if (cap == 0) return 0;

	unsigned char *pm = cfg + cap;
	if (pm[1] == 0) return 0;

	unsigned char *msi = cfg + pm[1];
	if (msi[1] == 0) return 0;

	return ((PPCI_EXPRESS_CAPABILITY)(cfg + msi[1]))->ExpressCapabilities.DeviceType;
}

#define GET_BIT(data, bit) ((data >> bit) & 1)
#define GET_BITS(data, high, low) ((data >> low) & ((1 << (high - low + 1)) - 1))

BOOL heuristic_detection(unsigned char *cfg)
{
	unsigned char *a0 = cfg + *(BYTE*)(cfg + 0x34);
	if (a0[1] == 0)
		return 0;

	a0 = cfg + a0[1];
	if (a0[1] == 0)
		return 0;
	DWORD a1 = *(DWORD*)(cfg + a0[1] + 0x0C);
	return (GET_BITS(a1, 14, 12) + GET_BITS(a1, 17, 15) + (GET_BIT(a1, 10) | GET_BIT(a1, 11))) == 15;
}

PCSTR get_port_type_str(unsigned char *cfg)
{
	switch (get_port_type(cfg))
	{
		case PciExpressEndpoint: return "PciExpressEndpoint";
		case PciExpressLegacyEndpoint: return "PciExpressLegacyEndpoint";
		case 2: return "NVME";
		case PciExpressRootPort: return "PciExpressRootPort";
		case PciExpressUpstreamSwitchPort: return "PciExpressUpstreamSwitchPort";
		case PciExpressDownstreamSwitchPort: return "PciExpressDownstreamSwitchPort";
		case PciExpressToPciXBridge: return "PciExpressToPciXBridge";
		case PciXToExpressBridge: return "PciXToExpressBridge";
		case PciExpressRootComplexIntegratedEndpoint: return "PciExpressRootComplexIntegratedEndpoint";
		case PciExpressRootComplexEventCollector: return "PciExpressRootComplexEventCollector";
	}
	return "";
}

typedef struct {
		
	unsigned char  bus, slot, func, cfg[0x200];
	unsigned char  blk;
	unsigned char  info;
} DEVICE_INFO;

std::vector<DEVICE_INFO> get_pci_device_list(void)
{
	std::vector<DEVICE_INFO> devices;
	for (unsigned char bus = 0; bus < 255; bus++)
	{
		for (unsigned char slot = 0; slot < 32; slot++)
		{
			QWORD physical_address = cl::pci::get_physical_address(bus, slot);
			if (physical_address == 0)
			{
				continue;
			}

			for (unsigned char func = 0; func < 8; func++)
			{
				physical_address = physical_address + (func << 12);

				QWORD device_control = cl::io::read<QWORD>(physical_address + 0x04);

				if (device_control == 0xFFFFFFFFFFFFFFFF)
				{
					continue;
				}

				DEVICE_INFO device;
				device.bus = bus;
				device.slot = slot;
				device.func = func;
				device.blk = 0;
				device.info = 0;


				//
				// do not even ask...
				//
				for (int i = 0; i < 0x200; i+= 8)
				{
					*(QWORD*)((char*)device.cfg + i) = cl::io::read<QWORD>(physical_address + i);
				}
				// cl::io::read(physical_address, device.cfg, sizeof(device.cfg));
				devices.push_back(device);
			}
		}
	}
	return devices;
}

void test_devices(std::vector<DEVICE_INFO> &devices)
{
	//
	// test shadow cfg (pcileech-fpga 4.11 and lower)
	//
	for (auto &dev : devices)
	{
		DWORD tick = GetTickCount();
		cl::pci::write<WORD>(dev.bus, dev.slot, 0xA0, *(WORD*)(dev.cfg + 0xA0));
		tick = GetTickCount() - tick;
		if (tick > 100)
			continue;

		tick = GetTickCount();
		cl::pci::write<WORD>(dev.bus, dev.slot, 0xA8, *(WORD*)(dev.cfg + 0xA8));
		tick = GetTickCount() - tick;
		if (tick > 100)
		{
			dev.blk = 2;
			dev.info = 1;
			break;
		}
	}
	
	//
	// check configuration space
	//
	for (auto &dev : devices)
	{
		//
		// device was already blocked
		//
		if (dev.blk)
		{
			continue;
		}

		if (!GET_BIT(*(WORD*)(dev.cfg + 0x04), 2))
		{
			dev.blk = 1;
			dev.info = 2;
			continue;
		}

		if (heuristic_detection(dev.cfg))
		{
			dev.blk = 2;
			dev.info = 3;
			continue;
		}

		if (get_port_type(dev.cfg) == 8)
		{
			if (dev.func == 0)
			{
				dev.blk = 2;
				dev.info = 4;
				continue;
			}
		}

		if (*(WORD*)(dev.cfg) == 0xFFFF || *(WORD*)(dev.cfg + 0x02) == 0xFFFF)
		{
			dev.blk  = 2;
			dev.info = 5;
		}
	}

	for (auto &dev : devices)
	{
		if (!dev.blk)
		{
			LOG("[%s] [%02d:%02d:%02d] [%04X:%04X] [%s]\n",
				get_port_type_str(dev.cfg), dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02), blkinfo(dev.info));
		}
	}

	for (auto &dev : devices)
	{
		if (dev.blk == 1)
		{
			LOG_YELLOW("[%s] [%02d:%02d:%02d] [%04X:%04X] [%s]\n",
				get_port_type_str(dev.cfg), dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02), blkinfo(dev.info));
		}
	}

	for (auto &dev : devices)
	{
		if (dev.blk == 2)
		{
			LOG_RED("[%s] [%02d:%02d:%02d] [%04X:%04X] [%s]\n",
				get_port_type_str(dev.cfg), dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02), blkinfo(dev.info));
		}
	}
}


static void scan_pci(BOOL pcileech, BOOL dump_cfg, BOOL dump_bar)
{
	std::vector<DEVICE_INFO> devices = get_pci_device_list();

	if (dump_cfg)
	{
		for (auto &dev : devices)
		{
			printf("[%d:%d:%d] [%02X:%02X]", dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02));
			PrintPcieConfiguration(dev.cfg, sizeof(dev.cfg));
			printf("\n");
		}
	}
	if (dump_bar)
	{
		for (auto &dev : devices)
		{
			if (!GET_BIT(*(WORD*)(dev.cfg + 0x04), 2))
			{
				continue;
			}
			DWORD *bar = (DWORD*)(dev.cfg + 0x10);
			for (int i = 0; i < 6; i++)
			{
				if (bar[i] > 0x10000000)
				{
					printf("[%d:%d:%d] [%02X:%02X]\n", dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02));
					PrintPcieBarSpace(bar[i]);
					printf("\n\n\n\n");
				}
			}
				
		}
	}
	if (pcileech)
	{
		test_devices(devices);
	}
}

static BOOLEAN IsAddressEqual(QWORD address0, QWORD address2, INT64 cnt)
{
	INT64 res = abs(  (INT64)(address2 - address0)  );
	return res <= cnt;
}

static void scan_section(DWORD diff, CHAR *section_name, QWORD local_image, QWORD runtime_image, QWORD size, QWORD section_address)
{
	for (QWORD i = 0; i < size; i++)
	{
		if (((unsigned char*)local_image)[i] == ((unsigned char*)runtime_image)[i])
		{
			continue;
		}

		DWORD cnt = 0;
		while (1)
		{

			if (i + cnt >= size)
			{
				break;
			}

			if (((unsigned char*)local_image)[i + cnt] == ((unsigned char*)runtime_image)[i + cnt])
			{
				break;
			}

			cnt++;
		}
		if (cnt >= diff)
		{
			printf("%s:0x%llx is modified (%ld bytes): ", section_name, section_address + i, cnt);
			for (DWORD j = 0; j < cnt; j++)
			{
				PRINT_GREEN("%02X ", ((unsigned char*)local_image)[i + j]);
			}
			printf("-> ");
			for (DWORD j = 0; j < cnt; j++)
			{
				PRINT_RED("%02X ", ((unsigned char*)runtime_image)[i + j]);
			}
			printf("\n");
		}
		i += cnt;
	}
}

static void compare_sections(QWORD local_image, QWORD runtime_image, DWORD diff)
{
	QWORD image_dos_header = (QWORD)local_image;
	QWORD image_nt_header = *(DWORD*)(image_dos_header + 0x03C) + image_dos_header;
	unsigned short machine = *(WORD*)(image_nt_header + 0x4);

	QWORD section_header_off = machine == 0x8664 ?
		image_nt_header + 0x0108 :
		image_nt_header + 0x00F8;

	for (WORD i = 0; i < *(WORD*)(image_nt_header + 0x06); i++) {
		QWORD section = section_header_off + (i * 40);
		ULONG section_characteristics = *(ULONG*)(section + 0x24);

		UCHAR *section_name = (UCHAR*)(section + 0x00);
		ULONG section_virtual_address = *(ULONG*)(section + 0x0C);
		ULONG section_virtual_size = *(ULONG*)(section + 0x08);

		if (section_characteristics & 0x00000020 && !(section_characteristics & 0x02000000))
		{
			//
			// skip Warbird page
			//
			if (!strcmp((const char*)section_name, "PAGEwx3"))
			{
				continue;
			}
		
			scan_section(
				diff,
				(CHAR*)section_name,
				(QWORD)((BYTE*)local_image + section_virtual_address),
				(QWORD)(runtime_image + section_virtual_address),
				section_virtual_size,
				section_virtual_address
			);
		}
	}
}

static void scan_image(std::vector<FILE_INFO> modules, DWORD pid, FILE_INFO file, BOOL use_cache)
{
	//
	// dump image
	//
	QWORD runtime_image = (QWORD)cl::vm::dump_module(pid, file.base, DMP_FULL | DMP_RUNTIME);
	if (runtime_image == 0)
	{
		LOG_RED("failed to scan %s\n", file.path.c_str());
		return;
	}


	//
	// try to use existing memory dumps
	//
	HMODULE local_image = 0;

	if (use_cache)
	{
		local_image = (HMODULE)LoadImageEx(("./dumps/" + file.name).c_str(), 0, file.base, runtime_image);
		if (local_image == 0)
		{
			local_image = (HMODULE)LoadImageEx(file.path.c_str(), 0, file.base, runtime_image);
		}
	}
	else
	{
		const char *sub_str = strstr(file.path.c_str(), "\\dump_");

		if (sub_str)
		{
			std::string sub_name = sub_str + 6;
			std::string resolved_path;

			for (auto &lookup : modules)
			{
				if (!_strcmpi(lookup.name.c_str(), sub_name.c_str()))
				{
					resolved_path = lookup.path;
				}
			}

			if (resolved_path.size() < 1)
			{
				resolved_path = "C:\\Windows\\System32\\Drivers\\" + sub_name;
			}

			file.path = resolved_path;
		}

		local_image = (HMODULE)LoadImageEx(file.path.c_str(), 0, file.base, runtime_image);
	}

	if (local_image == 0)
	{
		LOG_RED("failed to scan %s\n", file.path.c_str());
		cl::vm::free_module((PVOID)runtime_image);
		return;
	}

	QWORD image_dos_header = (QWORD)local_image;
	QWORD image_nt_header = *(DWORD*)(image_dos_header + 0x03C) + image_dos_header;
	unsigned short machine = *(WORD*)(image_nt_header + 0x4);

	DWORD min_difference = 1;

	LOG("scanning: %s\n", file.path.c_str());

	compare_sections((QWORD)local_image, runtime_image, min_difference);

	cl::vm::free_module((PVOID)runtime_image);

	FreeImageEx((void *)local_image);
}

static BOOL write_dump_file(std::string name, PVOID buffer, QWORD size)
{
	if (CreateDirectoryA("./dumps/", NULL) || ERROR_ALREADY_EXISTS == GetLastError())
	{
		std::string path = "./dumps/" + name;
		FILE* f = fopen(path.c_str(), "wb");

		if (f)
		{
			fwrite(buffer, size, 1, f);

			fclose(f);

			return 1;
		}
	}

	return 0;
}

static BOOL dump_module_to_file(std::vector<FILE_INFO> modules, DWORD pid, FILE_INFO file)
{
	const char *sub_str = strstr(file.path.c_str(), "\\dump_");

	if (sub_str)
	{
		std::string sub_name = sub_str + 6;
		std::string resolved_path;

		for (auto &lookup : modules)
		{
			if (!_strcmpi(lookup.name.c_str(), sub_name.c_str()))
			{
				resolved_path = lookup.path;
			}
		}

		if (resolved_path.size() < 1)
		{
			resolved_path = "C:\\Windows\\System32\\Drivers\\" + sub_name;
		}

		file.path = resolved_path;
	}

	PVOID disk_base = (PVOID)LoadFileEx(file.path.c_str(), 0);
	if (disk_base == 0)
	{
		return 0;
	}

	QWORD target_base = (QWORD)cl::vm::dump_module(pid, file.base, DMP_FULL | DMP_RAW);
	if (target_base == 0)
	{
		free(disk_base);
		return FALSE;
	}

	//
	// copy discardable sections from disk
	//
	QWORD disk_nt = (QWORD)pe::get_nt_headers((QWORD)disk_base);
	PIMAGE_SECTION_HEADER section_disk = pe::nt::get_image_sections(disk_nt);
	for (WORD i = 0; i < pe::nt::get_section_count(disk_nt); i++)
	{
		if (section_disk[i].SizeOfRawData)
		{
			if ((section_disk[i].Characteristics & 0x02000000))
			{
				memcpy(
					(void*)(target_base + section_disk[i].PointerToRawData),
					(void*)((QWORD)disk_base + section_disk[i].PointerToRawData),
					section_disk[i].SizeOfRawData
				);
			}
		}
	}

	//
	// free disk base
	//
	free(disk_base);

	//
	// write dump file to /dumps/modulename
	//
	BOOL status = write_dump_file(file.name.c_str(), (PVOID)target_base, *(QWORD*)(target_base - 16 + 8));

	if (status)
		LOG("module %s is succesfully cached\n", file.name.c_str());
	cl::vm::free_module((PVOID)target_base);

	return status;
}

static BOOL unlink_detection(
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

static BOOL invalid_range_detection(
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

static void scan_runtime(std::vector<EFI_MODULE_INFO> &dxe_modules)
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

static void dump_to_file(PCSTR filename, QWORD physical_address, QWORD size)
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

static void scan_efi(BOOL dump)
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

	scan_runtime(dxe_modules);

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

	//
	// later runtime checks
	// 
	// if (is_efi_address(rip) && !is_inside(rip, dxe_range))
	//	printf("wssu doing m8???\n");
	//
}

