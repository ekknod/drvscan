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

#define MIN_DIFFERENCE 9
#define IOCTL_READMEMORY 0xECAC00
#define IOCTL_READMEMORY_PROCESS 0xECAC02
#define IOCTL_READ_PORT 0xECAC04
#define IOCTL_WRITE_PORT 0xECAC06
#define IOCTL_IO_READ 0xECAC08
#define IOCTL_IO_WRITE 0xECAC10

#pragma pack(1)
typedef struct {
	PVOID src;
	PVOID dst;
	SIZE_T length;
	ULONG virtual_memory;
} DRIVER_READMEMORY;

#pragma pack(1)
typedef struct {
	PVOID src;
	PVOID dst;
	ULONG_PTR length;
	ULONG pid;
} DRIVER_READMEMORY_PROCESS;

#pragma pack(1)
typedef struct {
	unsigned short address;
	ULONG_PTR      length;
	PVOID          buffer;
} DRIVER_READWRITEPORT;

#pragma pack(1)
typedef struct {
	PVOID address;
	PVOID buffer;
	ULONG_PTR length;
} DRIVER_READWRITEIO;

typedef ULONG_PTR QWORD;

#pragma pack(1)
typedef struct {
	std::string path;
	std::string name;
	QWORD       base;
	QWORD       size;
} FILE_INFO ;

#pragma pack(1)
typedef struct {
	DWORD                  process_id;
	std::vector<FILE_INFO> process_modules;
} PROCESS_INFO;

std::vector<FILE_INFO>    get_kernel_modules(void);
std::vector<FILE_INFO>    get_user_modules(DWORD pid);
std::vector<PROCESS_INFO> get_user_processes();

namespace km
{
	HANDLE hDriver = 0;

	bool initialize(void)
	{
		if (hDriver != 0)
		{
			return 1;
		}

		hDriver = CreateFileA("\\\\.\\memdriver", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		if (hDriver == INVALID_HANDLE_VALUE)
		{
			hDriver = 0;
		}

		return hDriver != 0;
	}


	namespace vm
	{
		BOOL read(DWORD pid, ULONG_PTR address, PVOID buffer, QWORD length)
		{
			if (pid == 4)
			{
				if (!km::initialize())
				{
					return 0;
				}
				DRIVER_READMEMORY io;
				io.src = (PVOID)address;
				io.dst = buffer;
				io.length = length;
				io.virtual_memory = 1;
				return DeviceIoControl(hDriver, IOCTL_READMEMORY, &io, sizeof(io), &io, sizeof(io), 0, 0);
			} else {
				if (!km::initialize())
				{
					return 0;
				}
				DRIVER_READMEMORY_PROCESS io;
				io.src = (PVOID)address;
				io.dst = buffer;
				io.length = length;
				io.pid = pid;
				return DeviceIoControl(hDriver, IOCTL_READMEMORY_PROCESS, &io, sizeof(io), &io, sizeof(io), 0, 0);
			}
		}

		template <typename t>
		t read(DWORD pid, ULONG_PTR address)
		{
			t b;
			if (!read(pid, address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}
	}

	namespace pm
	{
		BOOL read(ULONG_PTR address, PVOID buffer, QWORD length)
		{
			if (!km::initialize())
			{
				return 0;
			}
			DRIVER_READMEMORY io;
			io.src = (PVOID)address;
			io.dst = buffer;
			io.length = length;
			io.virtual_memory = 0;
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
		BOOL read(ULONG_PTR address, PVOID buffer, QWORD length)
		{
			if (!km::initialize())
			{
				return 0;
			}
			DRIVER_READWRITEIO io;
			io.address = (PVOID)address;
			io.buffer = buffer;
			io.length = length;
			return DeviceIoControl(hDriver, IOCTL_IO_READ, &io, sizeof(io), &io, sizeof(io), 0, 0);
		}

		BOOL write(ULONG_PTR address, PVOID buffer, QWORD length)
		{
			if (!km::initialize())
			{
				return 0;
			}
			DRIVER_READWRITEIO io;
			io.address = (PVOID)address;
			io.buffer = buffer;
			io.length = length;
			return DeviceIoControl(hDriver, IOCTL_IO_WRITE, &io, sizeof(io), &io, sizeof(io), 0, 0);
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
		template <typename t>
		BOOL write(ULONG_PTR address, t value)
		{
			return km::io::write(address, &value, sizeof(t));
		}
	}

	namespace port
	{
		BOOL read(WORD address, PVOID buffer, QWORD length)
		{
			if (!km::initialize())
			{
				return 0;
			}
			DRIVER_READWRITEPORT io;
			io.address = address;
			io.buffer = buffer;
			io.length = length;
			return DeviceIoControl(hDriver, IOCTL_READ_PORT, &io, sizeof(io), &io, sizeof(io), 0, 0);
		}

		BOOL write(WORD address, PVOID buffer, QWORD length)
		{
			if (!km::initialize())
			{
				return 0;
			}
			DRIVER_READWRITEPORT io;
			io.address = address;
			io.buffer = buffer;
			io.length = length;
			return DeviceIoControl(hDriver, IOCTL_WRITE_PORT, &io, sizeof(io), &io, sizeof(io), 0, 0);
		}

		template <typename t>
		t read(WORD address)
		{
			t b;
			if (!km::port::read(address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}

		template <typename t>
		BOOL write(WORD address, t value)
		{
			return km::port::write(address, &value, sizeof(t));
		}
	}

	namespace pci
	{
		WORD read_i16_legacy(BYTE bus, BYTE slot, BYTE func, BYTE offset)
		{
			DWORD address = 0x80000000 | bus << 16 | slot << 11 | func <<  8 | offset;
			km::port::write<DWORD>(0xCF8, address);
			return (km::port::read<DWORD>(0xCFC) >> ((offset & 2) * 8)) & 0xFFFF;
		}

		void write_i16_legacy(BYTE bus, BYTE slot, BYTE func, BYTE offset, WORD value)
		{
			DWORD address = 0x80000000 | bus << 16 | slot << 11 | func <<  8 | offset;
			km::port::write<DWORD>(0xCF8, address);
			km::port::write<WORD>(0xCFC, value);
		}

		WORD read_i16(BYTE bus, BYTE slot, BYTE func, WORD offset)
		{
			DWORD address = 0x80000000 | (offset & 0xf00) << 16 | bus << 16 | slot << 11 | func <<  8 | (offset & 0xff);
			km::port::write<DWORD>(0xCF8, address);
			return (km::port::read<DWORD>(0xCFC) >> ((offset & 2) * 8)) & 0xFFFF;
		}

		void write_i16(BYTE bus, BYTE slot, BYTE func, WORD offset, WORD value)
		{
			DWORD address = 0x80000000 | (offset & 0xf00) << 16 | bus << 16 | slot << 11 | func <<  8 | (offset & 0xff);
			km::port::write<DWORD>(0xCF8, address);
			km::port::write<WORD>(0xCFC, value);
		}
	}
}

void FontColor(int color=0x07)
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

BOOLEAN IsAddressEqual(QWORD address0, QWORD address2, INT64 cnt)
{
	INT64 res = abs(  (INT64)(address2 - address0)  );
	return res <= cnt;
}

void scan_section(DWORD diff, BOOL wow64, DWORD pid, CHAR *section_name, QWORD local_image, QWORD runtime_image, QWORD size, QWORD section_address, std::vector<DWORD> &wla)
{
	DWORD min_difference = MIN_DIFFERENCE;

	if (wla.size())
	{
		if (wow64)
			min_difference = 3;
		else
			min_difference = 1;
	} else {
		if (pid != 4)
		{
			if (wow64)
				min_difference = 3;
			else
				min_difference = 1;
		}
	}

	//
	// force min difference if it's set.
	//
	if (diff != 0)
	{
		min_difference = diff;
	}

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

		if (cnt >= min_difference)
		{
			BOOL found = 0;
			 
			//
			// check if it was allowed change from our earlier clean dump
			//
			for (auto wl : wla)
			{
				if (IsAddressEqual(wl, (section_address + i), 8))
				{
					found = 1;
					break;
				}
			}
			if (found == 0)
			{
				printf("%s:0x%llx is modified (%ld bytes): ", section_name, section_address + i, cnt);
				FontColor(2);
				for (DWORD j = 0; j < cnt; j++)
				{
					printf("%02X ", ((unsigned char*)local_image)[i + j]);
				}
				FontColor(7);
				printf("-> ");

				FontColor(4);
				for (DWORD j = 0; j < cnt; j++)
				{
					printf("%02X ", ((unsigned char*)runtime_image)[i + j]);
				}
				FontColor(7);
				printf("\n");
			}
		}
		i += cnt;
	}
}

std::vector<DWORD> get_whitelisted_addresses(QWORD local_image, QWORD runtime_image, DWORD size, DWORD section_address)
{
	std::vector<DWORD> whitelist_addresses;

	for (DWORD i = 0; i < size; i++)
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
		if (cnt >= 1)
		{
			whitelist_addresses.push_back( (section_address + i) );
		}
		i += cnt;	
	}

	return whitelist_addresses;
}

QWORD vm_dump_module_ex(DWORD pid, QWORD base, BOOL code_only)
{
	QWORD a0, a1, a2, a3 = 0;
	char *a4;

	a0 = base;
	if (a0 == 0)
		return 0;

	a1 = km::vm::read<DWORD>(pid, a0 + 0x03C) + a0;
	if (a1 == a0)
	{
		return 0;
	}

	a2 = km::vm::read<DWORD>(pid, a1 + 0x050);
	if (a2 < 8)
		return 0;

	a4 = (char *)malloc(a2+24);


	*(QWORD*)(a4)=base;
	*(QWORD*)(a4 + 8)=a2;
	*(QWORD*)(a4 + 16)=a3;

	a4 += 24;

	QWORD image_dos_header = base;
	QWORD image_nt_header = km::vm::read<DWORD>(pid, image_dos_header + 0x03C) + image_dos_header;

	DWORD headers_size = km::vm::read<DWORD>(pid, image_nt_header + 0x54);
	km::vm::read(pid, image_dos_header, a4, headers_size);

	unsigned short machine = km::vm::read<WORD>(pid, image_nt_header + 0x4);

	QWORD section_header = machine == 0x8664 ?
		image_nt_header + 0x0108 :
		image_nt_header + 0x00F8;

	
	for (WORD i = 0; i < km::vm::read<WORD>(pid, image_nt_header + 0x06); i++) {

		QWORD section = section_header + (i * 40);
		DWORD section_characteristics = km::vm::read<DWORD>(pid, section + 0x24);


		if (code_only)
		{
			if (!(section_characteristics & 0x00000020))
				continue;
		}

		if ((section_characteristics & 0x02000000))
			continue;

		QWORD local_virtual_address = base + km::vm::read<DWORD>(pid, section + 0x0c);
		DWORD local_virtual_size = km::vm::read<DWORD>(pid, section + 0x08);
		QWORD target_virtual_address = (QWORD)a4 + km::vm::read<DWORD>(pid, section + 0x14);
		km::vm::read(pid, local_virtual_address, (PVOID)target_virtual_address, local_virtual_size );
		*(DWORD*)((QWORD)a4 + (section - image_dos_header) + 0x10) = local_virtual_size;
	}
	return (QWORD)a4;
}

void vm_free_module(QWORD dumped_module)
{
	dumped_module-=24;
	free((void *)dumped_module);
}

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

		if (fread(ret, len, 1, f) != 1)
		{
			free(ret);
			ret = 0;
		}

		fclose(f);
	}

	return (PVOID)ret;
}

void FreeFileEx(PVOID hMod)
{
	free(hMod);
}

BOOL write_dump_file(std::string name, PVOID buffer, QWORD size)
{
	if (CreateDirectoryA("./dumps/", NULL) || ERROR_ALREADY_EXISTS == GetLastError())
	{
		std::string path = "./dumps/" + name;
		FILE *f = fopen(path.c_str(), "wb");

		if (f)
		{
			fwrite(buffer, size, 1, f);

			fclose(f);

			return 1;
		}
	}

	return 0;
}

BOOL dump_module_to_file(DWORD pid, FILE_INFO file)
{

	QWORD target_base = vm_dump_module_ex(pid, file.base, 0);

	if (target_base == 0 || *(WORD*)target_base != IMAGE_DOS_SIGNATURE)
	{
		vm_free_module(target_base);
		return FALSE;
	}

	//
	// write dump file to /dumps/drivername
	//
	if (write_dump_file (file.name.c_str(), (PVOID)target_base, *(QWORD*)(target_base - 24 + 8)))
		printf("[+] driver: %s is succesfully dumped\n", file.name.c_str());

	HMODULE dll = (HMODULE)LoadFileEx(file.path.c_str(), 0);
	if (!dll)
	{
		vm_free_module(target_base);
		return 0;
	}
	
	QWORD image_dos_header = (QWORD)dll;
	QWORD image_nt_header = *(DWORD*)(image_dos_header + 0x03C) + image_dos_header;
	unsigned short machine = *(WORD*)(image_nt_header + 0x4);

	QWORD section_header_off = machine == 0x8664 ?
		image_nt_header + 0x0108 :
		image_nt_header + 0x00F8;

	std::vector <DWORD> whitelist_addresses;

	for (WORD i = 0; i < *(WORD*)(image_nt_header + 0x06); i++) {
		QWORD section = section_header_off + (i * 40);
		ULONG section_characteristics = *(ULONG*)(section + 0x24);

		UCHAR *section_name = (UCHAR*)(section + 0x00);
		ULONG section_virtual_address = *(ULONG*)(section + 0x0C);
		ULONG section_raw_address = *(ULONG*)(section + 0x14);
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
		
			auto temp = get_whitelisted_addresses(
				(QWORD)((BYTE*)dll + section_raw_address),
				(QWORD)(target_base + section_raw_address),
				section_virtual_size,
				section_virtual_address
			);

			whitelist_addresses.reserve(whitelist_addresses.size() + temp.size());
			whitelist_addresses.insert(whitelist_addresses.end(), temp.begin(), temp.end());

		}
	}

	FreeFileEx(dll);
	vm_free_module(target_base);

	if (whitelist_addresses.size())
	{
		FILE *f = fopen(("./dumps/" + file.name + ".wl").c_str(), "wb+");
		if (f) {
			for (auto& wt : whitelist_addresses)
			{
				fwrite(&wt, sizeof(wt), 1, f);
			}
			fclose(f);
		}
	}

	return TRUE;
}

void scan_image(DWORD pid, FILE_INFO file, DWORD diff, BOOL use_cache)
{
	//
	// try to use existing memory dumps
	//

	HMODULE dll = 0;
	std::vector<DWORD> whitelist_addresses;

	if (use_cache)
	{
		dll = (HMODULE)LoadFileEx(("./dumps/" + file.name).c_str(), 0);
		if (dll == 0)
		{
			dll = (HMODULE)LoadFileEx(file.path.c_str(), 0);
		}

	
		DWORD size;
		PVOID wt = LoadFileEx(("./dumps/" + file.name + ".wl").c_str(), &size);
		if (wt)
		{
			for (DWORD i = 0; i < size / sizeof(DWORD); i++)
			{
				whitelist_addresses.push_back(((DWORD*)wt)[i]);
			}
		}
		FreeFileEx(wt);
	}
	else
	{
		dll = (HMODULE)LoadFileEx(file.path.c_str(), 0);
	}




	if (dll)
	{
		QWORD target_base = vm_dump_module_ex(pid, file.base, 1);

		if (target_base == 0 || *(WORD*)target_base != IMAGE_DOS_SIGNATURE)
		{
			FreeFileEx(dll);
			vm_free_module(target_base);
			return;
		}

		printf("scanning image: %s\n", file.path.c_str());

		QWORD image_dos_header = (QWORD)dll;
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
			ULONG section_raw_address = *(ULONG*)(section + 0x14);
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
					machine != 0x8664,
					pid,
					(CHAR*)section_name,
					(QWORD)((BYTE*)dll + section_raw_address),
					(QWORD)(target_base + section_raw_address),
					section_virtual_size,
					section_virtual_address,
					whitelist_addresses
				);
			}
		}

		vm_free_module(target_base);
		FreeFileEx(dll);
	} else {
		printf("failed to open %s\n", file.path.c_str());
	}
}

void compare_cfg(unsigned char *cfg, unsigned char *orig_cfg)
{
	printf("\n     00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n\n");

	int line_counter=0;
	for (int i = 0; i < 256; i++)
	{
		if (line_counter == 0)
		{
			printf("%02X   ", i);
		}

		line_counter++;


		if (cfg[i] == orig_cfg[i])
			printf("%02X ", cfg[i]);
		else
		{
			FontColor(2);
			printf("%02X ", orig_cfg[i]);
			FontColor();
		}

		if (line_counter == 16)
		{
			printf("\n");
			line_counter=0;
		}
		
	}

	printf("\n");

	line_counter=0;
	for (int i = 0; i < 256; i++)
	{
		if (line_counter == 0)
		{
			printf("%02X   ", i);
		}

		line_counter++;


		if (cfg[i] == orig_cfg[i])
			printf("%02X ", cfg[i]);
		else
		{
			FontColor(4);
			printf("%02X ", cfg[i]);
			FontColor();
		}

		if (line_counter == 16)
		{
			printf("\n");
			line_counter=0;
		}
		
	}
}

#define GET_BITS(data, high, low) ((data >> low) & ((1 << (high - low + 1)) - 1))
#define GET_BIT(data, bit) ((data >> bit) & 1)


//
// not complete. no cfg filtering. only experimental.
//
void scan_pcileech(void)
{
	typedef struct {
		
		unsigned char  bus, slot, func;
		unsigned char  cfg[0x100];
		unsigned char  blk;
	} DEVICE_INFO;

	std::vector<DEVICE_INFO> devices;

	
	for (unsigned char bus = 0; bus < 255; bus++)
	{
		for (unsigned char slot = 0; slot < 32; slot++)
		{
			for (unsigned char function = 0; function < 8; function++)
			{
				WORD device_control = km::pci::read_i16_legacy(bus, slot, function, 4);
				if (device_control == 0xFFFF)
				{
					continue;
				}

				DEVICE_INFO device;
				device.bus = bus;
				device.slot = slot;
				device.func = function;
				device.blk = 0;
				for (int i = 0; i < 0x100; i+=2)
				{
					*(WORD*)&device.cfg[i] = km::pci::read_i16_legacy(bus, slot, function, i);
				}
				devices.push_back(device);
			}
		}
	}


	//
	// test shadow cfg (4.11 and lower)
	//
	printf("[+] testing shadow config space\n");
	for (auto & dev : devices)
	{		
		DWORD tick = GetTickCount();
		km::pci::write_i16_legacy(dev.bus, dev.slot, dev.func, 0xA8, *(WORD*)(dev.cfg + 0xA8));
		tick = GetTickCount() - tick;
		if (tick > 100)
		{
			FontColor(4);
			dev.blk = 1;
		}
		else
		{
			FontColor(2);
		}
		printf("[+] [%02X:%02X:%02X] [%04X:%04X] IOWr took took: %d\n", dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02), tick);
		FontColor(7);
	}
	printf("[+] test complete\n\n");



	printf("[+] testing base address register\n");
	// QWORD mgmt_base = 0xF0000000;
	for (auto & dev : devices)
	{
		//
		// device was already blocked
		//
		if (dev.blk)
		{
			continue;
		}


		//
		// memory mapped configuration space, can be used instead of km::pci::read_i16_legacy if wanted to.
		// https://wiki.osdev.org/PCI_Express
		// 
		// QWORD physical_address = mgmt_base + ((bus - 0) << 20 | slot << 15 | function << 12);
		// DWORD bar = km::io::read<DWORD>(physical_address + 0x10);
		// 


		//
		// make sure bus master is enabled
		//
		if (!GET_BIT(*(WORD*)(dev.cfg + 0x04), 2))
		{
			//
			// bus master was disabled from the device, we can safely block it
			//
			if (dev.func == 0)
			{
				dev.blk = 2;
			}
			continue;
		}

		DWORD bar = *(DWORD*)(dev.cfg + 0x10);


		if (bar < 0x10000)
		{
			continue;
		}

		unsigned char buffer[16];
		DWORD tickcount = GetTickCount();
		km::io::read(bar + 0x100, buffer, 16);
		tickcount = GetTickCount() - tickcount;

		if (tickcount > 100)
		{
			FontColor(4);
			dev.blk = 3;
		}
		else
		{
			FontColor(2);
		}

		printf("[+] [%02X:%02X:%02X] [%04X:%04X] 0x%lX MRd: ", dev.bus, dev.slot,dev.func, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02), bar);			
		for (int i = 0; i < 16; i++)
		{
			printf("%02X ", buffer[i]);
		}
		printf("took: %d\n", tickcount);
		FontColor(7);
	}

	printf("[+] test complete\n\n");


	printf("[+] checking configuration space\n");
	for (auto & dev : devices)
	{
		//
		// device was already blocked
		//
		if (dev.blk)
		{
			continue;
		}

		if (dev.func != 0)
		{
			continue;
		}

		//
		// add code here, something like xilinx_cfg (https://github.com/ekknod/xilinx_cfg)
		//
	
	}
	printf("[+] test complete\n\n");


	//
	// whitelist/verify
	//
	for (auto &dev : devices)
	{
		BYTE *cd = (BYTE*)(dev.cfg + 0x09);
		if (cd[2] == 0x06 && cd[1] == 0x00 && cd[0] == 0x00)
		{
			//
			// skip bridge devices
			// verify_legit_bridge();
			//
			dev.blk = 0;
			continue;
		}


		if (cd[2] == 0x0C && cd[1] == 0x05 && cd[0] == 0x00)
		{
			//
			// skip SMBus controller
			// verify_smbus_controller();
			//
			dev.blk = 0;
			continue;
		}
	}


	printf("[+] blocked devices\n");
	for (auto &dev : devices)
	{
		if (!dev.blk)
		{
			continue;
		}
		

		FontColor(14);
		printf("[+] [%02X:%02X:%02X] [%04X:%04X] (%d)\n", dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02), dev.blk);
		FontColor(7);
	}
}

int main(int argc, char **argv)
{
	if (!km::initialize())
	{
		printf("[-] drvscan driver is not running\n");
		printf("Press any key to continue . . .");
		return getchar();
	}
	
	if (argc < 2)
	{
		printf("[drvscan] --help\n");
		return getchar();
	}

	BOOL scan=0, pid = 4, cache = 0, pcileech = 0, diff = 0, use_cache = 0;


	for (int i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "--help"))
		{
			printf(
				"\n\n"

				"--scan                 scan target process memory changes\n"
				"--diff      (optional) the amount of bytes that have to be different before logging the patch\n"
				"--usecache             if option is selected, we use local dumps instead of original disk files\n"
				"--savecache            dump target process modules to disk, these can be used later with --usecache\n"
				"--pid                  target process id\n"
				"--pcileech             scan pcileech-fpga cards from the system\n\n\n"
			);


			printf("\nExample (verifying modules integrity by using cache):\n"
				"1.			making sure Windows is not infected\n"
				"1.			drvscan.exe --savecache --pid 4\n"
				"2.			reboot the computer\n"
				"3.			load malware what is potentially modifying modules\n"
				"4.			drvscan.exe --scan --usecache --pid 4\n"
				"all malware patches should be now visible\n\n"
			);
			
		}

		else if (!strcmp(argv[i], "--scan"))
		{
			scan = 1;
		}

		else if (!strcmp(argv[i], "--diff"))
		{
			diff = atoi(argv[i + 1]);
		}

		else if (!strcmp(argv[i], "--pid"))
		{
			pid = atoi(argv[i + 1]);
		}

		else if (!strcmp(argv[i], "--savecache"))
		{
			cache = 1;
		}

		else if (!strcmp(argv[i], "--pcileech"))
		{
			pcileech = 1;
		}

		else if (!strcmp(argv[i], "--usecache"))
		{
			use_cache = 1;
		}
	}

	if (pcileech)
	{
		printf("[+] scanning PCIe devices\n");
		scan_pcileech();
		printf("[+] PCIe scan is complete\n");
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

		printf("\n[+] scanning modules\n");
		for (auto mod : modules)
		{
			scan_image(pid, mod, diff, use_cache);
		}

		printf("[+] scan is complete\n");
	}

	if (cache)
	{
		std::vector<FILE_INFO> modules;

		if (pid == 4 || pid == 0)
		{
			modules = get_kernel_modules();
		}
		else
		{
			modules = get_user_modules(pid);
		}

		for (auto mod : modules)
		{
			dump_module_to_file(pid, mod);
		}
	
	}

	return 0;
}

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

std::vector<FILE_INFO> get_user_modules(DWORD pid)
{
	std::vector<FILE_INFO> info;
	

	HANDLE snp = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

	MODULEENTRY32 module_entry{};
	module_entry.dwSize = sizeof(module_entry);

	if (!Module32First(snp, &module_entry))
	{
		CloseHandle(snp);
		return info;
	}

	QWORD nt_header = km::vm::read<DWORD>(pid, (QWORD)module_entry.modBaseAddr + 0x03C) + (QWORD)module_entry.modBaseAddr;
	BOOL  wow64_process = km::vm::read<WORD>(pid, nt_header + 0x4) == 0x8664 ? 0 : 1;
	
	while (Module32Next(snp, &module_entry))
	{
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
		FILE_INFO temp;
		temp.base = (QWORD)module_entry.modBaseAddr;
		temp.size = module_entry.modBaseSize;
		temp.path = std::string(module_entry.szExePath);
		temp.name = std::string(module_entry.szModule);

		info.push_back(temp);
	}
	CloseHandle(snp);
	return info;
}

std::vector<PROCESS_INFO> get_user_processes()
{
	std::vector<PROCESS_INFO> process_info;


	HANDLE snp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(entry);

	while (Process32Next(snp, &entry))
	{
		if (entry.th32ProcessID == 0 || entry.th32ProcessID == 4)
		{
			continue;
		}

		HANDLE module_snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, entry.th32ProcessID);

		if (module_snap == 0)
		{
			continue;
		}

		MODULEENTRY32 module_entry{};
		module_entry.dwSize = sizeof(module_entry);

		std::vector<FILE_INFO> module_info;

		while (Module32Next(module_snap, &module_entry))
		{
			FILE_INFO temp;

			temp.base = (QWORD)module_entry.modBaseAddr;
			temp.size = module_entry.modBaseSize;
			temp.path = std::string(module_entry.szExePath);
			temp.name = std::string(module_entry.szModule);

			module_info.push_back(temp);
		}

		process_info.push_back({entry.th32ProcessID, module_info});

		CloseHandle(module_snap);
	}

	CloseHandle(snp);

	return process_info;
}
