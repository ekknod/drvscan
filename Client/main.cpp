#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
#include <stdlib.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <iostream>


#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))

typedef ULONG_PTR QWORD;

inline void FontColor(int color=0x07) { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color); }

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





#define DEBUG
#define LOG(...) printf("[drvscan.exe] "  __VA_ARGS__)
#ifdef DEBUG
#define DEBUG_LOG(...) printf("[drvscan.exe] " __VA_ARGS__)
#else
#define DEBUG_LOG(...) // __VA_ARGS__
#endif


#define LOG_RED(...) \
printf("[drvscan.exe] "); \
FontColor(4); \
printf(__VA_ARGS__); \
FontColor(7); \


#pragma pack(1)
typedef struct {
	std::string             path;
	std::string             name;
	QWORD                   base;
	QWORD                   size;
} FILE_INFO ;
#pragma pack(1)
typedef struct {
	DWORD                  process_id;
	std::vector<FILE_INFO> process_modules;
} PROCESS_INFO;
#pragma pack(1)
typedef struct {
	QWORD                  address;
	QWORD                  length;
	DWORD                  tag;
} BIGPOOL_INFO;
#pragma pack(1)
typedef struct {
	DWORD                  pid;
	BYTE                   object_type;
	BYTE                   flags;
	QWORD                  handle;
	QWORD                  object;
	ACCESS_MASK            access_mask;
} HANDLE_INFO;
#pragma pack(1)
typedef struct {
	QWORD                  virtual_address;
	QWORD                  physical_address;
	DWORD                  page_count;
} EFI_PAGE_INFO;
#pragma pack(1)
typedef struct {
	QWORD                  virtual_address;
	QWORD                  physical_address;
	DWORD                  size;
} EFI_MODULE_INFO;
std::vector<FILE_INFO>       get_kernel_modules(void);
std::vector<FILE_INFO>       get_user_modules(DWORD pid);
std::vector<PROCESS_INFO>    get_system_processes();
std::vector<BIGPOOL_INFO>    get_kernel_allocations(void);
std::vector<HANDLE_INFO>     get_system_handle_information(void);
std::vector<EFI_PAGE_INFO>   get_efi_runtime_pages(void);
std::vector<EFI_MODULE_INFO> get_efi_module_list(void);

QWORD get_kernel_export(PCSTR export_name)
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


namespace km
{
	#define IOCTL_NVIDIA 0x9C40A484

	HANDLE driver_handle;
	void* (*encrypt_payload)(void* data_crypt, int, void* temp_buf) = nullptr;

	
	QWORD thread_object;


	QWORD HalpPciMcfgTableCount;
	QWORD HalpPciMcfgTable;

	QWORD get_physical_address(QWORD virtual_address)
	{
		typedef struct
		{
			QWORD request_id;
			QWORD result_addr;
			QWORD virtual_addr;
			int writevalue;
			char unk[0x20 - 4];
			unsigned __int64 packet_key[0x40 / 8];
			char unk_data[0x138 - 0x40 - 56];
		} PAYLOAD ;

		if (virtual_address < 0)
		{
			LOG("get_physical_address: should not happen: %llx\n", virtual_address);
			return 0;
		}

		if (virtual_address > 0xffffff0000000000)
		{
			LOG("get_physical_address: should not happen: %llx\n", virtual_address);
			return 0;
		}

		PAYLOAD Request{};
		Request.request_id = 0x26;
		Request.result_addr = 0;
		Request.virtual_addr = virtual_address;
		encrypt_payload(&Request, 0x38, Request.packet_key);
		if (!DeviceIoControl(driver_handle, IOCTL_NVIDIA, &Request, 0x138u, &Request, 0x138, 0, 0i64))
		{
			return 0;
		}

		if (PAGE_ALIGN(Request.result_addr) == 0)
		{
			return 0;
		}

		return Request.result_addr;
	}

	BOOL nvpm_read(QWORD physical_address, PVOID buffer, QWORD length)
	{
		typedef struct
		{
			ULONG request_id;
			ULONG size;
			__int64 dst_addr;
			__int64 src_addr;
			char unk[0x20];
			unsigned __int64 packet_key[0x40 / 8];
			char unk_data[0x138 - 0x40 - 56];
		} PAYLOAD ;

		PAYLOAD Request{};
		Request.request_id = 0x14;
		Request.size = ( ULONG ) length;
		Request.dst_addr = (__int64)buffer;
		Request.src_addr = physical_address;
		encrypt_payload(&Request, 0x38, Request.packet_key);
		return DeviceIoControl(driver_handle, IOCTL_NVIDIA, &Request, 0x138u, &Request, 0x138, 0, 0i64);
	}

	BOOL nvpm_write(QWORD physical_address, PVOID buffer, QWORD length)
	{
		typedef struct
		{
			ULONG request_id;
			ULONG size;
			__int64 dst_addr;
			__int64 src_addr;
			char unk[0x20];
			unsigned __int64 packet_key[0x40 / 8];
			char unk_data[0x138 - 0x40 - 56];
		} PAYLOAD ;

		PAYLOAD Request2{};
		Request2.request_id = 0x15;
		Request2.size = ( ULONG ) length;
		Request2.dst_addr = physical_address;
		Request2.src_addr = (__int64)buffer;
		encrypt_payload(&Request2, 0x38, Request2.packet_key);
		return DeviceIoControl(driver_handle, IOCTL_NVIDIA, &Request2, 0x138u, &Request2, 0x138, 0, 0i64);
	}

	BOOL nvvm_read(QWORD virtual_address, PVOID buffer, QWORD length)
	{
		QWORD total_size = length;
		QWORD offset = 0;
		QWORD bytes_read=0;
		int   cnt=0;

		while (total_size) {
			QWORD physical_address = get_physical_address(virtual_address + offset);
			if (!physical_address) {
				if (total_size >= 0x1000)
				{
					bytes_read = 0x1000;
				}
				else
				{
					bytes_read = total_size;
				}
				memset((PVOID)((QWORD)buffer + offset), 0, bytes_read);
				goto E0;
			}
			{
			QWORD current_size = min(0x1000 - (physical_address & 0xFFF), total_size);
			if (!nvpm_read(physical_address, (PVOID)((QWORD)buffer + offset), current_size))
			{
				break;
			}
			cnt++;
			bytes_read = current_size;
			}
		E0:
			total_size -= bytes_read;
			offset += bytes_read;
		}
		return cnt != 0;
	}

	BOOL nvvm_write(QWORD virtual_address, PVOID buffer, QWORD length)
	{
		QWORD total_size = length;
		QWORD offset = 0;
		QWORD bytes_read=0;
		int   cnt=0;
		while (total_size) {
			QWORD physical_address = get_physical_address(virtual_address + offset);
			if (!physical_address) {
				if (total_size >= 0x1000)
				{
					bytes_read = 0x1000;
				}
				else
				{
					bytes_read = total_size;
				}
				goto E0;
			}
			{
			QWORD current_size = min(0x1000 - (physical_address & 0xFFF), total_size);
			if (!nvpm_write(physical_address, (PVOID)((QWORD)buffer + offset), current_size))
			{
				break;
			}
			cnt++;
			bytes_read = current_size;
			}
		E0:
			total_size -= bytes_read;
			offset += bytes_read;
		}
		return cnt != 0;
	}

	namespace vm
	{
		BOOL read(DWORD pid, QWORD address, PVOID buffer, QWORD length)
		{
			if (pid == 0 || pid == 4)
			{
				return nvvm_read(address, buffer, length);
			}

			unsigned char previous_mode = 0;
			nvvm_write(thread_object + 0x232, &previous_mode, 1);

			HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

			previous_mode = 1;
			nvvm_write(thread_object + 0x232, &previous_mode, 1);

			if (process_handle == 0)
			{
				return 0;
			}

			BOOL ret = ReadProcessMemory(process_handle, (LPCVOID)address, buffer, length, 0);

			CloseHandle(process_handle);

			return ret;
		}

		BOOL write(DWORD pid, QWORD address, PVOID buffer, QWORD length)
		{
			if (pid == 0 || pid == 4)
			{
				return nvvm_write(address, buffer, length);
			}

			unsigned char previous_mode = 0;
			nvvm_write(thread_object + 0x232, &previous_mode, 1);

			HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

			previous_mode = 1;
			nvvm_write(thread_object + 0x232, &previous_mode, 1);

			if (process_handle == 0)
			{
				return 0;
			}

			BOOL ret = WriteProcessMemory(process_handle, (LPVOID)address, buffer, length, 0);

			CloseHandle(process_handle);

			return ret;
		}

		template <typename t>
		t read(DWORD pid, QWORD address)
		{
			t b;
			if (!read(pid, address, &b, sizeof(b)))
			{
				b = {};
			}
			return b;
		}

		template <typename t>
		BOOL write(DWORD pid, QWORD address, t value)
		{
			return write(pid, address, &value, sizeof(t));
		}

		QWORD get_relative_address(DWORD pid, QWORD address, INT offset, INT instruction_size)
		{
			return (address + instruction_size) + vm::read<INT>(pid, address + offset);
		}
	}

	namespace pm
	{
		BOOL read(QWORD address, PVOID buffer, QWORD length)
		{	
			return nvpm_read(address, buffer, length);
		}

		BOOL write(QWORD address, PVOID buffer, QWORD length)
		{	
			return nvpm_write(address, buffer, length);
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
		BOOL write(DWORD pid, QWORD address, t value)
		{
			return write(pid, address, &value, sizeof(t));
		}
	}

	namespace pci
	{
		QWORD get_physical_address(ULONG bus, ULONG slot)
		{
			DWORD v3; // r10d
			unsigned __int8 *i; // r9

			v3 = 0;

			QWORD table = vm::read<QWORD>(4, HalpPciMcfgTable);
			DWORD table_count = vm::read<DWORD>(4, HalpPciMcfgTableCount);

			if ( !table )
				return 0i64;

			if ( !table_count )
				return 0i64;
			
			for (i = (unsigned __int8 *)(table + 54);

				(bus >> 8) != vm::read<WORD>(4, (QWORD)(i - 1)) ||
				bus < vm::read<BYTE>(4, (QWORD)i)       ||
				bus > vm::read<BYTE>(4, (QWORD)i+1);

				i += 16
				)
			{
				if ( ++v3 >= (unsigned int)table_count )
					return 0i64;
			}
			return vm::read<QWORD>(4, (QWORD)(i - 10)) + (((slot >> 5) + 8 * ((slot & 0x1F) + 32i64 * bus)) << 12);
		}

		BOOL read(BYTE bus, BYTE slot, BYTE offset, PVOID buffer, QWORD size)
		{
			QWORD device = get_physical_address(bus, slot);

			if (device == 0)
				return 0;

			return pm::read(device + offset, buffer, size);
		}

		BOOL write(BYTE bus, BYTE slot, BYTE offset, PVOID buffer, QWORD size)
		{
			QWORD device = get_physical_address(bus, slot);

			if (device == 0)
				return 0;

			return pm::write(device + offset, buffer, size);
		}

		template <typename t>
		t read(BYTE bus, BYTE slot, BYTE offset)
		{
			t b;
			if (!read(bus, slot, offset, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}

		template <typename t>
		BOOL write(BYTE bus, BYTE slot, BYTE offset, t value)
		{
			return write(bus, slot, offset, &value, sizeof(t));
		}

	}

	//
	// external __readgsqword(0x188)
	//
	inline QWORD get_current_thread(void)
	{
		DWORD eax              = GetCurrentProcessorNumber();
		QWORD KiProcessorBlock = vm::get_relative_address(4, KeQueryPrcbAddress + 2, 3, 7);
		QWORD prcb             = vm::read<QWORD>(4, KiProcessorBlock + (eax*8));
		return vm::read<QWORD>(4, prcb + 0x08);
	}

	//
	// external *(QWORD*)(__readgsqword(0x188) + 0xB8)
	//
	inline QWORD get_current_process(void)
	{
		return vm::read<QWORD>(4, get_current_thread() + 0xB8);
	}

	
	static QWORD MmPfnDatabase;
	static QWORD MmPteBase;

	BOOL is_efi_address(QWORD physical_address)
	{
		DWORD index = (((DWORD*)&physical_address)[0] >> 12);
		QWORD pfn   = (MmPfnDatabase + (index * 0x30));
		return vm::read<QWORD>(4, pfn) == 0;
	}

	BOOL initialize()
	{
		if (driver_handle != 0)
		{
			return 1;
		}

		QWORD       target_base = 0;
		std::string target_path;

		for (auto &drv : get_kernel_modules())
		{
			if (!_strcmpi(drv.name.c_str(), "nvoclock.sys"))
			{
				target_base = drv.base;
				target_path = drv.path;
				break;
			}
		}

		if (target_base == 0)
		{
			LOG("driver nvoclock.sys is not running\n");
			return 0;
		}

		HMODULE lib = LoadLibraryA(target_path.c_str() + 4);
		if (!lib)
		{
			LOG("%s not found\n", target_path.c_str() + 4);
			return 0;
		}

		encrypt_payload = (decltype(encrypt_payload))(__int64(lib) + 0x2130);
		driver_handle   = CreateFileA("\\\\.\\NVR0Internal", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		if (driver_handle == INVALID_HANDLE_VALUE)
		{
			driver_handle = 0;
			return 0;
		}


		//
		// KTHREAD used by vm::read/vm::write
		//
		thread_object = get_current_thread();

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

		return 1;
	}
}

BOOLEAN IsAddressEqual(QWORD address0, QWORD address2, INT64 cnt)
{
	INT64 res = abs(  (INT64)(address2 - address0)  );
	return res <= cnt;
}

void scan_section(DWORD diff, CHAR *section_name, QWORD local_image, QWORD runtime_image, QWORD size, QWORD section_address, std::vector<DWORD> &wla)
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
				//
				// skip zero pages
				//
				int read_success=0;
				for (DWORD j = 0; j < cnt; j++)
				{
					if (((unsigned char*)runtime_image)[i + j] != 0)
					{
						read_success=1;
						break;
					}
				}

				if (read_success)
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

QWORD vm_dump_module_ex(DWORD pid, QWORD base, BOOL code_only, BOOL rt)
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
		QWORD target_virtual_address = (QWORD)a4 + km::vm::read<DWORD>(pid, section + (rt ? 0x0c : 0x14));
		km::vm::read(pid, local_virtual_address, (PVOID)target_virtual_address, local_virtual_size);

		if (!rt)
			*(DWORD*)((QWORD)a4 + (section - image_dos_header) + 0x10) = local_virtual_size;
	}
	return (QWORD)a4;
}

void vm_free_module(QWORD dumped_module)
{
	dumped_module-=24;
	free((void *)dumped_module);
}


namespace pe
{
	QWORD get_nt_headers(QWORD image)
	{
		return *(DWORD*)(image + 0x03C) + image;
	}

	namespace nt
	{
		DWORD get_size(QWORD nt)
		{
			return *(DWORD*)(nt + 0x50);
		}

		DWORD get_headers_size(QWORD nt)
		{
			return *(DWORD*)(nt + 0x54);
		}

		WORD get_section_count(QWORD nt)
		{
			return *(WORD*)(nt + 0x06);
		}

		BOOL is_wow64(QWORD nt)
		{
			return *(WORD*)(nt + 0x4) == 0x014c;
		}

		PIMAGE_SECTION_HEADER get_image_sections(QWORD nt)
		{
			return is_wow64(nt) ? (PIMAGE_SECTION_HEADER)(nt + 0x00F8) :
				(PIMAGE_SECTION_HEADER)(nt + 0x0108);
		}

		QWORD get_optional_header(QWORD nt)
		{
			return nt + 0x18;
		}
	}


	namespace optional
	{
		QWORD get_image_base(QWORD opt)
		{
			QWORD nt = opt - 0x18;
			return nt::is_wow64(nt) ? *(DWORD*)(opt + 0x1C) : *(QWORD*)(opt + 0x18);
		}

		IMAGE_DATA_DIRECTORY *get_data_directory(QWORD opt, int index)
		{
			QWORD nt = opt - 0x18;
			return nt::is_wow64(nt) ?
				(IMAGE_DATA_DIRECTORY*)(opt + 0x60 + (index * sizeof(IMAGE_DATA_DIRECTORY))) :
				(IMAGE_DATA_DIRECTORY*)(opt + 0x70 + (index * sizeof(IMAGE_DATA_DIRECTORY)));
		}
	}
}



#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)

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

PVOID LoadImageEx(PCSTR path, QWORD current_base, DWORD *out_len)
{
	VOID *ret = LoadFileEx(path, out_len);

	if (ret == 0)
		return 0;

	QWORD nt = pe::get_nt_headers((QWORD)ret);

	DWORD image_size = pe::nt::get_size(nt);

	QWORD local_base = pe::optional::get_image_base(pe::nt::get_optional_header(nt));

	VOID *new_image = malloc(image_size);

	memcpy(
		new_image,
		ret,
		pe::nt::get_headers_size(nt)
		);

	PIMAGE_SECTION_HEADER section = pe::nt::get_image_sections(nt);

	for (WORD i = 0; i < pe::nt::get_section_count(nt); i++)
	{
		if (section[i].SizeOfRawData)
		{
			memcpy (
				(void *)((QWORD)new_image + section[i].VirtualAddress),
				(void *)((QWORD)ret       + section[i].PointerToRawData),
				section[i].SizeOfRawData
			);
		}
	}

	free( ret ) ;


	nt = pe::get_nt_headers((QWORD)new_image);


	QWORD opt = pe::nt::get_optional_header(nt);

	BYTE *delta = (BYTE*)current_base - (QWORD)local_base;

	if (!delta)
		return new_image;

	
	
	IMAGE_DATA_DIRECTORY *relocation = pe::optional::get_data_directory(opt, 5);

	if (!relocation->Size)
		return new_image;

	
	IMAGE_BASE_RELOCATION* pRelocData = (IMAGE_BASE_RELOCATION*)((QWORD)new_image + relocation->VirtualAddress);
	const IMAGE_BASE_RELOCATION* pRelocEnd = (IMAGE_BASE_RELOCATION*)((QWORD)(pRelocData) + relocation->Size);
	while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock)
	{
		QWORD count = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(UINT16);
		UINT16* pRelativeInfo = (UINT16*)(pRelocData + 1);
		for (QWORD i = 0; i != count; ++i, ++pRelativeInfo)
		{
			if (RELOC_FLAG64(*pRelativeInfo))
			{
				QWORD* pPatch = (QWORD*)((BYTE*)new_image + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
				*pPatch += (QWORD)(delta);
			}
			else if (RELOC_FLAG32(*pRelativeInfo))
			{
				DWORD* pPatch = (DWORD*)((BYTE*)new_image + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
				*pPatch += (DWORD)(QWORD)(delta);
			}
		}
		pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)(pRelocData) + pRelocData->SizeOfBlock);
	}

	return new_image;
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

	QWORD target_base = vm_dump_module_ex(pid, file.base, 0, 0);

	if (target_base == 0 || *(WORD*)target_base != IMAGE_DOS_SIGNATURE)
	{
		LOG_RED("failed to dump %s\n", file.name.c_str());
		if (target_base != 0)
			vm_free_module(target_base);
		return FALSE;
	}

	//
	// write dump file to /dumps/drivername
	//
	if (write_dump_file (file.name.c_str(), (PVOID)target_base, *(QWORD*)(target_base - 24 + 8)))
	{
		LOG("module: %s is succesfully dumped\n", file.name.c_str());
	}

	HMODULE dll = (HMODULE)LoadImageEx(file.path.c_str(), file.base, 0);
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
		
			std::vector<DWORD> temp = get_whitelisted_addresses(
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

void compare_sections(QWORD local_image, QWORD runtime_image, DWORD diff, std::vector<DWORD> &whitelist_addresses)
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
				section_virtual_address,
				whitelist_addresses
			);
		}
	}
}

void scan_image(std::vector<FILE_INFO> modules, DWORD pid, FILE_INFO file, DWORD diff, BOOL use_cache)
{
	//
	// try to use existing memory dumps
	//

	HMODULE local_image = 0;
	std::vector<DWORD> whitelist_addresses;

	if (use_cache)
	{
		local_image = (HMODULE)LoadImageEx(("./dumps/" + file.name).c_str(), file.base, 0);
		if (local_image == 0)
		{
			local_image = (HMODULE)LoadImageEx(file.path.c_str(), file.base, 0);
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

		local_image = (HMODULE)LoadImageEx(file.path.c_str(), file.base, 0);
	}

	if (local_image)
	{
		QWORD runtime_image = vm_dump_module_ex(pid, file.base, 1, 1);

		if (runtime_image == 0 || *(WORD*)runtime_image != IMAGE_DOS_SIGNATURE)
		{
			FontColor(14);
			LOG("skipping image: %s\n", file.path.c_str());
			FontColor(7);
			FreeFileEx(local_image);
			if (runtime_image != 0)
			{
				vm_free_module(runtime_image);
			}
			return;
		}

		LOG("scanning image: %s\n", file.path.c_str());

		QWORD image_dos_header = (QWORD)local_image;
		QWORD image_nt_header = *(DWORD*)(image_dos_header + 0x03C) + image_dos_header;
		unsigned short machine = *(WORD*)(image_nt_header + 0x4);

		DWORD min_difference = 9;

		if (whitelist_addresses.size())
		{
			if (machine != 0x8664)
				min_difference = 3;
			else
				min_difference = 1;
		} else {
			if (pid != 4)
			{
				if (machine != 0x8664)
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

		compare_sections((QWORD)local_image, runtime_image, min_difference, whitelist_addresses);

		vm_free_module(runtime_image);
		FreeFileEx(local_image);
	} else {
		LOG_RED("failed to open %s\n", file.path.c_str());
	}
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
			QWORD physical_address = km::pci::get_physical_address(bus, slot);
			if (physical_address == 0)
			{
				continue;
			}

			for (unsigned char func = 0; func < 8; func++)
			{
				physical_address = physical_address + (func << 12);

				QWORD device_control = km::pm::read<QWORD>(physical_address + 0x04);

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
				km::pm::read(physical_address, device.cfg, sizeof(device.cfg));
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
		km::pci::write<WORD>(dev.bus, dev.slot, 0xA0, *(WORD*)(dev.cfg + 0xA0));
		tick = GetTickCount() - tick;
		if (tick > 100)
			continue;

		tick = GetTickCount();
		km::pci::write<WORD>(dev.bus, dev.slot, 0xA8, *(WORD*)(dev.cfg + 0xA8));
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

		/*
		int non_zero=0;
		DWORD *bar = (DWORD*)(dev.cfg + 0x10);
		for (int i = 0; i < 6; i++)
		{
			if (bar[i] != 0)
			{
				non_zero = 1;
			}
		}
		if (non_zero == 0)
		{
			LOG("[%02d-%02d-%02d]\n", dev.bus, dev.slot, dev.func);
		}
		*/

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
			FontColor(14);
			LOG("[%s] [%02d:%02d:%02d] [%04X:%04X] [%s]\n",
				get_port_type_str(dev.cfg), dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02), blkinfo(dev.info));
			FontColor(7);
		}
	}

	for (auto &dev : devices)
	{
		if (dev.blk == 2)
		{
			FontColor(4);
			LOG("[%s] [%02d:%02d:%02d] [%04X:%04X] [%s]\n",
				get_port_type_str(dev.cfg), dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02), blkinfo(dev.info));
			FontColor(7);
		}
	}
}

int scan_pci(void)
{
	std::vector<DEVICE_INFO> devices = get_pci_device_list();

	while (1)
	{
		printf(
			"1.  scan devices\n"
			"2.  dump cfg\n"
			"3.  back\n"
		);

		int operation=0;

		std::cout << "operation: ";
		std::cin >> operation;

		switch (operation)
		{
		case 1:
			test_devices(devices);
			break;
		case 2:
			for (auto &dev : devices)
			{
				printf("[%d:%d:%d] [%02X:%02X]", dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02));
				PrintPcieConfiguration(dev.cfg, sizeof(dev.cfg));
				printf("\n");
			}
			break;
		case 3:
			return 0;
		default:
			LOG("no operation selected\n");
			operation = 0;
			break;
		}

		printf("\n");

	}
	return 0;
}

BOOL get_first_efi_page(EFI_PAGE_INFO *entry)
{
	QWORD HalEfiRuntimeServicesTableAddr = km::vm::get_relative_address(0, HalEnumerateEnvironmentVariablesEx + 0xC, 1, 5);
	HalEfiRuntimeServicesTableAddr = km::vm::get_relative_address(0, HalEfiRuntimeServicesTableAddr + 0x69, 3, 7);
	HalEfiRuntimeServicesTableAddr = km::vm::read<QWORD>(0, HalEfiRuntimeServicesTableAddr);

	//
	// no table found
	//
	if (HalEfiRuntimeServicesTableAddr == 0)
	{
		return 0;
	}

	QWORD virtual_address = (QWORD)PAGE_ALIGN(km::vm::read<QWORD>(0, HalEfiRuntimeServicesTableAddr));
	if (virtual_address == 0)
		return 0;

	while (1)
	{
		QWORD phys = km::get_physical_address(virtual_address);
		if (phys == 0)
		{
			virtual_address += PAGE_SIZE;
			break;
		}
		else if (phys == 0x1000)
		{
			break;
		}
		virtual_address -= PAGE_SIZE;
	}

	DWORD page_count = 1;
	QWORD physical_address = km::get_physical_address(virtual_address);

	while (1)
	{
		QWORD phys = km::get_physical_address(virtual_address + (page_count * PAGE_SIZE));
		if ((phys - physical_address) == (page_count * PAGE_SIZE))
		{
			page_count++;
		}
		else
		{
			break;
		}
	}

	entry->virtual_address  = virtual_address;
	entry->physical_address = physical_address;
	entry->page_count       = page_count;

	return 1;
}

BOOL get_next_efi_page(EFI_PAGE_INFO *entry)
{
	if (entry->virtual_address == 0)
	{
		return get_first_efi_page(entry);
	}

	QWORD next_virt = (entry->virtual_address + (entry->page_count * PAGE_SIZE));
	QWORD next_phys = km::get_physical_address(next_virt);
	if (next_phys == 0)
	{
		*entry = {};
		return 0;
	}

	if (!km::is_efi_address(next_phys))
	{
		*entry = {};
		return 0;
	}

	entry->virtual_address  = next_virt;
	entry->physical_address = next_phys;
	DWORD count = 1;

	while (km::get_physical_address(next_virt + (count * PAGE_SIZE)) == next_phys + (count * PAGE_SIZE))
		count++;

	entry->page_count = count;
	return 1;
}

std::vector<EFI_PAGE_INFO> get_efi_runtime_pages(void)
{
	std::vector<EFI_PAGE_INFO> ret;
	EFI_PAGE_INFO page{};

	while (get_next_efi_page(&page))
	{
		if (page.page_count < 3)
		{
			continue;
		}
		ret.push_back( {page.virtual_address, page.physical_address, page.page_count} );
	}
	return ret;
}

std::vector<EFI_MODULE_INFO> get_efi_module_list(void)
{
	std::vector<EFI_MODULE_INFO> modules;
	QWORD efi_page=0;
	QWORD efi_page_count=0;

	for (auto &page : get_efi_runtime_pages())
	{
		LOG("EFI Page [%llx] [0x%llx - 0x%llx] page count: %ld\n",
			page.virtual_address, page.physical_address, page.physical_address + (page.page_count * PAGE_SIZE), page.page_count);

		if (modules.size())
		{
			continue;
		}
		
		for (DWORD page_num = 0; page_num < page.page_count; page_num++)
		{
			QWORD module_base = page.virtual_address + (page_num * PAGE_SIZE);
			if (km::vm::read<WORD>(0, module_base) == IMAGE_DOS_SIGNATURE)
			{
				QWORD nt = km::vm::read<DWORD>(0, module_base + 0x03C) + module_base;
				if (km::vm::read<WORD>(0, nt) != IMAGE_NT_SIGNATURE)
				{
					continue;
				}
				QWORD module_base_phys = page.physical_address + (page_num * PAGE_SIZE);
				modules.push_back({module_base, module_base_phys, km::vm::read<DWORD>(0, nt + 0x050)});
			}
		}
		
		if (modules.size() < 4)
		{
			modules.clear();
		}
		else
		{
			efi_page = page.physical_address;
			efi_page_count = page.page_count;
		}
	}
	printf("\n");
	if (efi_page)
	{
		LOG("EFI DXE range: [0x%llx - 0x%llx]\n\n", efi_page, efi_page + (efi_page_count * PAGE_SIZE));
		for (auto &base : modules)
		{
			LOG("EFI Runtime image [0x%llx - 0x%llx]\n", base.physical_address, base.physical_address + base.size);
		}
	}
	printf("\n");
	return modules;
}

int scan_efi(void)
{
	QWORD HalEfiRuntimeServicesTableAddr = km::vm::get_relative_address(4, HalEnumerateEnvironmentVariablesEx + 0xC, 1, 5);
	HalEfiRuntimeServicesTableAddr = km::vm::get_relative_address(4, HalEfiRuntimeServicesTableAddr + 0x69, 3, 7);
	HalEfiRuntimeServicesTableAddr = km::vm::read<QWORD>(4, HalEfiRuntimeServicesTableAddr);

	//
	// no table found
	//
	if (HalEfiRuntimeServicesTableAddr == 0)
	{
		return 0;
	}

	QWORD HalEfiRuntimeServicesTable[9];
	km::vm::read(4, HalEfiRuntimeServicesTableAddr, &HalEfiRuntimeServicesTable, sizeof(HalEfiRuntimeServicesTable));
	

	//
	// you can also test get_efi_module_list2();
	//
	std::vector<EFI_MODULE_INFO> module_list = get_efi_module_list();

	for (int i = 0; i < 9; i++)
	{
		QWORD rt_func = HalEfiRuntimeServicesTable[i];
		if (km::vm::read<WORD>(0, rt_func) == 0x25ff)
		{
			LOG_RED("EFI Runtime service [%d] is hooked with byte patch: %llx\n", i, rt_func);
			continue;
		}
		
		QWORD physical_address = km::get_physical_address(rt_func);
		BOOL found = 0;
		for (auto &base : module_list)
		{
			if (physical_address >= (QWORD)base.physical_address && physical_address <= (QWORD)((QWORD)base.physical_address + base.size))
			{
				found = 1;
				break;
			}
		}

		LOG("EFI Runtime service [%d] [%llx]\n", i, physical_address);

		if (!found)
		{
			LOG_RED("EFI Runtime service [%d] is hooked with pointer swap: %llx, %llx\n", i, rt_func, physical_address);
		}
	}
	return 0;
}

QWORD get_dump_export(PVOID dumped_module, PCSTR export_name)
{
	QWORD a0;
	DWORD a1[4]{};


	QWORD base = (QWORD)dumped_module;


	a0 = base + *(WORD*)(base + 0x3C);
	if (a0 == base)
	{
		return 0;
	}

	DWORD wow64_off = *(WORD*)(a0 + 0x4) == 0x8664 ? 0x88 : 0x78;

	a0 = base + (QWORD)*(DWORD*)(a0 + wow64_off);
	if (a0 == base)
	{
		return 0;
	}

	static int cnt=0;
	cnt++;

	memcpy(&a1, (const void *)(a0 + 0x18), sizeof(a1));
	while (a1[0]--)
	{
		a0 = (QWORD)*(DWORD*)(base + a1[2] + ((QWORD)a1[0] * 4));
		if (a0 == 0)
		{
			continue;
		}

		if (!_strcmpi((const char*)(base + a0), export_name))
		{
			a0 = *(WORD*)(base + a1[3] + ((QWORD)a1[0] * 2)) * 4;
			a0 = *(DWORD*)(base + a1[1] + a0);
			return (QWORD)((QWORD)dumped_module + a0);
		}
	}
	return 0;
}

QWORD find_table_by_function(QWORD win32k, QWORD win32k_dmp, QWORD Win32kApiSetTable, QWORD func)
{
	for (int i = 0; i < 60; i++)
	{
		QWORD table = *(QWORD*)(Win32kApiSetTable + (i * sizeof(QWORD)));
		if (table == 0)
			continue;

		table = table - win32k;
		table = table + win32k_dmp;
		if (*(QWORD*)table == func)
		{
			return table;
		}
	}
	return 0;
}

//
// scans only ext_ms_win_core_win32k_fulluser_l1_table/ext_ms_win_core_win32k_fullgdi_l1_table
// because i just wanted to show how it could be done
//
int scan_w32k(void)
{
	FILE_INFO win32k{};
	FILE_INFO win32kfull{};

	for (auto &drv : get_kernel_modules())
	{
		if (!_strcmpi(drv.name.c_str(), "win32k.sys"))
		{
			win32k = drv;
		}
		else if (!_strcmpi(drv.name.c_str(), "win32kfull.sys"))
		{
			win32kfull = drv;
		}
	}

	if (win32k.base == 0 || win32kfull.base == 0)
	{
		return 0;
	}

	QWORD win32k_dmp = vm_dump_module_ex(4, win32k.base, 0, 1);
	QWORD Win32kApiSetTable = get_dump_export((PVOID)win32k_dmp, "ext_ms_win_moderncore_win32k_base_sysentry_l1_table");
	Win32kApiSetTable =  Win32kApiSetTable + 0x70;

	QWORD win32kfull_dmp = vm_dump_module_ex(4, win32kfull.base, 0, 1);
	QWORD *table0  = (QWORD*)get_dump_export((PVOID)win32kfull_dmp, "ext_ms_win_core_win32k_fulluser_l1_table");
	QWORD *table1  = (QWORD*)find_table_by_function(win32k.base, win32k_dmp, Win32kApiSetTable, *(QWORD*)table0);
	QWORD lastadr = (QWORD)table0 + win32kfull.base - (QWORD)win32kfull_dmp;


	LOG("scanning win32k hooks\n");

	int index=0;
	while (1)
	{
		if (table0[index] == lastadr)
		{
			break;
		}

		if (table1[index] < win32kfull.base || table1[index] > (win32kfull.base + win32kfull.size))
		{
			LOG("ptr swap detected [%d] [%llX]\n", index, table1[index]);
		}

		if (table0[index] != table1[index])
		{
			LOG("ptr swap detected [%d] [%llX]\n", index, table1[index]);
		}

		index++;
	}

	LOG("ext_ms_win_core_win32k_fulluser_l1_table total entries: %ld\n", index);

	index   = 0;
	table0  = (QWORD*)get_dump_export((PVOID)win32kfull_dmp, "ext_ms_win_core_win32k_fullgdi_l1_table");
	table1  = (QWORD*)find_table_by_function(win32k.base, win32k_dmp, Win32kApiSetTable, *(QWORD*)table0);
	lastadr = (QWORD)table0 + win32kfull.base - (QWORD)win32kfull_dmp;
	while (1)
	{
		if (table0[index] == lastadr)
		{
			break;
		}

		if (table1[index] < win32kfull.base || table1[index] > (win32kfull.base + win32kfull.size))
		{
			LOG("ptr swap detected [%d] [%llX]\n", index, table1[index]);
		}

		if (table0[index] != table1[index])
		{
			LOG("ptr swap detected [%d] [%llX]\n", index, table1[index]);
		}

		index++;
	}

	LOG("ext_ms_win_core_win32k_fullgdi_l1_table total entries: %ld\n", index);

	vm_free_module(win32k_dmp);
	vm_free_module(win32kfull_dmp);

	LOG("scan is complete\n");

	return 0;
}

void dump_module(int pid, std::string module_name)
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

	for (auto &mod : modules)
	{
		if (module_name.length() > 1)
		{
			if (_strcmpi(mod.name.c_str(), module_name.c_str()))
			{
				continue;
			}
		}
		dump_module_to_file(pid, mod);
	}
}

void scan_module(int pid, std::string module_name, int diff, int use_cache)
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
		if (module_name.length() > 1)
		{
			if (_strcmpi(mod.name.c_str(), module_name.c_str()))
			{
				continue;
			}
		}
		scan_image(modules, pid, mod, diff, use_cache);
	}
	LOG("scan is complete\n");
}

int scan_memory(void)
{
	int pid = 4;
	std::string module_name;
	int diff = 0;
	int use_cache = 0;

	while (1)
	{
		printf(
			"1.  [%d] target process id\n"
			"2.  [%s] (optional) name of the image e.g. explorer.exe\n"
			"3.  [%d] the amount of bytes that have to be different before logging the patch\n"
			"4.  [%d] if option is selected, we use local dumps instead of original disk files\n"
			"5.  dump\n"
			"6.  scan\n"
			"7.  back\n",

			pid,
			module_name.size() < 4 ? "0" : module_name.c_str(),
			diff,
			use_cache
		);

		int operation=0;

		std::cout << "operation: ";
		std::cin >> operation;

		switch (operation)
		{
		case 1:
			std::cout << "pid(int): ";
			std::cin  >> pid;
			if (pid == 0)
			{
				pid = 4;
			}
			break;
		case 2:
			std::cout << "modulename(string): ";
			std::cin  >> module_name;
			if (module_name.size() < 4)
			{
				module_name = "";
			}
			break;
		case 3:
			std::cout << "diff(int): ";
			std::cin  >> diff;
			break;
		case 4:
			std::cout << "usecache(0/1): ";
			std::cin  >> use_cache;
			break;
		case 5: dump_module(pid, module_name);
			break;
		case 6: scan_module(pid, module_name, diff, use_cache);
			break;
		case 7:
			return 0;
		default:
			LOG("no operation selected\n");
			operation = 0;
			break;
		}

		printf("\n");

	}
	return 0;
}

int main(void)
{
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
		LOG_RED("ntoskrnl.exe base address not found\n");
		return getchar();
	}

	for (auto &i : global_export_list)
	{
		QWORD temp = *(QWORD*)i;

		*(QWORD*)i = get_kernel_export((PCSTR)temp);
		if (*(QWORD*)i == 0)
		{
			LOG_RED("export %s not found\n", (PCSTR)temp);
			return getchar();
		}
	}

	if (!km::initialize())
	{
		LOG_RED("failed to initialize driver\n");
		return getchar();
	}


	int operation=0;


	while (1)
	{
		std::cout << "1.  scan memory\n";
		std::cout << "2.  scan PCIe\n";
		std::cout << "3.  scan UEFI\n";
		std::cout << "4.  scan win32k hooks\n";
		std::cout << "5.  exit drvscan\n";
		std::cout << "operation: ";
		std::cin >> operation;

		printf("\n");

		switch (operation)
		{
		case 1: scan_memory();
			break;
		case 2: scan_pci();
			break;
		case 3: scan_efi();
			break;
		case 4: scan_w32k();
			break;
		case 5: exit(0);
			break;
		default:
			LOG("no operation selected\n");
			break;
		}

		printf("\n");

	}
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

	if (snp == INVALID_HANDLE_VALUE)
	{
		return info;
	}

	MODULEENTRY32 module_entry{};
	module_entry.dwSize = sizeof(module_entry);

	if (!Module32First(snp, &module_entry))
	{
		CloseHandle(snp);
		return info;
	}

	QWORD nt_header = km::vm::read<DWORD>(pid, (QWORD)module_entry.modBaseAddr + 0x03C) + (QWORD)module_entry.modBaseAddr;
	BOOL  wow64_process = km::vm::read<WORD>(pid, nt_header + 0x4) == 0x8664 ? 0 : 1;

	do
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

		if (strstr(module_entry.szExePath, "WindowsApps"))
		{
			continue;
		}

		FILE_INFO temp;
		temp.base = (QWORD)module_entry.modBaseAddr;
		temp.size = module_entry.modBaseSize;
		temp.path = std::string(module_entry.szExePath);
		temp.name = std::string(module_entry.szModule);

		info.push_back(temp);
	} while (Module32Next(snp, &module_entry));

	CloseHandle(snp);

	return info;
}

std::vector<PROCESS_INFO> get_system_processes()
{
	std::vector<PROCESS_INFO> process_info;

	HANDLE snp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 entry{};
	entry.dwSize = sizeof(entry);

	while (Process32Next(snp, &entry))
	{
		if (entry.th32ProcessID == 0)
		{
			continue;
		}
		if (entry.th32ProcessID == 4)
			process_info.push_back({entry.th32ProcessID, get_kernel_modules()});
		else
			process_info.push_back({entry.th32ProcessID, get_user_modules(entry.th32ProcessID)});
	}
	CloseHandle(snp);
	return process_info;
}

//
// https://github.com/processhacker/plugins-extra/blob/master/PoolMonPlugin/pooltable.c 
//
NTSTATUS EnumBigPoolTable(
	_Out_ PVOID* Buffer
)
{
	NTSTATUS status;
	PVOID buffer;
	ULONG bufferSize;
	ULONG attempts;

	bufferSize = 0x100;
	buffer = malloc(bufferSize);

	status = NtQuerySystemInformation(
		0x42,
		buffer,
		bufferSize,
		&bufferSize
	);
	attempts = 0;

	while (status == 0xC0000004 && attempts < 8)
	{
		free(buffer);
		buffer = malloc(bufferSize);

		status = NtQuerySystemInformation(
			0x42,
			buffer,
			bufferSize,
			&bufferSize
		);
		attempts++;
	}

	if (status == 0)
		*Buffer = buffer;
	else
		free(buffer);

	return status;
}

typedef struct _SYSTEM_BIGPOOL_ENTRY {
    union {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };
    ULONG_PTR SizeInBytes;
    union {
        UCHAR Tag[4];
        ULONG TagULong;
    };
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
    ULONG Count; 
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

std::vector<BIGPOOL_INFO> get_kernel_allocations(void)
{
	std::vector<BIGPOOL_INFO> info;
	PVOID buffer;

	if (EnumBigPoolTable(&buffer) != 0)
	{
		return info;
	}

	PSYSTEM_BIGPOOL_INFORMATION bigpool_info = (PSYSTEM_BIGPOOL_INFORMATION)buffer;
	for (ULONG i = 0; i < bigpool_info->Count; i++)
	{
		QWORD virtual_address = (QWORD)bigpool_info->AllocatedInfo[i].VirtualAddress;
		virtual_address = virtual_address - 1; // prefix.

		if (virtual_address && bigpool_info->AllocatedInfo[i].NonPaged)
		{			
			info.push_back({virtual_address, bigpool_info->AllocatedInfo[i].SizeInBytes, bigpool_info->AllocatedInfo[i].TagULong});
		}
	}
	free(buffer);
	return info;
}

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

NTSTATUS PhEnumHandles(_Out_ PSYSTEM_HANDLE_INFORMATION* Handles)
{
	static ULONG initialBufferSize = 0x4000;
	NTSTATUS status;
	PVOID buffer;
	ULONG bufferSize;

	bufferSize = initialBufferSize;
	buffer = malloc(bufferSize);

	while ((status = NtQuerySystemInformation(
		0x10,
		buffer,
		bufferSize,
		NULL
	)) == 0xC0000004)
	{
		free(buffer);
		bufferSize *= 2;
		buffer = malloc(bufferSize);
	}

	if (status != 0)
	{
		free(buffer);
		return status;
	}

	if (bufferSize <= 0x100000) initialBufferSize = bufferSize;
	*Handles = (PSYSTEM_HANDLE_INFORMATION)buffer;

	return status;
}

std::vector<HANDLE_INFO> get_system_handle_information(void)
{
	std::vector<HANDLE_INFO> info;
	PSYSTEM_HANDLE_INFORMATION handle_info = 0;

	if (PhEnumHandles(&handle_info))
	{
		return info;
	}

	for (ULONG i = 0; i < handle_info->HandleCount; i++)
	{
		HANDLE_INFO entry;
		entry.pid = handle_info->Handles[i].ProcessId;
		entry.object_type = handle_info->Handles[i].ObjectTypeNumber;
		entry.flags = handle_info->Handles[i].Flags;
		entry.handle = handle_info->Handles[i].Handle;
		entry.object = (QWORD)handle_info->Handles[i].Object;
		entry.access_mask = handle_info->Handles[i].GrantedAccess;

		info.push_back(entry);
	}

	free(handle_info);

	return info;
}

