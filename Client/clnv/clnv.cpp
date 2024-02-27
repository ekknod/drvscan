#include "../client.h"
#include "../utils.h"
#include "clnv.h"

/*
 *
 * driver connector
 * pros: most priviliges
 * cons: requires test signing
 * 
 */

#define IOCTL_NVIDIA 0x9C40A484

#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(0x1000 - 1)))

static void unsupported_error(void)
{
	printf(
		"NV connector is not supported,\n"
		"please launch driver or change your target process\n"
	);
}

BOOL cl::clnv::initialize(void)
{
	if (hDriver != 0)
	{
		return 1;
	}

	std::string target_path;

	for (auto &drv : get_kernel_modules())
	{
		if (!_strcmpi(drv.name.c_str(), "nvoclock.sys"))
		{
			target_path = drv.path;
			break;
		}
	}

	if (target_path.empty())
	{
		return 0;
	}

	hDriver = CreateFileA("\\\\.\\NVR0Internal", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
		hDriver = 0;
	}
	else
	{
		HMODULE lib = LoadLibraryA(target_path.c_str() + 4);
		encrypt_payload = (decltype(encrypt_payload))(__int64(lib) + 0x2130);
	}

	return hDriver != 0;
}

BOOL cl::clnv::read_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length)
{
	if (pid == 4 || pid == 0)
	{
		unsupported_error();
		return 0;
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
	// close proces object and return read status
	//
	CloseHandle(process_handle);
	return status;
}

BOOL cl::clnv::read_mmio(QWORD address, PVOID buffer, QWORD length)
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
	} PAYLOAD;

	PAYLOAD Request{};
	Request.request_id = 0x14;
	Request.size = (ULONG)length;
	Request.dst_addr = (__int64)buffer;
	Request.src_addr = address;
	encrypt_payload(&Request, 0x38, Request.packet_key);
	return DeviceIoControl(hDriver, IOCTL_NVIDIA, &Request, 0x138u, &Request, 0x138, 0, 0i64);
}

BOOL cl::clnv::write_mmio(QWORD address, PVOID buffer, QWORD length)
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
	} PAYLOAD;

	PAYLOAD Request2{};
	Request2.request_id = 0x15;
	Request2.size = (ULONG)length;
	Request2.dst_addr = address;
	Request2.src_addr = (__int64)buffer;
	encrypt_payload(&Request2, 0x38, Request2.packet_key);
	return DeviceIoControl(hDriver, IOCTL_NVIDIA, &Request2, 0x138u, &Request2, 0x138, 0, 0i64);
}

QWORD cl::clnv::get_physical_address(QWORD virtual_address)
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
	} PAYLOAD;

	if (virtual_address < 0)
	{
		return 0;
	}

	if (virtual_address > 0xffffff0000000000)
	{
		return 0;
	}

	PAYLOAD Request{};
	Request.request_id = 0x26;
	Request.result_addr = 0;
	Request.virtual_addr = virtual_address;
	encrypt_payload(&Request, 0x38, Request.packet_key);
	if (!DeviceIoControl(hDriver, IOCTL_NVIDIA, &Request, 0x138u, &Request, 0x138, 0, 0i64))
	{
		return 0;
	}

	if (PAGE_ALIGN(Request.result_addr) == 0)
	{
		return 0;
	}

	return Request.result_addr;
}

PVOID cl::clnv::__get_memory_map(QWORD* size)
{
	UNREFERENCED_PARAMETER(size);
	unsupported_error();
	return 0;
}

PVOID cl::clnv::__get_memory_pages(QWORD* size)
{
	UNREFERENCED_PARAMETER(size);
	unsupported_error();
	return 0;
}

