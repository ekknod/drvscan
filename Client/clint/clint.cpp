#include "../client.h"
#include "../utils.h"
#include "clint.h"

#define INTEL 0x80862007

static void unsupported_error(void)
{
	printf(
		"INTEL connector is not supported,\n"
		"please launch driver or change your target action\n"
	);
}

BOOL cl::clint::initialize(void)
{
	if (hDriver != 0)
	{
		return 1;
	}

	hDriver = CreateFileA("\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
		hDriver = 0;
	}

	return hDriver != 0;
}

BOOL cl::clint::read_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length)
{
	if (pid == 4 || pid == 0)
	{
		return copy_memory(buffer, (PVOID)address, length);
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

BOOL cl::clint::read_mmio(QWORD address, PVOID buffer, QWORD length)
{
	QWORD map_address = map_mmio(address, (DWORD)length);

	if (!map_address)
		return 0;

	BOOL status = copy_memory(buffer, (PVOID)map_address, length);

	unmap_mmio(map_address, (DWORD)length);

	return status;
}

BOOL cl::clint::write_mmio(QWORD address, PVOID buffer, QWORD length)
{
	QWORD map_address = map_mmio(address, (DWORD)length);

	if (!map_address)
		return 0;

	BOOL status = copy_memory((PVOID)map_address, buffer, length);

	unmap_mmio(map_address, (DWORD)length);

	return status;
}

QWORD cl::clint::get_physical_address(QWORD virtual_address)
{
	typedef struct
	{
		QWORD case_number;
		QWORD reserved;
		QWORD return_physical_address;
		QWORD address_to_translate;
	} PAYLOAD;

	PAYLOAD payload{};
	payload.case_number = 0x25;
	payload.address_to_translate = virtual_address;
	if (!DeviceIoControl(hDriver, INTEL, &payload, sizeof(payload), 0, 0, 0, 0))
		return 0;

	return payload.return_physical_address;
}

PVOID cl::clint::__get_memory_map(QWORD* size)
{
	UNREFERENCED_PARAMETER(size);
	unsupported_error();
	return 0;
}

PVOID cl::clint::__get_memory_pages(QWORD* size)
{
	UNREFERENCED_PARAMETER(size);
	unsupported_error();
	return 0;
}

void cl::clint::get_pci_latency(BYTE bus, BYTE slot, BYTE func, BYTE offset, DWORD loops, DRIVER_TSC *out)
{
	UNREFERENCED_PARAMETER(bus);
	UNREFERENCED_PARAMETER(slot);
	UNREFERENCED_PARAMETER(func);
	UNREFERENCED_PARAMETER(offset);
	UNREFERENCED_PARAMETER(loops);
	UNREFERENCED_PARAMETER(out);
	unsupported_error();
}

BOOL cl::clint::copy_memory(PVOID dest, PVOID src, QWORD length)
{
	typedef struct
	{
		QWORD case_number;
		QWORD reserved;
		QWORD source;
		QWORD destination;
		QWORD length;
	} PAYLOAD;
	PAYLOAD payload{};
	payload.case_number = 0x33;
	payload.source      = (QWORD)src;
	payload.destination = (QWORD)dest;
	payload.length = length;
	return DeviceIoControl(hDriver, INTEL, &payload, sizeof(payload), 0, 0, 0, 0);
}

QWORD cl::clint::map_mmio(QWORD physical_address, DWORD size)
{
	typedef struct
	{
		QWORD case_number;
		QWORD reserved;
		QWORD return_value;
		QWORD return_virtual_address;
		QWORD physical_address_to_map;
		DWORD size;
	} PAYLOAD;
	PAYLOAD payload{};

	payload.case_number = 0x19;
	payload.physical_address_to_map = physical_address;
	payload.size = size;
	if (!DeviceIoControl(hDriver, INTEL, &payload, sizeof(payload), 0, 0, 0, 0))
		return 0;
	return payload.return_virtual_address;
}

BOOL cl::clint::unmap_mmio(QWORD address, DWORD size)
{
	typedef struct
	{
		QWORD case_number;
		QWORD reserved1;
		QWORD reserved2;
		QWORD virt_address;
		QWORD reserved3;
		DWORD number_of_bytes;
	} PAYLOAD;
	PAYLOAD payload{};
	payload.case_number = 0x1A;
	payload.virt_address = address;
	payload.number_of_bytes = size;
	return DeviceIoControl(hDriver, INTEL, &payload, sizeof(payload), 0, 0, 0, 0);
}

