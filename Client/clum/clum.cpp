#include "clum.h"

BOOL cl::clum::initialize(void)
{
	return 1;
}

static void unsupported_error(void)
{
	printf(
		"Usermode connector is not supported,\n"
		"please launch driver or change your target action\n"
	);
}

BOOL cl::clum::read_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length)
{
	if (pid == 4 || pid == 0)
	{
		printf(
			"Usermode connector is not supported,\n"
			"please launch driver or change your target process\n"
		);
		return 0;
	}


	HANDLE process_handle = OpenProcess(PROCESS_VM_READ, 0, pid);

	//
	// access denied / process not found
	//
	if (!process_handle)
	{
		printf(
			"Process not found or not enough privileges,\n"
			"please launch driver or change your target process\n\n"
		);
		return 0;
	}

	BOOL status = ReadProcessMemory(process_handle, (LPCVOID)address, buffer, length, 0);

	//
	// close process object and return read status
	//
	CloseHandle(process_handle);
	return status;
}

BOOL cl::clum::write_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length)
{
	if (pid == 0 || pid == 4)
	{
		printf(
			"Usermode connector is not supported,\n"
			"please launch driver or change your target process\n"
		);
		return 0;
	}

	HANDLE process_handle = OpenProcess(PROCESS_VM_WRITE, 0, pid);

	//
	// access denied / process not found
	//
	if (!process_handle)
	{
		printf(
			"Process not found or not enough privileges,\n"
			"please launch driver or change your target process\n\n"
		);
		return 0;
	}

	BOOL status = WriteProcessMemory(process_handle, (LPVOID)address, buffer, length, 0);

	//
	// close proces object and return read status
	//
	CloseHandle(process_handle);
	return status;
}

BOOL cl::clum::read_mmio(QWORD address, PVOID buffer, QWORD length)
{
	UNREFERENCED_PARAMETER(address);
	UNREFERENCED_PARAMETER(buffer);
	UNREFERENCED_PARAMETER(length);
	unsupported_error();
	return 0;
}

BOOL cl::clum::write_mmio(QWORD address, PVOID buffer, QWORD length)
{
	UNREFERENCED_PARAMETER(address);
	UNREFERENCED_PARAMETER(buffer);
	UNREFERENCED_PARAMETER(length);
	unsupported_error();
	return 0;
}

BOOL cl::clum::read_pci(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD length)
{
	UNREFERENCED_PARAMETER(bus);
	UNREFERENCED_PARAMETER(slot);
	UNREFERENCED_PARAMETER(func);
	UNREFERENCED_PARAMETER(offset);
	UNREFERENCED_PARAMETER(buffer);
	UNREFERENCED_PARAMETER(length);
	unsupported_error();
	return 0;
}

BOOL cl::clum::write_pci(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD length)
{
	UNREFERENCED_PARAMETER(bus);
	UNREFERENCED_PARAMETER(slot);
	UNREFERENCED_PARAMETER(func);
	UNREFERENCED_PARAMETER(offset);
	UNREFERENCED_PARAMETER(buffer);
	UNREFERENCED_PARAMETER(length);
	unsupported_error();
	return 0;
}

QWORD cl::clum::get_physical_address(QWORD virtual_address)
{
	UNREFERENCED_PARAMETER(virtual_address);
	unsupported_error();
	return QWORD();
}

std::vector<EFI_MEMORY_DESCRIPTOR> cl::clum::get_memory_map()
{
	unsupported_error();
	return {};
}

