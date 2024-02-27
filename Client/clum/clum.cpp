#include "clum.h"

BOOL cl::clum::initialize(void)
{
	return 1;
}

static void unsupported_error(void)
{
	printf(
		"Usermode connector is not supported,\n"
		"please launch driver or change your target process\n"
	);
}

BOOL cl::clum::read_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length)
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

QWORD cl::clum::get_physical_address(QWORD virtual_address)
{
	UNREFERENCED_PARAMETER(virtual_address);
	unsupported_error();
	return QWORD();
}

PVOID cl::clum::__get_memory_map(QWORD* size)
{
	UNREFERENCED_PARAMETER(size);
	unsupported_error();
	return PVOID();
}

PVOID cl::clum::__get_memory_pages(QWORD* size)
{
	UNREFERENCED_PARAMETER(size);
	unsupported_error();
	return PVOID();
}

