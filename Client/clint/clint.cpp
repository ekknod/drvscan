#include "../client.h"
#include "../utils.h"
#include "clint.h"

#define INTEL 0x80862007

BOOL cl::clint::initialize(void)
{
	if (driver_handle != 0)
	{
		return 1;
	}

	driver_handle = CreateFileA("\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (driver_handle == INVALID_HANDLE_VALUE)
	{
		driver_handle = 0;
	}

	return driver_handle != 0;
}

BOOL cl::clint::read_kernel(QWORD address, PVOID buffer, QWORD length)
{
	return copy_memory(buffer, (PVOID)address, length);
}

BOOL cl::clint::write_kernel(QWORD address, PVOID buffer, QWORD length)
{
	return copy_memory((PVOID)address, (PVOID)buffer, length);
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
	return DeviceIoControl(driver_handle, INTEL, &payload, sizeof(payload), 0, 0, 0, 0);
}

