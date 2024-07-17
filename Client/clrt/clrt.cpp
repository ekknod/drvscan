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

typedef struct
{
	QWORD address;       // 0x00
	DWORD size;          // 0x08
	uint8_t gap[16];     // 0x20
} IO_STRUCT_PHYS ;

typedef struct
{
	DWORD   bus_number;  // 0x00
	DWORD   slot_number; // 0x04
	DWORD   func_number; // 0x08
	DWORD   offset;      // 0x0C
	DWORD   length;      // 0x10
	DWORD   result;      // 0x14
} IO_STRUCT_PCI ;

//
// data: 0x20
// out : 0x08
//
DWORD read_pci_ex(HANDLE driver_handle, BYTE bus, BYTE slot, BYTE func, DWORD offset, DWORD length)
{
	IO_STRUCT_PCI io{};
	io.bus_number  = bus;
	io.slot_number = slot;
	io.func_number = func;
	io.offset      = offset;
	io.length      = length;
	if (!DeviceIoControl(driver_handle, 0x80002050, &io, sizeof(io), &io, sizeof(io), NULL, NULL))
	{
		return (DWORD)0xFFFFFFFF;
	}
	return io.result;
}

BOOL write_pci_ex(HANDLE driver_handle, BYTE bus, BYTE slot, BYTE func, DWORD offset, DWORD value, DWORD length)
{
	IO_STRUCT_PCI io{};
	io.bus_number  = bus;
	io.slot_number = slot;
	io.func_number = func;
	io.offset      = offset;
	io.length      = length;
	io.result      = value;
	return DeviceIoControl(driver_handle, 0x80002054, &io, sizeof(io), &io, sizeof(io), NULL, NULL);
}

DWORD read_pci_i32(HANDLE driver_handle, BYTE bus, BYTE slot, BYTE func, DWORD offset)
{
	return read_pci_ex(driver_handle, bus, slot, func, offset, sizeof(DWORD));
}

WORD read_pci_i16(HANDLE driver_handle, BYTE bus, BYTE slot, BYTE func, DWORD offset)
{
	return read_pci_ex(driver_handle, bus, slot, func, offset, sizeof(WORD)) & 0xFFFF;
}

BYTE read_pci_i8(HANDLE driver_handle, BYTE bus, BYTE slot, BYTE func, DWORD offset)
{
	return read_pci_ex(driver_handle, bus, slot, func, offset, sizeof(BYTE)) & 0xFF;
}






BOOL write_pci_i32(HANDLE driver_handle, BYTE bus, BYTE slot, BYTE func, DWORD offset, DWORD value)
{
	return write_pci_ex(driver_handle, bus, slot, func, offset, value, sizeof(DWORD));
}

BOOL write_pci_i16(HANDLE driver_handle, BYTE bus, BYTE slot, BYTE func, DWORD offset, WORD value)
{
	return write_pci_ex(driver_handle, bus, slot, func, offset, value, sizeof(WORD));
}

BOOL write_pci_i8(HANDLE driver_handle, BYTE bus, BYTE slot, BYTE func, DWORD offset, BYTE value)
{
	return write_pci_ex(driver_handle, bus, slot, func, offset, value, sizeof(BYTE));
}

BOOL read_pci_data(HANDLE driver_handle, BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD length)
{
	DWORD location  = 0;
	DWORD data_left = length;

	while (data_left)
	{
		if (data_left >= 4)
		{
			DWORD data = read_pci_i32(driver_handle, bus, slot, func, offset + location);
			*(DWORD*)((PBYTE)buffer + location) = data;
			location += 4;
		}
		else if (data_left >= 2)
		{
			WORD data = read_pci_i16(driver_handle, bus, slot, func, offset + location);
			*(WORD*)((PBYTE)buffer + location) = data;
			location += 2;
		}
		else
		{
			BYTE data = read_pci_i8(driver_handle, bus, slot, func, offset + location);
			*(BYTE*)((PBYTE)buffer + location) = data;
			location += 1;
		}
		data_left = length - location;
	}
	return 1;
}

BOOL write_pci_data(HANDLE driver_handle, BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD length)
{
	DWORD location  = 0;
	DWORD data_left = length;

	while (data_left)
	{
		if (data_left >= 4)
		{
			write_pci_i32(driver_handle, bus, slot, func, offset + location, *(DWORD*)((PBYTE)buffer + location));
			location += 4;
		}
		else if (data_left >= 2)
		{
			write_pci_i16(driver_handle, bus, slot, func, offset + location, *(WORD*)((PBYTE)buffer + location));
			location += 2;
		}
		else
		{
			write_pci_i8(driver_handle, bus, slot, func, offset + location, *(BYTE*)((PBYTE)buffer + location));
			location += 1;
		}
		data_left = length - location;
	}
	return 1;
}

static PVOID map_physical_address(HANDLE driver_handle, QWORD physical_address, DWORD size)
{
	IO_STRUCT_PHYS operation{};
	operation.address = physical_address;
	operation.size = size;
	if (!DeviceIoControl(driver_handle, 0x80002000, &operation,
		sizeof(operation), &operation, sizeof(operation), NULL, NULL))
	{
		return 0;
	}
	return (PVOID)operation.address;
}

static BOOL unmap_physical_address(HANDLE driver_handle, PVOID mapped_address)
{
	IO_STRUCT_PHYS operation{};
	operation.address = (QWORD)mapped_address;
	return DeviceIoControl(driver_handle, 0x80002004, &operation,
		sizeof(operation), &operation, sizeof(operation), NULL, NULL);
}

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

BOOL cl::clrt::read_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length)
{
	if (!cl::initialize())
	{
		return 0;
	}

	if (pid == 0 || pid == 4)
	{
		return rt_read(driver_handle, address, buffer, length);
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

BOOL cl::clrt::write_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length)
{
	if (!cl::initialize())
	{
		return 0;
	}

	if (pid == 0 || pid == 4)
	{
		return rt_write(driver_handle, address, buffer, length);
	}

	HANDLE process_handle = OpenProcess(PROCESS_VM_WRITE, 0, pid);

	//
	// access denied / process not found
	//
	if (!process_handle)
	{
		return 0;
	}

	BOOL status = WriteProcessMemory(process_handle, (LPVOID)address, buffer, length, 0);

	//
	// close proces object and return read status
	//
	CloseHandle(process_handle);
	return status;
}

BOOL cl::clrt::read_mmio(QWORD address, PVOID buffer, QWORD length)
{
	BOOL  status        = 0;
	PVOID mapped_memory = map_physical_address(driver_handle, address, (DWORD)length);
	if (mapped_memory)
	{
		memcpy(buffer, mapped_memory, length);
		unmap_physical_address(driver_handle, mapped_memory);
		status = 1;
	}
	return status;
}

BOOL cl::clrt::write_mmio(QWORD address, PVOID buffer, QWORD length)
{
	BOOL  status        = 0;
	PVOID mapped_memory = map_physical_address(driver_handle, address, (DWORD)length);
	if (mapped_memory)
	{
		memcpy(mapped_memory, buffer, length);
		unmap_physical_address(driver_handle, mapped_memory);
		status = 1;
	}
	return status;
}

BOOL cl::clrt::read_pci(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD length)
{
	return read_pci_data(driver_handle, bus, slot, func, offset, buffer, length);
}

BOOL cl::clrt::write_pci(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD length)
{
	return write_pci_data(driver_handle, bus, slot, func, offset, buffer, length);
}

QWORD cl::clrt::get_physical_address(QWORD virtual_address)
{
	UNREFERENCED_PARAMETER(virtual_address);
	return 0;
}

std::vector<EFI_MEMORY_DESCRIPTOR> cl::clrt::get_memory_map()
{
	return {};
}

