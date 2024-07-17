#include "../client.h"
#include "clkm.h"

#define IOCTL_READMEMORY         0xECAC00
#define IOCTL_IO_READ            0xECAC02
#define IOCTL_IO_WRITE           0xECAC12
#define IOCTL_REQUEST_MMAP       0xECAC04
#define IOCTL_REQUEST_PAGES      0xECAC06
#define IOCTL_READMEMORY_PROCESS 0xECAC08
#define IOCTL_GET_PHYSICAL       0xECAC10

#pragma comment(lib, "ntdll.lib")
extern "C" __kernel_entry NTSYSCALLAPI NTSTATUS NtFreeVirtualMemory(
	HANDLE  ProcessHandle,
	PVOID   *BaseAddress,
	PSIZE_T RegionSize,
	ULONG   FreeType
);

#pragma pack(push, 1)
typedef struct {
	PVOID address;
	PVOID buffer;
	ULONG_PTR length;
} DRIVER_READMEMORY;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	PVOID buffer;
	QWORD buffer_size;
} DRIVER_REQUEST_MAP;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	PVOID src;
	PVOID dst;
	ULONG_PTR length;
	ULONG pid;
} DRIVER_READMEMORY_PROCESS;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	PVOID InOutPhysical;
} DRIVER_GET_PHYSICAL;
#pragma pack(pop)

BOOL cl::clkm::initialize(void)
{
	if (hDriver != 0)
	{
		return 1;
	}

	hDriver = CreateFileA("\\\\.\\drvscan", GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
		hDriver = 0;
	}

	return hDriver != 0;
}

BOOL copy_memory_ex(HANDLE driver_handle, DWORD pid, QWORD address, PVOID buffer, QWORD length)
{
	DRIVER_READMEMORY_PROCESS io{};
	io.src = (PVOID)buffer;
	io.dst = (PVOID)address;
	io.length = length;
	io.pid = pid;
	return DeviceIoControl(driver_handle, IOCTL_READMEMORY_PROCESS, &io, sizeof(io), &io, sizeof(io), 0, 0);
}

BOOL cl::clkm::read_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length)
{
	if (!cl::initialize())
	{
		return 0;
	}

	DRIVER_READMEMORY_PROCESS io{};
	io.src = (PVOID)address;

	PVOID tmp_buffer = (PVOID)malloc(length);

	io.dst = tmp_buffer;
	io.length = length;
	io.pid = pid;

	BOOL status = DeviceIoControl(hDriver, IOCTL_READMEMORY_PROCESS, &io, sizeof(io), &io, sizeof(io), 0, 0);

	if (status)
	{
		memcpy(buffer, tmp_buffer, length);
	}
	else
	{
		memset(buffer, 0, length);
	}

	free(tmp_buffer);

	return status;
}

BOOL cl::clkm::write_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length)
{
	if (!cl::initialize())
	{
		return 0;
	}

	if (pid == 0 || pid == 4)
	{
		return copy_memory_ex(hDriver, 0, address, buffer, length);
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

BOOL cl::clkm::read_mmio(QWORD address, PVOID buffer, QWORD length)
{
	DRIVER_READMEMORY io;
	io.address = (PVOID)address;
	io.buffer = buffer;
	io.length = length;
	return DeviceIoControl(hDriver, IOCTL_IO_READ, &io, sizeof(io), &io, sizeof(io), 0, 0);
}

BOOL cl::clkm::write_mmio(QWORD address, PVOID buffer, QWORD length)
{
	DRIVER_READMEMORY io;
	io.address = (PVOID)address;
	io.buffer = buffer;
	io.length = length;
	return DeviceIoControl(hDriver, IOCTL_IO_WRITE, &io, sizeof(io), &io, sizeof(io), 0, 0);
}

BOOL cl::clkm::read_pci(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD length)
{
	UNREFERENCED_PARAMETER(bus);
	UNREFERENCED_PARAMETER(slot);
	UNREFERENCED_PARAMETER(func);
	UNREFERENCED_PARAMETER(offset);
	UNREFERENCED_PARAMETER(buffer);
	UNREFERENCED_PARAMETER(length);
	return 0;
}

BOOL cl::clkm::write_pci(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD length)
{
	UNREFERENCED_PARAMETER(bus);
	UNREFERENCED_PARAMETER(slot);
	UNREFERENCED_PARAMETER(func);
	UNREFERENCED_PARAMETER(offset);
	UNREFERENCED_PARAMETER(buffer);
	UNREFERENCED_PARAMETER(length);
	return 0;
}

QWORD cl::clkm::get_physical_address(QWORD virtual_address)
{
	DRIVER_GET_PHYSICAL io{};
	io.InOutPhysical = (PVOID)&virtual_address;
	if (!DeviceIoControl(hDriver, IOCTL_GET_PHYSICAL, &io, sizeof(io), &io, sizeof(io), 0, 0))
		return 0;
	return virtual_address;
}

PVOID cl::clkm::__get_memory_pages(QWORD* size)
{
	if (!cl::initialize())
	{
		return 0;
	}

	PVOID buffer = 0;
	QWORD buffer_size = 0;
	DRIVER_REQUEST_MAP io{};

	io.buffer = (PVOID)&buffer;
	io.buffer_size = (QWORD)&buffer_size;

	if (!DeviceIoControl(hDriver, IOCTL_REQUEST_PAGES, &io, sizeof(io), &io, sizeof(io), 0, 0))
	{
		return 0;
	}

	*size = buffer_size;

	return buffer;
}

std::vector<EFI_MEMORY_DESCRIPTOR> cl::clkm::get_memory_map()
{
	std::vector<EFI_MEMORY_DESCRIPTOR> table;
	QWORD efi_page_table_size = 0;
	PVOID efi_page_tables = __get_memory_pages(&efi_page_table_size);
	for (DWORD i = 0; i < *(DWORD*)efi_page_tables; i++)
	{
		QWORD temp = ((QWORD)efi_page_tables + (i * 16)) + 0x04;
		QWORD address = *(QWORD*)((QWORD)temp + 0x00);
		QWORD page_cnt = *(QWORD*)((QWORD)temp + 0x08);

		EFI_MEMORY_DESCRIPTOR entry{};
		entry.PhysicalStart = address;
		entry.NumberOfPages = page_cnt;

		table.push_back(entry);
	}
	NtFreeVirtualMemory(GetCurrentProcess(), &efi_page_tables, &efi_page_table_size, MEM_RELEASE);
	for (auto &entry : table)
	{
		entry.Type = 5;
		entry.Attribute = 0x800000000000000f;
	}
	return table;
}

