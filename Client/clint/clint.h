#ifndef CLINT_H
#define CLINT_H

#include "../client.h"

namespace cl
{
class clint : public client
{
	HANDLE driver_handle = 0;
public:
	clint()  {}
	~clint() {};
	BOOL  initialize(void);
	BOOL  read_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length);
	BOOL  write_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length);
	BOOL  read_mmio(QWORD address, PVOID buffer, QWORD length);
	BOOL  write_mmio(QWORD address, PVOID buffer, QWORD length);
	BOOL  read_pci(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD length);
	BOOL  write_pci(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD length);
	QWORD get_physical_address(QWORD virtual_address);
	std::vector<EFI_MEMORY_DESCRIPTOR> get_memory_map();
private:
	BOOL  copy_memory(PVOID dest, PVOID src, QWORD length);
	QWORD map_mmio(QWORD physical_address, DWORD size);
	BOOL  unmap_mmio(QWORD address, DWORD size);
};
}

#endif /* CLINT_H */

