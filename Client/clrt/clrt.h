#ifndef CLRT_H
#define CLRT_H

#include "../client.h"

namespace cl
{
class clrt : public client
{
	HANDLE driver_handle = 0;
public:
	clrt()  {}
	~clrt() {}
	BOOL  initialize(void);
	BOOL  read_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length);
	BOOL  write_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length);
	BOOL  read_mmio(QWORD address, PVOID buffer, QWORD length);
	BOOL  write_mmio(QWORD address, PVOID buffer, QWORD length);
	BOOL  read_pci(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD length);
	BOOL  write_pci(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD length);
	QWORD get_physical_address(QWORD virtual_address);
	std::vector<EFI_MEMORY_DESCRIPTOR> get_memory_map();
};
}

#endif /* CLRT_H */

