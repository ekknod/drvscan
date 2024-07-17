#ifndef CLUM_H
#define CLUM_H

#include "../client.h"

namespace cl
{

class clum : public client
{
public:
	clum()  {}
	~clum() {}
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

#endif /* CLUM_H */

