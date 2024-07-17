#ifndef CLKM_H
#define CLKM_H

#include "../client.h"

namespace cl
{
class clkm : public client
{
	HANDLE hDriver = 0;
public:
	clkm()  {}
	~clkm() {}
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
	PVOID __get_memory_pages(QWORD* size);
};
}

#endif /* CLKM_H */

