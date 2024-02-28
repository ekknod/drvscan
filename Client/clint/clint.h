#ifndef CLNV_H
#define CLNV_H

#include "../client.h"

namespace cl
{
class clint : public client
{
	HANDLE hDriver = 0;
	void* (*encrypt_payload)(void* data_crypt, int, void* temp_buf) = 0;
public:
	clint()  {}
	~clint() {}
	BOOL  initialize(void);
	BOOL  read_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length);
	BOOL  read_mmio(QWORD address, PVOID buffer, QWORD length);
	BOOL  write_mmio(QWORD address, PVOID buffer, QWORD length);
	QWORD get_physical_address(QWORD virtual_address);
	PVOID __get_memory_map(QWORD* size);
	PVOID __get_memory_pages(QWORD* size);
private:
	BOOL  copy_memory(PVOID dest, PVOID src, QWORD length);
	QWORD map_mmio(QWORD physical_address, DWORD size);
	BOOL  unmap_mmio(QWORD address, DWORD size);
};
}

#endif /* CLVD_H */

