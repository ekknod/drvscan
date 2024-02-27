#ifndef CLNV_H
#define CLNV_H

#include "../client.h"

namespace cl
{
class clnv : public client
{
	HANDLE hDriver = 0;
	void* (*encrypt_payload)(void* data_crypt, int, void* temp_buf) = 0;
public:
	clnv()  {}
	~clnv() {}
	BOOL  initialize(void);
	BOOL  read_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length);
	BOOL  read_mmio(QWORD address, PVOID buffer, QWORD length);
	BOOL  write_mmio(QWORD address, PVOID buffer, QWORD length);
	QWORD get_physical_address(QWORD virtual_address);
	PVOID __get_memory_map(QWORD* size);
	PVOID __get_memory_pages(QWORD* size);
};
}

#endif /* CLNV_H */

