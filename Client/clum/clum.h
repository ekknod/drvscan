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
	BOOL  is_driver() { return 0; }
	BOOL  read_virtual(DWORD pid, QWORD address, PVOID buffer, QWORD length);
	BOOL  read_mmio(QWORD address, PVOID buffer, QWORD length);
	BOOL  write_mmio(QWORD address, PVOID buffer, QWORD length);
	QWORD get_physical_address(QWORD virtual_address);
	PVOID __get_memory_map(QWORD* size);
	PVOID __get_memory_pages(QWORD* size);
};

}

#endif /* CLUM_H */

