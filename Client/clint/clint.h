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
	BOOL  read_kernel(QWORD address, PVOID buffer, QWORD length);
	BOOL  write_kernel(QWORD address, PVOID buffer, QWORD length);
private:
	BOOL copy_memory(PVOID dest, PVOID src, QWORD length);
};
}

#endif /* CLINT_H */

