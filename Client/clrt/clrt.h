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
	BOOL  read_kernel(QWORD address, PVOID buffer, QWORD length);
	BOOL  write_kernel(QWORD address, PVOID buffer, QWORD length);
};
}

#endif /* CLRT_H */

