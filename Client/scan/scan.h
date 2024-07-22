#ifndef SCAN_H
#define SCAN_H

#define _CRT_SECURE_NO_WARNINGS
#include "../client.h"

namespace scan
{
	void efi(BOOL dump);
	void pci(BOOL disable, BOOL advanced, BOOL dump_cfg);
	void image(BOOL save_cache, std::vector<FILE_INFO> modules, DWORD pid, FILE_INFO file, BOOL use_cache);
	void mouse(BOOL log_mouse);
}


#endif /* SCAN_H */

