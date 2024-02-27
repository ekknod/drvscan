#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
#include <stdlib.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <iostream>

typedef ULONG_PTR QWORD;

#pragma pack(push, 1)
typedef struct {
	std::string             path;
	std::string             name;
	QWORD                   base;
	QWORD                   size;
} FILE_INFO ;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	DWORD                  process_id;
	std::vector<FILE_INFO> process_modules;
} PROCESS_INFO;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	QWORD                  address;
	QWORD                  length;
	DWORD                  tag;
} BIGPOOL_INFO;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	DWORD                  pid;
	BYTE                   object_type;
	BYTE                   flags;
	QWORD                  handle;
	QWORD                  object;
	ACCESS_MASK            access_mask;
} HANDLE_INFO;
#pragma pack(pop)

namespace pe
{
	inline QWORD get_nt_headers(QWORD image)
	{
		return *(DWORD*)(image + 0x03C) + image;
	}

	namespace nt
	{
		inline WORD get_section_count(QWORD nt)
		{
			return *(WORD*)(nt + 0x06);
		}

		inline BOOL is_wow64(QWORD nt)
		{
			return *(WORD*)(nt + 0x4) == 0x014c;
		}

		inline PIMAGE_SECTION_HEADER get_image_sections(QWORD nt)
		{
			return is_wow64(nt) ? (PIMAGE_SECTION_HEADER)(nt + 0x00F8) :
				(PIMAGE_SECTION_HEADER)(nt + 0x0108);
		}

		inline PIMAGE_SECTION_HEADER get_image_section(QWORD nt, PCSTR name)
		{
			PIMAGE_SECTION_HEADER section = get_image_sections(nt);
			for (WORD i = 0; i < get_section_count(nt); i++)
			{
				if (!_strcmpi((const char *)section[i].Name, name))
					return &section[i];
			}
			return 0;
		}

		inline QWORD get_optional_header(QWORD nt)
		{
			return nt + 0x18;
		}
	}


	namespace optional
	{
		inline DWORD get_entry_point(QWORD opt)
		{
			return *(DWORD*)(opt + 0x10);
		}

		inline DWORD get_image_size(QWORD opt)
		{
			return *(DWORD*)(opt + 0x38);
		}

		inline DWORD get_headers_size(QWORD opt)
		{
			return *(DWORD*)(opt + 0x3C);
		}

		inline QWORD get_image_base(QWORD opt)
		{
			QWORD nt = opt - 0x18;
			return nt::is_wow64(nt) ? *(DWORD*)(opt + 0x1C) : *(QWORD*)(opt + 0x18);
		}

		inline IMAGE_DATA_DIRECTORY *get_data_directory(QWORD opt, int index)
		{
			QWORD nt = opt - 0x18;
			return nt::is_wow64(nt) ?
				(IMAGE_DATA_DIRECTORY*)(opt + 0x60 + (index * sizeof(IMAGE_DATA_DIRECTORY))) :
				(IMAGE_DATA_DIRECTORY*)(opt + 0x70 + (index * sizeof(IMAGE_DATA_DIRECTORY)));
		}
	}
}


std::vector<FILE_INFO>    get_kernel_modules(void);
std::vector<FILE_INFO>    get_user_modules(DWORD pid);
std::vector<PROCESS_INFO> get_system_processes();
std::vector<BIGPOOL_INFO> get_kernel_allocations(void);
std::vector<HANDLE_INFO>  get_system_handle_information(void);

PVOID LoadFileEx(PCSTR path, DWORD *out_len);
PVOID LoadImageEx(PCSTR path, DWORD *out_len, QWORD current_base = 0, QWORD memory_image=0);
void  FreeImageEx(PVOID ImageBase);

#endif /* UTILS_H */

