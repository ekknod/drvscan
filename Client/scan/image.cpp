#include "scan.h"

namespace scan
{
	static void compare_sections(QWORD local_image, QWORD runtime_image, DWORD diff);
	static BOOL dump_module_to_file(std::vector<FILE_INFO> modules, DWORD pid, FILE_INFO file);
}

void scan::image(BOOL save_cache, std::vector<FILE_INFO> modules, DWORD pid, FILE_INFO file, BOOL use_cache)
{
	if (save_cache)
	{
		dump_module_to_file(modules, pid, file);
		return;
	}


	//
	// dump image
	//
	QWORD runtime_image = (QWORD)cl::vm::dump_module(pid, file.base, DMP_FULL | DMP_RUNTIME);
	if (runtime_image == 0)
	{
		LOG_RED("failed to scan %s\n", file.path.c_str());
		return;
	}


	//
	// try to use existing memory dumps
	//
	HMODULE local_image = 0;

	if (use_cache)
	{
		local_image = (HMODULE)LoadImageEx(("./dumps/" + file.name).c_str(), 0, file.base, runtime_image);
		if (local_image == 0)
		{
			local_image = (HMODULE)LoadImageEx(file.path.c_str(), 0, file.base, runtime_image);
		}
	}
	else
	{
		const char *sub_str = strstr(file.path.c_str(), "\\dump_");

		if (sub_str)
		{
			std::string sub_name = sub_str + 6;
			std::string resolved_path;

			for (auto &lookup : modules)
			{
				if (!_strcmpi(lookup.name.c_str(), sub_name.c_str()))
				{
					resolved_path = lookup.path;
				}
			}

			if (resolved_path.size() < 1)
			{
				resolved_path = "C:\\Windows\\System32\\Drivers\\" + sub_name;
			}

			file.path = resolved_path;
		}

		local_image = (HMODULE)LoadImageEx(file.path.c_str(), 0, file.base, runtime_image);
	}

	if (local_image == 0)
	{
		LOG_RED("failed to scan %s\n", file.path.c_str());
		cl::vm::free_module((PVOID)runtime_image);
		return;
	}

	DWORD min_difference = 1;

	LOG("scanning: %s\n", file.path.c_str());

	compare_sections((QWORD)local_image, runtime_image, min_difference);

	cl::vm::free_module((PVOID)runtime_image);

	FreeImageEx((void *)local_image);
}

static void scan_section(DWORD diff, CHAR *section_name, QWORD local_image, QWORD runtime_image, QWORD size, QWORD section_address)
{
	for (QWORD i = 0; i < size; i++)
	{
		if (((unsigned char*)local_image)[i] == ((unsigned char*)runtime_image)[i])
		{
			continue;
		}

		DWORD cnt = 0;
		while (1)
		{

			if (i + cnt >= size)
			{
				break;
			}

			if (((unsigned char*)local_image)[i + cnt] == ((unsigned char*)runtime_image)[i + cnt])
			{
				break;
			}

			cnt++;
		}
		if (cnt >= diff)
		{
			printf("%s:0x%llx is modified (%ld bytes): ", section_name, section_address + i, cnt);
			for (DWORD j = 0; j < cnt; j++)
			{
				PRINT_GREEN("%02X ", ((unsigned char*)local_image)[i + j]);
			}
			printf("-> ");
			for (DWORD j = 0; j < cnt; j++)
			{
				PRINT_RED("%02X ", ((unsigned char*)runtime_image)[i + j]);
			}
			printf("\n");
		}
		i += cnt;
	}
}

static void scan::compare_sections(QWORD local_image, QWORD runtime_image, DWORD diff)
{
	QWORD image_dos_header = (QWORD)local_image;
	QWORD image_nt_header = *(DWORD*)(image_dos_header + 0x03C) + image_dos_header;
	unsigned short machine = *(WORD*)(image_nt_header + 0x4);

	QWORD section_header_off = machine == 0x8664 ?
		image_nt_header + 0x0108 :
		image_nt_header + 0x00F8;

	for (WORD i = 0; i < *(WORD*)(image_nt_header + 0x06); i++) {
		QWORD section = section_header_off + (i * 40);
		ULONG section_characteristics = *(ULONG*)(section + 0x24);

		UCHAR *section_name = (UCHAR*)(section + 0x00);
		ULONG section_virtual_address = *(ULONG*)(section + 0x0C);
		ULONG section_virtual_size = *(ULONG*)(section + 0x08);

		if (section_characteristics & 0x00000020 && !(section_characteristics & 0x02000000))
		{
			//
			// skip Warbird page
			//
			if (!strcmp((const char*)section_name, "PAGEwx3"))
			{
				continue;
			}
		
			scan_section(
				diff,
				(CHAR*)section_name,
				(QWORD)((BYTE*)local_image + section_virtual_address),
				(QWORD)(runtime_image + section_virtual_address),
				section_virtual_size,
				section_virtual_address
			);
		}
	}
}

static BOOL write_dump_file(std::string name, PVOID buffer, QWORD size)
{
	if (CreateDirectoryA("./dumps/", NULL) || ERROR_ALREADY_EXISTS == GetLastError())
	{
		std::string path = "./dumps/" + name;
		FILE* f = fopen(path.c_str(), "wb");

		if (f)
		{
			fwrite(buffer, size, 1, f);

			fclose(f);

			return 1;
		}
	}

	return 0;
}

static BOOL scan::dump_module_to_file(std::vector<FILE_INFO> modules, DWORD pid, FILE_INFO file)
{
	const char *sub_str = strstr(file.path.c_str(), "\\dump_");

	if (sub_str)
	{
		std::string sub_name = sub_str + 6;
		std::string resolved_path;

		for (auto &lookup : modules)
		{
			if (!_strcmpi(lookup.name.c_str(), sub_name.c_str()))
			{
				resolved_path = lookup.path;
			}
		}

		if (resolved_path.size() < 1)
		{
			resolved_path = "C:\\Windows\\System32\\Drivers\\" + sub_name;
		}

		file.path = resolved_path;
	}

	PVOID disk_base = (PVOID)LoadFileEx(file.path.c_str(), 0);
	if (disk_base == 0)
	{
		return 0;
	}

	QWORD target_base = (QWORD)cl::vm::dump_module(pid, file.base, DMP_FULL | DMP_RAW);
	if (target_base == 0)
	{
		free(disk_base);
		return FALSE;
	}

	//
	// copy discardable sections from disk
	//
	QWORD disk_nt = (QWORD)pe::get_nt_headers((QWORD)disk_base);
	PIMAGE_SECTION_HEADER section_disk = pe::nt::get_image_sections(disk_nt);
	for (WORD i = 0; i < pe::nt::get_section_count(disk_nt); i++)
	{
		if (section_disk[i].SizeOfRawData)
		{
			if ((section_disk[i].Characteristics & 0x02000000))
			{
				memcpy(
					(void*)(target_base + section_disk[i].PointerToRawData),
					(void*)((QWORD)disk_base + section_disk[i].PointerToRawData),
					section_disk[i].SizeOfRawData
				);
			}
		}
	}

	//
	// free disk base
	//
	free(disk_base);

	//
	// write dump file to /dumps/modulename
	//
	BOOL status = write_dump_file(file.name.c_str(), (PVOID)target_base, *(QWORD*)(target_base - 16 + 8));

	if (status)
		LOG("module %s is succesfully cached\n", file.name.c_str());
	cl::vm::free_module((PVOID)target_base);

	return status;
}
