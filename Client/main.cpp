#define _CRT_SECURE_NO_WARNINGS
#include "scan/scan.h"
#include <chrono>

int main(int argc, char **argv)
{
	//
	// reset font
	//
	FontColor(7);

	if (!cl::initialize())
	{
		LOG("driver is not running\n");
		printf("Press any key to continue . . .");
		return getchar();
	}

	if (argc < 2)
	{
		LOG("--help\n");
		return getchar();
	}

	DWORD scan = 0, pid = 4, savecache = 0, scanpci = 0, advanced=0, block=0, cfg=0, use_cache = 0, scanefi = 0, dump = 0, scanmouse=0, log = 0;
	for (int i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "--help"))
		{
			printf(
				"\n\n"

				"--scan                 scan target process memory changes\n"
				"    --pid              (optional) target process id\n"
				"    --usecache         (optional) we use local cache instead of original PE files\n"
				"    --savecache        (optional) dump target process modules to disk\n\n"
				"--scanefi              scan abnormals from efi memory map\n"
				"    --dump             (optional) dump found abnormal to disk\n\n"
				"--scanpci              scan pci cards from the system\n"
				"    --advanced         (optional) test pci features\n"
				"    --block            (optional) block illegal cards\n"
				"    --cfg              (optional) print out every card cfg space\n"
				"--scanmouse            catch aimbots by monitoring mouse packets\n"
				"    --log              (optional) print out every mouse packet\n\n\n"
			);

			printf("\nExample (verifying modules integrity by using cache):\n"
				"1.                     load malware\n"
				"1.                     drvscan.exe --scan --savecache --pid 4\n"
				"2.                     reboot the computer\n"
				"3.                     load windows without malware\n"
				"4.                     drvscan.exe --scan --usecache --pid 4\n"
				"all malware patches should be now visible\n\n"
			);
		}

		else if (!strcmp(argv[i], "--scan"))
		{
			scan = 1;
		}

		else if (!strcmp(argv[i], "--pid"))
		{
			pid = atoi(argv[i + 1]);
		}

		else if (!strcmp(argv[i], "--savecache"))
		{
			savecache = 1;
		}

		else if (!strcmp(argv[i], "--scanpci"))
		{
			scanpci = 1;
		}

		else if (!strcmp(argv[i], "--scanmouse"))
		{
			scanmouse = 1;
		}

		else if (!strcmp(argv[i], "--log"))
		{
			log = 1;
		}

		else if (!strcmp(argv[i], "--advanced"))
		{
			advanced = 1;
		}

		else if (!strcmp(argv[i], "--block"))
		{
			block = 1;
		}

		else if (!strcmp(argv[i], "--cfg"))
		{
			cfg = 1;
		}

		else if (!strcmp(argv[i], "--scanefi"))
		{
			scanefi = 1;
		}

		else if (!strcmp(argv[i], "--dump"))
		{
			dump = 1;
		}

		else if (!strcmp(argv[i], "--usecache"))
		{
			use_cache = 1;
		}
	}

	auto timer_start = std::chrono::high_resolution_clock::now();

	if (scanpci)
	{
		LOG("scanning PCIe devices\n");

		scan::pci(block, advanced, cfg);
	}

	if (scan)
	{
		std::vector<FILE_INFO> modules;

		if (!cl::kernel_access && pid == 4)
		{
			for (auto& proc : get_system_processes())
			{
				if (!_strcmpi(proc.name.c_str(), "explorer.exe"))
				{
					pid = proc.id;
					break;
				}
			}
		}

		if (pid == 4)
		{
			modules = get_kernel_modules();
		}
		else
		{
			modules = get_user_modules(pid);
		}

		LOG("scanning modules\n");
		for (auto mod : modules)
		{
			scan::image(savecache, modules, pid, mod, use_cache);
		}
	}

	if (scanefi)
	{
		LOG("scanning EFI\n");
		scan::efi(dump);
	}

	if (scanmouse)
	{
		LOG("monitoring mouse\n");
		scan::mouse(log);
	}

	auto timer_end = std::chrono::high_resolution_clock::now() - timer_start;

	if (scanefi+scan+scanpci)
		LOG("scan is complete [%lldms]\n",
			std::chrono::duration_cast<std::chrono::milliseconds>(timer_end).count());

	//
	// add watermark
	//
	PRINT_GREEN("\nbuild date: %s, %s\n", __DATE__, __TIME__);

	cl::terminate();

	return 0;
}

