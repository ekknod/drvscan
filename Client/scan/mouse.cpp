#include "scan.h"

typedef struct {
	HANDLE handle;
	QWORD  total_calls;
	QWORD  timestamp;
} MOUSE_INFO ;
 
namespace scan
{
	static std::vector<MOUSE_INFO> device_list;
	static std::vector<PROCESS_INFO> process_list;

	void handle_raw_input(QWORD timestamp, RAWINPUT *input);
}

QWORD SDL_GetTicksNS(void);
std::vector<MOUSE_INFO> get_input_devices(void);

void scan::mouse(void)
{
	RAWINPUTDEVICE setup_data[1];
	setup_data[0].usUsagePage = 0x01;
	setup_data[0].usUsage = 0x02;
	setup_data[0].dwFlags = RIDEV_INPUTSINK;
	setup_data[0].hwndTarget = (HWND)CreateWindowEx(0, TEXT("Message"), NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);
	RegisterRawInputDevices(setup_data, ARRAYSIZE(setup_data), sizeof(setup_data[0]));

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	device_list = get_input_devices();

	if (device_list.size() == 1) {
		LOG("primary input device has been selected\n");
	}

	LOG("Press F10 to stop monitoring . . .\n");

	while (!GetAsyncKeyState(VK_F10))
	{
		RAWINPUT data{};
		UINT     size = sizeof(data);
		GetRawInputBuffer(&data, &size, sizeof(RAWINPUTHEADER));
		if (size != sizeof(RAWINPUT))
		{
			continue;
		}
		handle_raw_input(SDL_GetTicksNS(), &data);
	}
}

void scan::handle_raw_input(QWORD timestamp, RAWINPUT *input)
{
	static int swap_mouse_cnt=0;

	//
	// we don't care about mouse_event/sendinput
	// you are caught anyways.
	//
	if (input->header.hDevice == 0)
	{
		DWORD pid = 0;
		GetWindowThreadProcessId(GetForegroundWindow(), &pid);

		if (process_list.size() == 0)
		{
		update_list:
			process_list = get_system_processes();
		}
		BOOL tested=0;
		for (auto &process : process_list)
		{
			if (pid == process.process_id)
			{
				LOG("simulated mouse: %s\n", process.process_modules[0].name.c_str());
				tested = 1;
			}
		}

		if (tested == 0)
			goto update_list;
		return;
	}

	//
	// block all non used devices
	//
	if (device_list.size() > 1)
	{
		MOUSE_INFO  primary_dev{};
		UINT64      max_calls = 0;
 
		for (MOUSE_INFO &dev : device_list)
		{
			if (dev.total_calls > max_calls)
			{
				max_calls   = dev.total_calls;
				primary_dev = dev;
			}
		}
 
		if (max_calls > 10)
		{
			primary_dev.timestamp = timestamp;
			device_list.clear();
			device_list.push_back(primary_dev);
			LOG("primary input device has been selected\n");
		}
	}
	
	//
	// validate incoming rawinput device
	//
	BOOLEAN found = 0;
	for (MOUSE_INFO& dev : device_list)
	{
		if (dev.handle == input->header.hDevice)
		{
			found = 1;
			dev.total_calls++;
			dev.timestamp = timestamp;
			break;
		}
	}
 
	//
	// did someone send empty mouse packet?
	//
	BOOL empty = 1;
	for (int i = sizeof(RAWMOUSE); i--;)
	{
		if (((BYTE*)&input->data.mouse)[i] != 0)
		{
			empty = 0;
			break;
		}
	}
 
	if (empty)
	{
		LOG("Device: 0x%llx, timestamp: %lld, aimbot\n", (QWORD)input->header.hDevice, timestamp);
	}
 
	if (found == 0)
	{
		if (device_list.size() != 1)
		{
			return;
		}
 
		LOG("Device: 0x%llx, timestamp: %lld, invalid mouse\n", (QWORD)input->header.hDevice, timestamp);
 
		if (++swap_mouse_cnt > 10)
		{
			device_list = get_input_devices();
			swap_mouse_cnt = 0;
		}
	}
	else
	{
		swap_mouse_cnt=0;
	}
}

QWORD SDL_GetPerformanceCounter(void)
{
	LARGE_INTEGER counter;
	QueryPerformanceCounter(&counter);
	return counter.QuadPart;
}
 
QWORD SDL_GetPerformanceFrequency(void)
{
	LARGE_INTEGER frequency;
	QueryPerformanceFrequency(&frequency);
	return frequency.QuadPart;
}
 
DWORD CalculateGCD(DWORD a, DWORD b)
{
	if (b == 0) {
		return a;
	}
	return CalculateGCD(b, (a % b));
}
 
QWORD SDL_GetTicksNS(void)
{
	QWORD starting_value, value;
 
	static QWORD tick_start = SDL_GetPerformanceCounter();
	static QWORD tick_freq = SDL_GetPerformanceFrequency();
	static DWORD gcd = CalculateGCD(1000000000LL, (DWORD)tick_freq);
	static QWORD tick_numerator_ns = (1000000000LL / gcd);
	static DWORD tick_denominator_ns = (DWORD)(tick_freq / gcd);
 
	starting_value = (SDL_GetPerformanceCounter() - tick_start);
	value = (starting_value * tick_numerator_ns);
	value /= tick_denominator_ns;
	return value;
}
 
std::vector<MOUSE_INFO> get_input_devices(void)
{
	std::vector<MOUSE_INFO> devices;
 
 
	//
	// get number of devices
	//
	UINT device_count = 0;
	GetRawInputDeviceList(0, &device_count, sizeof(RAWINPUTDEVICELIST));
 
 
	//
	// allocate space for device list
	//
	RAWINPUTDEVICELIST *device_list = (RAWINPUTDEVICELIST *)malloc(sizeof(RAWINPUTDEVICELIST) * device_count);
 
 
	//
	// get list of input devices
	//
	GetRawInputDeviceList(device_list, &device_count, sizeof(RAWINPUTDEVICELIST));
 
 
	for (UINT i = 0; i < device_count; i++)
	{
		//
		// skip non mouse devices ; we can adjust this in future
		//
		if (device_list[i].dwType != RIM_TYPEMOUSE)
		{
			continue;
		}
 
 
		//
		// add new device to our dynamic list
		//
		MOUSE_INFO info{};
		info.handle = device_list[i].hDevice;
		devices.push_back(info);
	}
 
 
	//
	// free resources
	//
	free(device_list);
 
 
	return devices;
}
 
