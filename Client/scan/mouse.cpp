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

	void handle_raw_input(BOOL log_mouse, QWORD timestamp, RAWINPUT *input);
}

QWORD SDL_GetTicksNS(void);
std::vector<MOUSE_INFO> get_input_devices(void);

void scan::mouse(BOOL log_mouse)
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

	QWORD last_rawinput_poll = 0;
	PBYTE data_rawinput      = 0;
	DWORD rawinput_size      = 0;
	QWORD rawinput_offset    = 0;

	while (!GetAsyncKeyState(VK_F10))
	{
		UINT size, i, count, total = 0;

		if (rawinput_offset == 0) {
			BOOL isWow64;

			rawinput_offset = sizeof(RAWINPUTHEADER);
			if (IsWow64Process(GetCurrentProcess(), &isWow64) && isWow64) {
				/* We're going to get 64-bit data, so use the 64-bit RAWINPUTHEADER size */
				rawinput_offset += 8;
			}
		}

		/* Get all available events */
		RAWINPUT* input = (RAWINPUT*)data_rawinput;

		for (;;) {
			size = rawinput_size - (UINT)((BYTE*)input - data_rawinput);
			count = GetRawInputBuffer(input, &size, sizeof(RAWINPUTHEADER));
			if (count == 0 || count == (UINT)-1) {
				if (!data_rawinput || (count == (UINT)-1 && GetLastError() == ERROR_INSUFFICIENT_BUFFER)) {
					const UINT RAWINPUT_BUFFER_SIZE_INCREMENT = 96;   // 2 64-bit raw mouse packets
					BYTE* rawinput = (BYTE*)realloc(data_rawinput, rawinput_size + RAWINPUT_BUFFER_SIZE_INCREMENT);
					if (!rawinput) {
						break;
					}
					input = (RAWINPUT*)(rawinput + ((BYTE*)input - data_rawinput));
					data_rawinput = rawinput;
					rawinput_size += RAWINPUT_BUFFER_SIZE_INCREMENT;
				}
				else {
					break;
				}
			}
			else {
				total += count;

				// Advance input to the end of the buffer
				while (count--) {
					input = NEXTRAWINPUTBLOCK(input);
				}
			}
		}

		QWORD now = SDL_GetTicksNS();
		if (total > 0)
		{
			QWORD timestamp, increment;
			QWORD delta = (now - last_rawinput_poll);

			if (total > 1 && delta <= 100000000) {

				timestamp = last_rawinput_poll;
				increment = delta / total;
			}
			else
			{
				timestamp = now;
				increment = 0;
			}

			if (increment == 0 && total > 1)
			{
				goto skip;
			}

			for (i = 0, input = (RAWINPUT*)data_rawinput; i < total; ++i, input = NEXTRAWINPUTBLOCK(input)) {
				timestamp += increment;

				if (input->header.dwType == RIM_TYPEMOUSE && last_rawinput_poll) {
					// RAWMOUSE *rawmouse = (RAWMOUSE *)((BYTE *)input + rawinput_offset);
					handle_raw_input(log_mouse, timestamp, input);
				}
			}
		skip:
			last_rawinput_poll = now;
		}
	}
}

double ns_to_herz(double ns) { return 1.0 / (ns / 1e9);  }

void scan::handle_raw_input(BOOL log_mouse, QWORD timestamp, RAWINPUT *input)
{
	static int swap_mouse_cnt=0;

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
			return;
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
			if (log_mouse)
			{
				LOG("Device: 0x%llx, timestamp: %lld, hz: [%f], state: [%d,%d,%d]\n",
					(QWORD)dev.handle,
					timestamp,
					ns_to_herz((double)(timestamp - dev.timestamp)),
					input->data.mouse.lLastX, input->data.mouse.lLastY, input->data.mouse.usButtonFlags
				);
			}
			/*
			driver is required https://github.com/ekknod/acdrv, because usermode rawinput events are delayed
			else if (timestamp - dev.timestamp < 500000) // if latency is less than 500000  ns (2000 Hz). tested with 1000hz mice.
			{
				//
				// https://www.unitjuggler.com/convert-frequency-from-Hz-to-ns(p).html?val=1550
				//
				LOG("Device: 0x%llx, timestamp: %lld, hz: [%f]\n", (QWORD)dev.handle, timestamp, ns_to_herz((double)(timestamp - dev.timestamp)));
			}
			*/
			dev.timestamp = timestamp;
			break;
		}
	}

	if (found)
	{
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
			LOG("Device: 0x%llx, timestamp: %lld, empty mouse packet\n", (QWORD)input->header.hDevice, timestamp);
		}
	}

	if (found == 0)
	{
		if (device_list.size() != 1)
		{
			return;
		}
 
		LOG("Device: 0x%llx, timestamp: %lld, multiple inputs\n", (QWORD)input->header.hDevice, timestamp);
 
		if (++swap_mouse_cnt > 50)
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
	// touchpad / mouse_event
	// 
	MOUSE_INFO touchpad{};
	touchpad.handle = 0;
	devices.push_back(touchpad);
 
 
	//
	// free resources
	//
	free(device_list);

 
	return devices;
}

