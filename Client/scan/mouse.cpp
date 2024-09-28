#include "scan.h"


typedef struct {
	WORD vendor;
	WORD product;
} KMBOXNET_LIST;

static KMBOXNET_LIST kmbox_devices[] = {
	{ 0x046d, 0xc547 }, // logitech receiver
	{ 0x1532, 0x00b7 }, // razer deathadder v3 pro
} ;

typedef struct {
	HANDLE handle;
	QWORD  total_calls;
	QWORD  timestamp;

	WORD  vid,pid;
	UCHAR device_class;
	UCHAR device_subclass;
	UCHAR device_protocol;
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

			if (dev.device_class != 3 || dev.device_subclass != 1 || dev.device_protocol != 2)
			{
				dev.device_class = 3; dev.device_subclass = 0; dev.device_protocol = 0;
				BOOL color = 0;

				for (auto &kbox : kmbox_devices)
				{
					if (kbox.vendor == dev.vid && kbox.product == dev.pid)
					{
						color = 1;
						break;
					}
				}

				if (color)
				{
					LOG_RED("kmbox device detected [%04X:%04X] [%d,%d,%d]\n", dev.vid, dev.pid, dev.device_class, dev.device_subclass, dev.device_protocol);
				}
				else
				{
					LOG_YELLOW("potential kmbox device [%04X:%04X] [%d,%d,%d]\n", dev.vid, dev.pid, dev.device_class, dev.device_subclass, dev.device_protocol);
				}
			}

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


#include <string>
#include <strsafe.h>
#include <usbioctl.h>
#include <setupapi.h>
#include <iostream>
#include <iostream>
#include <Windows.h>
#include <SetupAPI.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <usbiodef.h>
#include <usbioctl.h>
#include <regex>

#pragma comment(lib, "Setupapi.lib")


DEFINE_GUID(GUID_DEVINTERFACE_USB_DEVICE, 0xA5DCBF10L, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, \
	0xC0, 0x4F, 0xB9, 0x51, 0xED);


DEFINE_GUID(GUID_DEVINTERFACE_USB_HUB, 0xf18a0e88, 0xc30c, 0x11d0, 0x88, 0x15, 0x00, \
	0xa0, 0xc9, 0x06, 0xbe, 0xd8);

DEFINE_GUID(GUID_DEVINTERFACE_USB_HOST_CONTROLLER, 0x3abf6f2d, 0x71c4, 0x462a, 0x8a, 0x92, 0x1e, \
	0x68, 0x61, 0xe6, 0xaf, 0x27);


std::vector<HANDLE> get_usb_hubs(void)
{
	std::vector<HANDLE> hubs;

	HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_USB_HUB, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	if (hDevInfo == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Error: Unable to get device information set for USB hubs. " << GetLastError() << std::endl;
		return hubs;
	}

	SP_DEVICE_INTERFACE_DATA deviceInterfaceData;
	deviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

	DWORD index = 0;
	while (SetupDiEnumDeviceInterfaces(
		hDevInfo,
		NULL,
		&GUID_DEVINTERFACE_USB_HUB,
		index,
		&deviceInterfaceData
	))
	{
		DWORD requiredSize = 0;
		SetupDiGetDeviceInterfaceDetail(hDevInfo, &deviceInterfaceData, NULL, 0, &requiredSize, NULL);

		PSP_DEVICE_INTERFACE_DETAIL_DATA pDeviceInterfaceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(requiredSize);
		if (!pDeviceInterfaceDetailData)
		{
			std::cerr << "Error: Unable to allocate memory. " << GetLastError() << std::endl;
			break;
		}

		pDeviceInterfaceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

		SP_DEVINFO_DATA devInfoData;
		devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

		if (!SetupDiGetDeviceInterfaceDetail(
			hDevInfo,
			&deviceInterfaceData,
			pDeviceInterfaceDetailData,
			requiredSize,
			NULL,
			&devInfoData
		))
		{
			std::cerr << "Error: Unable to get device interface detail data. " << GetLastError() << std::endl;
			free(pDeviceInterfaceDetailData);
			break;
		}

		HANDLE hHubDevice = CreateFile(
			pDeviceInterfaceDetailData->DevicePath,
			GENERIC_WRITE,
			FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			0,
			NULL
		);

		if (hHubDevice == INVALID_HANDLE_VALUE)
		{
			std::cerr << "Error: Unable to open hub device. " << GetLastError() << std::endl;
			free(pDeviceInterfaceDetailData);
			index++;
			continue;
		}

		hubs.push_back(hHubDevice);
		free(pDeviceInterfaceDetailData);
		index++;
	}

	SetupDiDestroyDeviceInfoList(hDevInfo);

	return hubs;
}

typedef struct _STRING_DESCRIPTOR_NODE
{
    struct _STRING_DESCRIPTOR_NODE *Next;
    UCHAR                           DescriptorIndex;
    USHORT                          LanguageID;
    USB_STRING_DESCRIPTOR           StringDescriptor[1];
} STRING_DESCRIPTOR_NODE, *PSTRING_DESCRIPTOR_NODE;

typedef struct _USB_INTERFACE_DESCRIPTOR2 {
    UCHAR  bLength;             // offset 0, size 1
    UCHAR  bDescriptorType;     // offset 1, size 1
    UCHAR  bInterfaceNumber;    // offset 2, size 1
    UCHAR  bAlternateSetting;   // offset 3, size 1
    UCHAR  bNumEndpoints;       // offset 4, size 1
    UCHAR  bInterfaceClass;     // offset 5, size 1
    UCHAR  bInterfaceSubClass;  // offset 6, size 1
    UCHAR  bInterfaceProtocol;  // offset 7, size 1
    UCHAR  iInterface;          // offset 8, size 1
    USHORT wNumClasses;         // offset 9, size 2
} USB_INTERFACE_DESCRIPTOR2, *PUSB_INTERFACE_DESCRIPTOR2;

PUSB_DESCRIPTOR_REQUEST
GetConfigDescriptor(
	HANDLE  hHubDevice,
	ULONG   ConnectionIndex,
	UCHAR   DescriptorIndex
);

BOOL get_device_descriptor(HANDLE hub, DWORD index, USB_DEVICE_DESCRIPTOR *device_descriptor)
{
	auto config_descriptor = GetConfigDescriptor(hub, index, 0);
	if (config_descriptor == 0)
	{
		return 0;
	}

	auto usb_desc = (PUSB_CONFIGURATION_DESCRIPTOR)(config_descriptor + 1);
	auto usb_desc_size = (PUCHAR)usb_desc + usb_desc->wTotalLength;
	auto entry = (PUSB_COMMON_DESCRIPTOR)usb_desc;
	BOOL status = 0;

	while ((PUCHAR)entry + sizeof(USB_COMMON_DESCRIPTOR) <= usb_desc_size &&
		(PUCHAR)entry + entry->bLength <= usb_desc_size)
	{
		if (entry->bDescriptorType == USB_INTERFACE_DESCRIPTOR_TYPE)
		{
			device_descriptor->bDeviceClass    = ((PUSB_INTERFACE_DESCRIPTOR)entry)->bInterfaceClass;
			device_descriptor->bDeviceSubClass = ((PUSB_INTERFACE_DESCRIPTOR)entry)->bInterfaceSubClass;
			device_descriptor->bDeviceProtocol = ((PUSB_INTERFACE_DESCRIPTOR)entry)->bInterfaceProtocol;
			status = 1;
			break;
		}
		entry = (PUSB_COMMON_DESCRIPTOR)((PUCHAR)entry + entry->bLength);
	}
	free(config_descriptor);
	return status;
}

typedef struct
{
	WORD  vendor;
	WORD  product;
	UCHAR device_class;
	UCHAR device_subclass;
	UCHAR device_protocol;
} USB_CLS_INFO;

std::vector<USB_CLS_INFO> get_usb_devices()
{
	std::vector<USB_CLS_INFO> devices;

	const auto hubs = get_usb_hubs();

	for (const auto hHubDevice : hubs)
	{
		// Get hub information
		USB_NODE_INFORMATION hubInfo = {  };
		DWORD bytesReturned = 0;
		BOOL success = DeviceIoControl(
			hHubDevice,
			IOCTL_USB_GET_NODE_INFORMATION,
			&hubInfo,
			sizeof(hubInfo),
			&hubInfo,
			sizeof(hubInfo),
			&bytesReturned,
			NULL
		);

		if (!success)
		{
			std::cerr << "Error: Unable to get hub information. " << GetLastError() << std::endl;
			CloseHandle(hHubDevice);
			continue;
		}

		ULONG numPorts = hubInfo.u.HubInformation.HubDescriptor.bNumberOfPorts;

		// Enumerate ports on the hub
		for (ULONG port = 1; port <= numPorts; port++)
		{
			USB_NODE_CONNECTION_INFORMATION_EX connectionInfoEx = { 0 };
			connectionInfoEx.ConnectionIndex = port;

			success = DeviceIoControl(
				hHubDevice,
				IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX,
				&connectionInfoEx,
				sizeof(connectionInfoEx),
				&connectionInfoEx,
				sizeof(connectionInfoEx),
				&bytesReturned,
				NULL
			);

			if (!success)
			{
				std::cerr << "Error: Unable to get connection information. " << GetLastError() << std::endl;
				continue;
			}

			// Check if a device is connected
			if (connectionInfoEx.ConnectionStatus != USB_CONNECTION_STATUS::DeviceConnected)
			{
				continue;
			}

			// Use the DeviceDescriptor from connectionInfoEx
			if (!get_device_descriptor(hHubDevice, port, &connectionInfoEx.DeviceDescriptor))
			{
				continue;
			}

			devices.push_back(
				{ connectionInfoEx.DeviceDescriptor.idVendor, connectionInfoEx.DeviceDescriptor.idProduct,
				connectionInfoEx.DeviceDescriptor.bDeviceClass,
				connectionInfoEx.DeviceDescriptor.bDeviceSubClass,
				connectionInfoEx.DeviceDescriptor.bDeviceProtocol
				}
			);
		}

		CloseHandle(hHubDevice);
	}

	return devices;
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


	auto usb_devices = get_usb_devices();
 
 
	for (UINT i = 0; i < device_count; i++)
	{
		//
		// skip non mouse devices ; we can adjust this in future
		//
		if (device_list[i].dwType != RIM_TYPEMOUSE)
		{
			continue;
		}


		UINT name_length = 0;
		GetRawInputDeviceInfoA(device_list[i].hDevice, RIDI_DEVICENAME, 0, &name_length);
		CHAR *name = (char *)malloc(name_length);
		GetRawInputDeviceInfoA(device_list[i].hDevice, RIDI_DEVICENAME, name, &name_length);

		BOOL found = 0;
		USB_CLS_INFO cls_info{};
		for (auto &entry : usb_devices)
		{
			char vidpid[255]{};
			snprintf(vidpid, 255, "\\\\?\\HID#VID_%04X&PID_%04X&MI_", entry.vendor, entry.product);

			if (strstr(name, vidpid))
			{
				cls_info = entry;
				found = 1;
				break;
			}
		}

		free(name);

		if (!found)
		{
			continue;
		}

		//
		// add new device to our dynamic list
		//
		MOUSE_INFO info{};
		info.handle = device_list[i].hDevice;
		info.device_class = cls_info.device_class;
		info.device_subclass = cls_info.device_subclass;
		info.device_protocol = cls_info.device_protocol;
		info.vid = cls_info.vendor;
		info.pid = cls_info.product;
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

PUSB_DESCRIPTOR_REQUEST
GetConfigDescriptor(
	HANDLE  hHubDevice,
	ULONG   ConnectionIndex,
	UCHAR   DescriptorIndex
)
{
	BOOL    success = 0;
	ULONG   nBytes = 0;
	ULONG   nBytesReturned = 0;

	UCHAR   configDescReqBuf[sizeof(USB_DESCRIPTOR_REQUEST) +
		sizeof(USB_CONFIGURATION_DESCRIPTOR)];

	PUSB_DESCRIPTOR_REQUEST         configDescReq = NULL;
	PUSB_CONFIGURATION_DESCRIPTOR   configDesc = NULL;


	// Request the Configuration Descriptor the first time using our
	// local buffer, which is just big enough for the Cofiguration
	// Descriptor itself.
	//
	nBytes = sizeof(configDescReqBuf);

	configDescReq = (PUSB_DESCRIPTOR_REQUEST)configDescReqBuf;
	configDesc = (PUSB_CONFIGURATION_DESCRIPTOR)(configDescReq + 1);

	// Zero fill the entire request structure
	//
	memset(configDescReq, 0, nBytes);

	// Indicate the port from which the descriptor will be requested
	//
	configDescReq->ConnectionIndex = ConnectionIndex;

	//
	// USBHUB uses URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE to process this
	// IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION request.
	//
	// USBD will automatically initialize these fields:
	//     bmRequest = 0x80
	//     bRequest  = 0x06
	//
	// We must inititialize these fields:
	//     wValue    = Descriptor Type (high) and Descriptor Index (low byte)
	//     wIndex    = Zero (or Language ID for String Descriptors)
	//     wLength   = Length of descriptor buffer
	//
	configDescReq->SetupPacket.wValue = (USB_CONFIGURATION_DESCRIPTOR_TYPE << 8)
		| DescriptorIndex;

	configDescReq->SetupPacket.wLength = (USHORT)(nBytes - sizeof(USB_DESCRIPTOR_REQUEST));

	// Now issue the get descriptor request.
	//
	success = DeviceIoControl(hHubDevice,
		IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
		configDescReq,
		nBytes,
		configDescReq,
		nBytes,
		&nBytesReturned,
		NULL);

	if (!success)
	{
		return NULL;
	}

	if (nBytes != nBytesReturned)
	{
		return NULL;
	}

	if (configDesc->wTotalLength < sizeof(USB_CONFIGURATION_DESCRIPTOR))
	{
		return NULL;
	}

	// Now request the entire Configuration Descriptor using a dynamically
	// allocated buffer which is sized big enough to hold the entire descriptor
	//
	nBytes = sizeof(USB_DESCRIPTOR_REQUEST) + configDesc->wTotalLength;

	configDescReq = (PUSB_DESCRIPTOR_REQUEST)malloc(nBytes);

	if (configDescReq == NULL)
	{
		return NULL;
	}

	configDesc = (PUSB_CONFIGURATION_DESCRIPTOR)(configDescReq + 1);

	// Indicate the port from which the descriptor will be requested
	//
	configDescReq->ConnectionIndex = ConnectionIndex;

	//
	// USBHUB uses URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE to process this
	// IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION request.
	//
	// USBD will automatically initialize these fields:
	//     bmRequest = 0x80
	//     bRequest  = 0x06
	//
	// We must inititialize these fields:
	//     wValue    = Descriptor Type (high) and Descriptor Index (low byte)
	//     wIndex    = Zero (or Language ID for String Descriptors)
	//     wLength   = Length of descriptor buffer
	//
	configDescReq->SetupPacket.wValue = (USB_CONFIGURATION_DESCRIPTOR_TYPE << 8)
		| DescriptorIndex;

	configDescReq->SetupPacket.wLength = (USHORT)(nBytes - sizeof(USB_DESCRIPTOR_REQUEST));

	// Now issue the get descriptor request.
	//

	success = DeviceIoControl(hHubDevice,
		IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION,
		configDescReq,
		nBytes,
		configDescReq,
		nBytes,
		&nBytesReturned,
		NULL);

	if (!success)
	{
		free(configDescReq);
		return NULL;
	}

	if (nBytes != nBytesReturned)
	{
		free(configDescReq);
		return NULL;
	}

	if (configDesc->wTotalLength != (nBytes - sizeof(USB_DESCRIPTOR_REQUEST)))
	{
		free(configDescReq);
		return NULL;
	}
	return configDescReq;
}

