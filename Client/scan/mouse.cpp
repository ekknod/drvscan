#include "scan.h"



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


typedef struct {
	WORD vendor;
	WORD product;
} KMBOXNET_LIST;

static KMBOXNET_LIST kmbox_devices[] = {
	{ 0x046d, 0xc547 }, // logitech receiver
	{ 0x1532, 0x00b7 }, // razer deathadder v3 pro
} ;

typedef struct
{
	USB_INTERFACE_DESCRIPTOR self;
	std::vector<USB_ENDPOINT_DESCRIPTOR> endpoints;
} USB_CONFIG_DESCRIPTOR_ENTRY;

typedef struct
{
	//
	// flag to check if structure is initialized
	//
	BOOLEAN present;

	//
	// iManufacturer+iProduct combined (can be null)
	//
	std::string name;

	//
	// serial number (can be null)
	//
	std::string serial_number;

	//
	// device speed
	//
	UCHAR speed;

	//
	//  device information
	//
	USB_DEVICE_DESCRIPTOR device;

	//
	// power / attributes
	//
	USB_CONFIGURATION_DESCRIPTOR config;

	//
	// list of device descriptors
	//
	std::vector<USB_CONFIG_DESCRIPTOR_ENTRY> interfaces;
} USB_INFO;

typedef struct {
	HANDLE handle;
	QWORD  total_calls;
	QWORD  timestamp;
	USB_INFO usb_info;
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

void PrintUsbInformation(USB_INFO &info)
{
	printf(
		"---------------------------------------------------------------------\n"
		"	Name:       %s\n"
		"	Serial:     %s\n"
		"	Vendor:     0x%04X\n"
		"	Product:    0x%04X\n"
		"	Speed:      %d\n"
		"	Power:      %d mA\n"
		"	Attributes: 0x%x\n",
		info.name.c_str(), info.serial_number.c_str(),
		info.device.idVendor,info.device.idProduct,
		info.speed, info.config.MaxPower << 1,
		info.config.bmAttributes
	);

	for (auto &entry : info.interfaces)
	{
		printf(
			"	<---------------------------------------------->\n"
			"	bInterfaceNumber: %d\n"
			"	bAlternateSetting: %d\n"
			"	bNumEndpoints: %d\n"
			"	bInterfaceClass: %d\n"
			"	bInterfaceSubClass: %d\n"
			"	bInterfaceProtocol: %d\n"
			"	iInterface: %d\n",
			entry.self.bInterfaceNumber,
			entry.self.bAlternateSetting,
			entry.self.bNumEndpoints,
			entry.self.bInterfaceClass,
			entry.self.bInterfaceSubClass,
			entry.self.bInterfaceProtocol,
			entry.self.iInterface
		);



		for (auto &entry2 : entry.endpoints)
		{
			printf(
				"		bEndpointAddress: 0x%02X\n"
				"		bmAttributes: 0x%02X\n"
				"		wMaxPacketSize: %d\n"
				"		bInterval: %d\n",

				entry2.bEndpointAddress,
				entry2.bmAttributes,
				entry2.wMaxPacketSize,
				entry2.bInterval
			);
		}
	}

	printf("---------------------------------------------------------------------\n");
}

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


			auto &info = dev.usb_info;

			BOOLEAN protocol_found=0;
			USHORT  packetcnt=0;
			for (auto &desc : info.interfaces)
			{
				if (desc.self.bInterfaceClass == 3 && desc.self.bInterfaceSubClass == 1 && desc.self.bInterfaceProtocol == 2)
				{
					protocol_found = 1;
					for (auto &end : desc.endpoints)
					{
						packetcnt = end.wMaxPacketSize;
						break;
					}
					break;
				}
			}

			BOOL heuristic = (info.config.MaxPower << 1) == 500 && GET_BIT(info.config.bmAttributes, 6) == 0;

			if (!protocol_found || heuristic)
			{
				BOOL color = 0;

				for (auto &kbox : kmbox_devices)
				{
					if (kbox.vendor == info.device.idVendor && kbox.product == info.device.idProduct)
					{
						color = 1;
						break;
					}
				}

				if (color)
				{
					LOG_RED("kmbox device detected\n");

					PrintUsbInformation(info);
				}
				else
				{
					if (!protocol_found || packetcnt == 20)
					{
						LOG_YELLOW("potential kmbox device\n");
						PrintUsbInformation(info);
					}
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

DEFINE_GUID(GUID_DEVINTERFACE_USB_DEVICE, 0xA5DCBF10L, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, \
	0xC0, 0x4F, 0xB9, 0x51, 0xED);


DEFINE_GUID(GUID_DEVINTERFACE_USB_HUB, 0xf18a0e88, 0xc30c, 0x11d0, 0x88, 0x15, 0x00, \
	0xa0, 0xc9, 0x06, 0xbe, 0xd8);

DEFINE_GUID(GUID_DEVINTERFACE_USB_HOST_CONTROLLER, 0x3abf6f2d, 0x71c4, 0x462a, 0x8a, 0x92, 0x1e, \
	0x68, 0x61, 0xe6, 0xaf, 0x27);

PUSB_DESCRIPTOR_REQUEST
GetConfigDescriptor(
	HANDLE  hHubDevice,
	ULONG   ConnectionIndex,
	UCHAR   DescriptorIndex
);

USB_NODE_CONNECTION_INFORMATION_EX
GetDeviceConnectionInfo(
	HANDLE  hHubDevice,
	ULONG   ConnectionIndex
)
{
	USB_NODE_CONNECTION_INFORMATION_EX connectionInfoEx = { 0 };
	connectionInfoEx.ConnectionIndex = ConnectionIndex;

	DWORD bytesReturned{};
	BOOL success = DeviceIoControl(
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
		return connectionInfoEx;
	}

	return connectionInfoEx;
}

std::string get_descriptor_string(HANDLE hub, DWORD connection_index, UCHAR string_index)
{
	char buffer[2048];

	std::string out{};

	USB_DESCRIPTOR_REQUEST Request = { 0 };
	Request.ConnectionIndex = connection_index;
	Request.SetupPacket.wValue = (short)((USB_STRING_DESCRIPTOR_TYPE << 8) + string_index);
	Request.SetupPacket.wLength = (short)(2048 - sizeof(Request));
	Request.SetupPacket.wIndex = 0x409; // Language Code

	memset(buffer, 0, 2048);
	if (DeviceIoControl(hub, IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION, &Request, 2048, buffer, 2048, 0, 0))
	{
		USB_STRING_DESCRIPTOR* desc = (USB_STRING_DESCRIPTOR*)buffer + 3;
		WCHAR* tmp = desc->bString;
		while (*tmp) {
			out.push_back((CHAR)*tmp);
			tmp++;
		}
	}

	return out;
}

#pragma warning (disable: 4815)

USB_INFO get_usb_device_info(HANDLE hub, DWORD index)
{
	USB_INFO out{};

	auto connection_info = GetDeviceConnectionInfo(hub, index);
	if (connection_info.ConnectionStatus != USB_CONNECTION_STATUS::DeviceConnected)
	{
		return {};
	}

	out.device = connection_info.DeviceDescriptor;

	if (out.device.iManufacturer)
	{
		out.name += get_descriptor_string(hub, index, out.device.iManufacturer) + " ";
	}

	if (out.device.iProduct)
	{
		out.name += get_descriptor_string(hub, index, out.device.iProduct) + " ";
	}

	if (out.device.iSerialNumber)
	{
		out.serial_number += get_descriptor_string(hub, index, out.device.iSerialNumber);
	}

	auto config_descriptor = GetConfigDescriptor(hub, index, 0);
	if (config_descriptor == 0)
	{
		return out;
	}

	out.speed   = connection_info.Speed;
	out.present = 1;

	auto usb_desc = (PUSB_CONFIGURATION_DESCRIPTOR)(config_descriptor + 1);
	auto usb_desc_size = (PUCHAR)usb_desc + usb_desc->wTotalLength;
	auto entry = (PUSB_COMMON_DESCRIPTOR)usb_desc;

	while ((PUCHAR)entry + sizeof(USB_COMMON_DESCRIPTOR) <= usb_desc_size &&
		(PUCHAR)entry + entry->bLength <= usb_desc_size)
	{
		if (entry->bDescriptorType == USB_INTERFACE_DESCRIPTOR_TYPE)
		{
			USB_CONFIG_DESCRIPTOR_ENTRY temp{};
			temp.self = *(USB_INTERFACE_DESCRIPTOR*)entry;
			out.interfaces.push_back( temp  );
		}

		else if (entry->bDescriptorType == USB_CONFIGURATION_DESCRIPTOR_TYPE)
		{
			out.config = *(USB_CONFIGURATION_DESCRIPTOR*)entry;
		}

		else if (entry->bDescriptorType == USB_ENDPOINT_DESCRIPTOR_TYPE)
		{
			out.interfaces[out.interfaces.size() - 1].endpoints.push_back(*(USB_ENDPOINT_DESCRIPTOR*)entry);
		}

		entry = (PUSB_COMMON_DESCRIPTOR)((PUCHAR)entry + entry->bLength);
	}
	free(config_descriptor);
	return out;
}

UCHAR GetUsbPortCount(HANDLE hub)
{
	USB_NODE_INFORMATION hubInfo = {  };
	DWORD bytesReturned = 0;
	BOOL success = DeviceIoControl(
		hub,
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
		return 0;
	}

	return hubInfo.u.HubInformation.HubDescriptor.bNumberOfPorts;
}

std::vector<USB_INFO> get_usb_devices()
{
	std::vector<USB_INFO> devices;

	HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_USB_HUB, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	if (hDevInfo == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Error: Unable to get device information set for USB hubs. " << GetLastError() << std::endl;
		return {};
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

		for (ULONG port = 1; port <= GetUsbPortCount(hHubDevice); port++)
		{
			USB_INFO usb_device = get_usb_device_info(hHubDevice, port);
			if (!usb_device.present)
			{
				continue;
			}
			devices.push_back(usb_device);
		}

		CloseHandle(hHubDevice);

		free(pDeviceInterfaceDetailData);
		index++;
	}

	SetupDiDestroyDeviceInfoList(hDevInfo);

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
		USB_INFO dev_info{};
		for (auto &entry : usb_devices)
		{
			char vidpid[255]{};
			snprintf(vidpid, 255, "\\\\?\\HID#VID_%04X&PID_%04X&MI_", entry.device.idVendor, entry.device.idProduct);
			if (strstr(name, vidpid))
			{
				dev_info = entry;
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
		info.usb_info = dev_info;
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

