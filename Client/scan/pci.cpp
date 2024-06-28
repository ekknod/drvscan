#include "scan.h"

namespace scan
{
	static void dumpcfg(std::vector<PORT_DEVICE_INFO> &devices);

	static void check_driver(PORT_DEVICE_INFO &port);
	static void check_hidden(PORT_DEVICE_INFO &port);
	static void check_config(PORT_DEVICE_INFO &port);

	static void PrintPcieInfo(PORT_DEVICE_INFO& port);
	static void PrintPcieConfiguration(unsigned char *cfg, int size);

	std::wstring get_driver_name(DEVICE_INFO &dev)
	{
		if (!dev.drv_device_object)
			return L"NO_DRIVER";

		QWORD driver_object = cl::vm::read<QWORD>(4, dev.drv_device_object + 0x08);
		if (!driver_object)
			return L"???";

		QWORD stradr = cl::vm::read<QWORD>(4, driver_object + 0x38 + 0x08);
		if (stradr == 0)
			return L"";

		WORD  length = cl::vm::read<WORD>(4, driver_object + 0x38);
		if (length == 0)
			return L"";

		WORD* buffer = (WORD*)malloc(length + 2);
		memset(buffer, 0, length+2);
		cl::vm::read(4, stradr, buffer, length);

		std::wstring out = std::wstring((const WCHAR*)buffer, length + 2);

		free(buffer);

		return out;
	}
}

void scan::pci(BOOL disable, BOOL advanced, BOOL dump_cfg)
{
	UNREFERENCED_PARAMETER(advanced);

	std::vector<PORT_DEVICE_INFO> port_devices = cl::pci::get_port_devices();

	if (dump_cfg)
	{
		dumpcfg(port_devices);
		return;
	}

	//
	// hidden test
	//
	for (auto &port : port_devices) if (!port.blk) check_hidden(port);

	//
	// check device config
	//
	for (auto &port : port_devices) if (!port.blk) check_config(port);

	//
	// check if device has driver
	//
	for (auto &port : port_devices) if (!port.blk) check_driver(port);


	int block_cnt = 0;
	if (disable)
	{
		for (auto &port : port_devices)
		{
			if (!port.blk)
			{
				continue;
			}

			//
			// check if bus master is enabled
			//
			WORD command = port.self.cfg.command().raw;
			if (port.self.cfg.command().bus_master_enable())
			{
				block_cnt++;
				command &= ~(1 << 2);
				cl::io::write<WORD>(port.self.physical_address + 0x04, command);
			}
		}
	}

	//
	// print white cards
	//
	for (auto &port : port_devices) if (port.blk == 0) PrintPcieInfo(port);

	//
	// print yellow cards
	//
	for (auto &port : port_devices) if (port.blk == 1) PrintPcieInfo(port);

	//
	// print red cards
	//
	for (auto &port : port_devices) if (port.blk == 2) PrintPcieInfo(port);

	if (block_cnt)
	{
		LOG("Press any key to unblock [%d] devices . . .\n", block_cnt);
		getchar();

		for (auto &port : port_devices)
		{
			if (!port.blk)
			{
				continue;
			}

			WORD command = port.self.cfg.command().raw;
			if (port.self.cfg.command().bus_master_enable())
			{
				cl::io::write<WORD>(port.self.physical_address + 0x04, command);
			}
		}
	}
}

static void scan::check_driver(PORT_DEVICE_INFO &port)
{
	BOOL driver_installed=0;

	for (auto& dev : port.devices)
	{
		//
		// device is not found
		//
		if (!dev.drv_device_object)
		{
			//
			// driverless card with bus master enable
			//
			if (dev.cfg.command().bus_master_enable())
			{
				port.blk = 2; port.blk_info = 19;
				return;
			}
		}
		else
		{
			driver_installed = 1;
		}
	}

	if (!driver_installed)
	{
		port.blk = 1; port.blk_info = 16;
	}
}

static void scan::check_hidden(PORT_DEVICE_INFO &port)
{
	for (auto& dev : port.devices)
	{
		if (!dev.pci_device_object)
		{
			port.blk = 2; port.blk_info = 5;
			break;
		}
	}
}

static void scan::check_config(PORT_DEVICE_INFO &port)
{
	BOOL bme_enabled = 0;

	for (auto &dev : port.devices)
	{
		auto pcie = dev.cfg.get_pci();
		if (pcie.cap_on != 0)
		{
			auto pcie_port = port.self.cfg.get_pci();
			//
			// end point device never should be bridge/port
			//
			if (pcie.cap.pcie_cap_device_port_type() >= PciExpressRootPort)
			{
				port.blk = 2; port.blk_info = 14;
				return;
			}

			//
			// compare data between device data and port
			//
			if (pcie.link.status.link_status_link_speed() > pcie_port.link.status.link_status_link_speed())
			{
				port.blk = 2; port.blk_info = 15;
				return;
			}

			if (pcie.link.status.link_status_link_width() > pcie_port.link.status.link_status_link_width())
			{
				port.blk = 2; port.blk_info = 15;
				return;
			}

		}

		//
		// device reports to have capabilities, lets see if we got at least power management
		//
		if (dev.cfg.status().capabilities_list() && !dev.cfg.get_pm().cap_on)
		{
			port.blk = 2; port.blk_info = 6;
			return;
		}

		if (dev.cfg.command().bus_master_enable())
		{
			//
			// some device has bus master enabled
			//
			bme_enabled = 1;
		}

		if (dev.cfg.vendor_id() == 0x10EE)
		{
			port.blk = 1; port.blk_info = 3;
			return;
		}

		//
		// 1432
		// Header Type: bit 7 (0x80) indicates whether it is a multi-function device,
		// while interesting values of the remaining bits are: 00 = general device, 01 = PCI-to-PCI bridge.
		// src: https://www.khoury.northeastern.edu/~pjd/cs7680/homework/pci-enumeration.html
		//
		if (dev.cfg.header().multifunc_device())
		{
			//
			// check if we have any children devices
			//
			if (port.devices.size() < 2)
			{
				port.blk = 2; port.blk_info = 9;
				return;
			}
		}

		if (dev.cfg.header().type() == 1)
		{
		//
		// Header Type 1 Configuration Space Header is used for Root Port and Upstream Port/Downstream Port of PCIe Switch.
		//
		}
		else if (dev.cfg.header().type() == 2)
		{
		//
		// Header Type 2 Configuration Space header is used for cardbus bridges
		//
		}
		else if (dev.cfg.header().type() == 0)
		{
		//
		// Header Type 0 Configuration Space header is used for Endpoint Devices
		//
		}
		else
		{
			//
			// invalid header type
			//
			port.blk = 2; port.blk_info = 12;
			return;
		}
	}

	//
	// port was already blocked
	//
	if (port.blk)
	{
		return;
	}

	//
	// not any device has bus master enabled, we can safely block the port
	//
	if (bme_enabled == 0)
	{
		port.blk = 1; port.blk_info = 2;
		return;
	}
}

static void scan::dumpcfg(std::vector<PORT_DEVICE_INFO> &devices)
{
	for (auto& entry : devices)
	{
		for (auto& dev : entry.devices)
		{
			printf("[%d:%d:%d] [%02X:%02X]", dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg.raw), *(WORD*)(dev.cfg.raw + 0x02));
			PrintPcieConfiguration(dev.cfg.raw, sizeof(dev.cfg));
			printf("\n");
		}
	}
}

inline const char *blkinfo(unsigned char info)
{
	switch (info)
	{
	case 1:  return "pcileech";
	case 2:  return "bus master off";
	case 3:  return "xilinx development card";
	case 4:  return "invalid port";
	case 5:  return "hidden device";
	case 6:  return "invalid cap reporting";
	case 7:  return "nulled capabilities";
	case 8:  return "nulled ext capabilities";
	case 9:  return "invalid multi func device";
	case 10: return "invalid header type 0";
	case 11: return "invalid header type 1";
	case 12: return "invalid header type";
	case 13: return "invalid config"; // just general msg
	case 14: return "invalid device type"; // just general msg
	case 15: return "port/device mismatch";
	case 16: return "driverless card";
	case 17: return "invalid network adapter";
	case 18: return "no network connections";
	case 19: return "driverless card with bus master";
	case 20: return "invalid usb controller";
	case 21: return "no attached USB devices";
	case 22: return "driver status failed";
	}
	return "OK";
}

inline PCSTR get_port_type_str(config::Pci cfg)
{
	auto pci = cfg.get_pci();
	if (!pci.cap_on)
		return "PciExpressEndpoint";

	switch (pci.cap.pcie_cap_device_port_type())
	{
		case PciExpressEndpoint: return "PciExpressEndpoint";
		case PciExpressLegacyEndpoint: return "PciExpressLegacyEndpoint";
		case 2: return "NVME";
		case PciExpressRootPort: return "PciExpressRootPort";
		case PciExpressUpstreamSwitchPort: return "PciExpressUpstreamSwitchPort";
		case PciExpressDownstreamSwitchPort: return "PciExpressDownstreamSwitchPort";
		case PciExpressToPciXBridge: return "PciExpressToPciXBridge";
		case PciXToExpressBridge: return "PciXToExpressBridge";
		case PciExpressRootComplexIntegratedEndpoint: return "PciExpressRootComplexIntegratedEndpoint";
		case PciExpressRootComplexEventCollector: return "PciExpressRootComplexEventCollector";
	}
	return "";
}

static void scan::PrintPcieInfo(PORT_DEVICE_INFO &port)
{
	if (port.blk == 1)
	{
		FontColor(14);
	}
	else if (port.blk == 2)
	{
		FontColor(4);
	}

	//
	// print port information
	//
	printf("[%s] [%02d:%02d:%02d] [%04X:%04X] (%s) [%S]\n",
		get_port_type_str(port.self.cfg), port.self.bus, port.self.slot, port.self.func,
		port.self.cfg.vendor_id(), port.self.cfg.device_id(), blkinfo(port.blk_info),
		get_driver_name(port.self).c_str()
	);

	//
	// print device PCIe device information
	//
	for (auto &dev : port.devices)
	{
		printf("	[%s] [%02d:%02d:%02d] [%04X:%04X] [%S]\n",
			get_port_type_str(dev.cfg), dev.bus, dev.slot, dev.func, dev.cfg.vendor_id(), dev.cfg.device_id(),
			get_driver_name(dev).c_str()
		);
	}

	printf("\n");

	if (port.blk)
	{
		FontColor(7);
	}
}

static void scan::PrintPcieConfiguration(unsigned char *cfg, int size)
{
	printf("\n>    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n\n");
	int line_counter=0;
	for (int i = 0; i < size; i++)
	{
		if (line_counter == 0)
		{
			if (i < 0xFF)
				printf("%02X   ", i);
			else
				printf("%02X  ", i);
		}
		line_counter++;
		printf("%02X ", cfg[i]);
		if (line_counter == 16)
		{
			printf("\n");
			line_counter=0;
		}	
	}
	printf("\n");
}
