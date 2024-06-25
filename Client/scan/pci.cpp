#include "scan.h"

namespace scan
{
	static void dumpcfg(std::vector<PORT_DEVICE_INFO> &devices);
	static void dumpbar(std::vector<PORT_DEVICE_INFO> &devices);

	static void check_driver(PORT_DEVICE_INFO &port, std::vector<PNP_ADAPTER> &pnp_adapters);
	static void check_xilinx(PORT_DEVICE_INFO &port);
	static void check_config(PORT_DEVICE_INFO &port);
	static void check_features(PORT_DEVICE_INFO &port);
	static void check_shadowcfg(PORT_DEVICE_INFO &port);

	static void PrintPcieInfo(PORT_DEVICE_INFO& port);
	static void PrintPcieConfiguration(unsigned char *cfg, int size);
	static void PrintPcieBarSpace(DWORD bar);
	static void PrintPcieCfg(config::Pci cfg);
}

void scan::pci(BOOL disable, BOOL advanced, BOOL dump_cfg, BOOL dump_bar)
{
	std::vector<PORT_DEVICE_INFO> port_devices = cl::pci::get_port_devices();

	if (dump_cfg)
	{
		dumpcfg(port_devices);
		return;
	}

	if (dump_bar)
	{
		dumpbar(port_devices);
		return;
	}

	//
	// duplicated ports
	//
	{
		std::vector<BYTE> nums;
		for (auto &port : port_devices)
		{
			BYTE secondary_bus = port.self.cfg.secondary_bus() ;

			for (auto &num : nums)
			{
				if (num == secondary_bus)
				{
					port.blk = 2;
					port.blk_info = 4;
				}
			}

			nums.push_back(secondary_bus);
		}
	}

	//
	// duplicated port devices
	//
	{
		for (auto &port : port_devices)
		{
			std::vector<DWORD> nums;
			for (auto &dev : port.devices)
			{
				DWORD location = (dev.bus << 16) | (dev.slot << 8) | dev.func;
				for (auto &num : nums)
				{
					if (location == num)
					{
						port.blk = 2;
						port.blk_info = 4;
					}
				}
				nums.push_back(location);
			}
		}
	}

	//
	// get list of device manager devices
	//
	std::vector<PNP_ADAPTER> pnp_adapters = get_pnp_adapters();


	//
	// xilinx test
	//
	if (advanced)
		for (auto &port : port_devices) if (!port.blk) check_xilinx(port);

	//
	// check device config
	//
	for (auto &port : port_devices) if (!port.blk) check_config(port);

	//
	// check device features
	//
	if (advanced)
		for (auto &port : port_devices) if (!port.blk) check_features(port);

	//
	// check shadow cfg
	//
	for (auto &port : port_devices) if (!port.blk) check_shadowcfg(port);


	//
	// check if devices are found from registry
	//
	for (auto &port : port_devices) if (!port.blk) check_driver(port, pnp_adapters);


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

BOOL is_xilinx(unsigned char *cfg)
{
	unsigned char *a0 = cfg + *(BYTE*)(cfg + 0x34);
	if (a0[1] == 0)
		return 0;

	a0 = cfg + a0[1];
	if (a0[1] == 0)
		return 0;

	DWORD a1 = *(DWORD*)(cfg + a0[1] + 0x0C);
	return (GET_BITS(a1, 14, 12) + GET_BITS(a1, 17, 15) + (GET_BIT(a1, 10) | GET_BIT(a1, 11))) == 15;
}

static void scan::check_driver(PORT_DEVICE_INFO &port, std::vector<PNP_ADAPTER> &pnp_adapters)
{
	for (auto& dev : port.devices)
	{
		BOOL found = 0;

		for (auto& pnp : pnp_adapters)
		{
			if (pnp.bus == dev.bus &&
				pnp.slot == dev.slot &&
				pnp.func == dev.func
				)
			{
				found = 1;
				//
				// check if device is bus mastering without driver
				//
				if (dev.cfg.command().bus_master_enable() && pnp.driver_status != 0 && port.devices.size() == 1)
				{
					port.blk = 2;
					port.blk_info = 22;
					return;
				}
				break;
			}
		}

		//
		// device is not found
		//
		if (!found)
		{
			//
			// driverless card with bus master enable
			//
			if (dev.cfg.command().bus_master_enable())
			{
				port.blk = 2; port.blk_info = 19;
			}
			//
			// driverless card
			//
			else
			{
				port.blk = 1; port.blk_info = 16;
			}
			return;
		}
	}
}

static void scan::check_xilinx(PORT_DEVICE_INFO &port)
{
	for (auto& dev : port.devices)
	{
		if (port.devices.size() > 1)
		{
			continue;
		}

		//
		// device says i'm not xilinx, config latency test
		//
		// if (!is_xilinx(dev.cfg.raw))
		{
			//
			// config latency test
			//
			DRIVER_TSC latency{};
			cl::pci::get_pci_latency(dev.bus, dev.slot, dev.func, 0x00, 1024, &latency);

			DRIVER_TSC shadow_cfg{};
			cl::pci::get_pci_latency(dev.bus, dev.slot, dev.func, 0xA8, 1024, &shadow_cfg);

			QWORD shadow_delta = shadow_cfg.tsc - latency.tsc;

			LOG_DEBUG("[%d:%d:%d] delta: %lld, tsc: %lld\n", dev.bus, dev.slot, dev.func, shadow_delta, latency.tsc);
		}
	}
}

static void scan::check_config(PORT_DEVICE_INFO &port)
{
	BOOL bme_enabled = 0;

	for (auto &dev : port.devices)
	{
		//
		// check that the device has a pointer to the capabilities list (status register bit 4 set to 1)
		//
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
		// hidden device, LUL.
		//
		if (dev.cfg.device_id() == 0xFFFF && dev.cfg.vendor_id() == 0xFFFF)
		{
			port.blk  = 2; port.blk_info = 5;
			return;
		}


		//
		// invalid VID/PID
		//
		if (dev.cfg.device_id() == 0x0000 && dev.cfg.vendor_id() == 0x0000)
		{
			port.blk  = 2; port.blk_info = 5;
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

	for (auto &dev : port.devices)
		if (dev.cfg.status().capabilities_list())
			for (BYTE i = 0; i < config::MAX_CAPABILITIES; i++)
			{
				auto cap = dev.cfg.get_capability_by_id(i);

				if (!cap)
					continue;

				if (*(DWORD*)(dev.cfg.raw + cap) == 0)
				{
					//
					// device reports to have next cap, but it's empty (???)
					//
					port.blk_info = 7;
					port.blk = 2;
					return;
				}
			}

	//
	// check ext capability list (https://pcisig.com/sites/default/files/files/PCI_Code-ID_r_1_12__v9_Jan_2020.pdf)
	//
	for (auto &dev : port.devices)
		for (BYTE i = 0; i < config::MAX_EXTENDED_CAPABILITIES; i++)
		{
			auto ext_cap = dev.cfg.get_ext_capability_by_id(i);

			if (!ext_cap)
				continue;

			if (*(DWORD*)(dev.cfg.raw + ext_cap) == 0)
			{
				//
				// device reports to have next cap, but it's empty (???)
				// i don't have enough data to confirm if this is possible with legal devices too
				//
				port.blk_info = 8;
				port.blk = 2;
				return;
			}
		}
}

static void scan::check_features(PORT_DEVICE_INFO &port)
{
}

static void scan::check_shadowcfg(PORT_DEVICE_INFO &port)
{
	//
	// test shadow cfg (pcileech-fpga 4.11 and lower)
	//
	for (auto& dev : port.devices)
	{
		DWORD tick = GetTickCount();
		cl::pci::write<WORD>(dev.bus, dev.slot, 0xA0, *(WORD*)(dev.cfg.raw + 0xA0));
		tick = GetTickCount() - tick;
		if (tick > 100)
			continue;

		tick = GetTickCount();
		cl::pci::write<WORD>(dev.bus, dev.slot, 0xA8, *(WORD*)(dev.cfg.raw + 0xA8));
		tick = GetTickCount() - tick;
		if (tick > 100)
		{
			port.blk = 2;
			port.blk_info = 1;
			return;
		}
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
			PrintPcieCfg(dev.cfg);
			printf("\n");
		}
	}
}

static void scan::dumpbar(std::vector<PORT_DEVICE_INFO> &devices)
{
	for (auto& entry : devices)
	for (auto& dev : entry.devices)
	{
		if (!dev.cfg.command().bus_master_enable())
		{
			continue;
		}

		for (DWORD i = 0; i < 6; i++)
		{
			DWORD bar = dev.cfg.bar(i);
			if (bar > 0x10000000)
			{
				printf("[%d:%d:%d] [%02X:%02X]\n",
					dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg.raw), *(WORD*)(dev.cfg.raw + 0x02));
				PrintPcieBarSpace(bar);
				printf("\n\n\n\n");
			}
		}

	}
}

static void scan::PrintPcieBarSpace(DWORD bar)
{
	int line_counter=0;
	int row_max_count=0;
	for (int i = 0; i < 0x1000; i+=4)
	{
		unsigned int cfg = cl::io::read<unsigned int>(bar + i);
		line_counter++;
		printf("%08X,", cfg);
		if (line_counter == 4)
		{
			printf("\n");
			line_counter=0;
		}
		row_max_count++;

		if (row_max_count == (16*4))
		{
			printf("\n");
			row_max_count=0;
		}
	}
	printf("\n");
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
	printf("[%s] [%02d:%02d:%02d] [%04X:%04X] (%s)\n",
		get_port_type_str(port.self.cfg), port.self.bus, port.self.slot, port.self.func,
		port.self.cfg.vendor_id(), port.self.cfg.device_id(), blkinfo(port.blk_info));

	//
	// print device PCIe device information
	//
	for (auto &dev : port.devices)
	{
		printf("	[%s] [%02d:%02d:%02d] [%04X:%04X]\n",
			get_port_type_str(dev.cfg), dev.bus, dev.slot, dev.func, dev.cfg.vendor_id(), dev.cfg.device_id());
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

static void scan::PrintPcieCfg(config::Pci cfg)
{
}

