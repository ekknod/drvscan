#include "scan.h"

//0x28 bytes (sizeof)
struct _ISRDPCSTATS_SEQUENCE
{
    DWORD SequenceNumber;                                               //0x0
    QWORD IsrTime;                                                      //0x8
    QWORD IsrCount;                                                     //0x10
    QWORD DpcTime;                                                      //0x18
    QWORD DpcCount;                                                     //0x20
};

typedef struct _ISRDPCSTATS {
    QWORD IsrTime;                                                      //0x0
    QWORD IsrTimeStart;                                                 //0x8
    QWORD IsrCount;                                                     //0x10
    QWORD DpcTime;                                                      //0x18
    QWORD DpcTimeStart;                                                 //0x20
    QWORD DpcCount;                                                     //0x28
    UCHAR IsrActive;                                                    //0x30
    UCHAR Reserved[7];                                                  //0x31
    struct _ISRDPCSTATS_SEQUENCE DpcWatchdog;                           //0x38
} ISRDPCSTATS;

typedef struct {
	BYTE  bus,slot,func;
	config::Pci cfg;
	QWORD pci_device_object;
	QWORD drv_device_object;
} DEVICE_INFO;

typedef struct {
	unsigned char  blk;       // is port blocked
	unsigned char  blk_info;  // reason for blocking
	DEVICE_INFO    self;      // self data
	std::vector<DEVICE_INFO> devices;
} PORT_DEVICE_INFO;

namespace scan
{
	static void dumpcfg(std::vector<PORT_DEVICE_INFO> &devices);

	static void check_faceit(PORT_DEVICE_INFO &port);
	static void check_activity(PORT_DEVICE_INFO &port);
	static void check_driver(PORT_DEVICE_INFO &port);
	static void check_hidden(PORT_DEVICE_INFO &port);
	static void check_gummybear(BOOL advanced, PORT_DEVICE_INFO &port);
	static void check_config(PORT_DEVICE_INFO &port);
	static void check_features(PORT_DEVICE_INFO &port, std::vector<PNP_ADAPTER> &pnp_adapters);

	static void PrintPcieInfo(PORT_DEVICE_INFO& port);
	static void PrintPcieConfiguration(unsigned char *cfg, int size);

	static void filter_pci_cfg(config::Pci &cfg);

	std::vector<PORT_DEVICE_INFO> get_port_devices(void);
	BOOL get_isr_stats(DEVICE_INFO& dev, ISRDPCSTATS* out);

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

void scan::pci(BOOL disable, BOOL advanced, BOOL dump_cfg)
{
	UNREFERENCED_PARAMETER(advanced);

	std::vector<PORT_DEVICE_INFO> port_devices = get_port_devices();

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
	// shadow test : public troll
	//
	for (auto &port : port_devices) if (!port.blk) check_gummybear(advanced, port);

	//
	// check device config
	//
	for (auto &port : port_devices) if (!port.blk) check_config(port);

	//
	// check if device has driver
	//
	for (auto &port : port_devices) if (!port.blk) check_driver(port);

	//
	// check faceit : my anti-cheat would never do this. really cheap way.
	//
	for (auto &port : port_devices) if (!port.blk) check_faceit(port);

	//
	// check if device has fired any interrupt (everdox & ekknod)
	//
	for (auto &port : port_devices) if (!port.blk) check_activity(port);

	if (advanced)
	{
		std::vector<PNP_ADAPTER> pnp_devices = get_pnp_adapters();
		for (auto &port : port_devices) if (!port.blk) check_features(port, pnp_devices);
	}


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
				cl::pci::write<WORD>(port.self.bus, port.self.slot, port.self.func, 0x04, command);
			}
			else
			{
				continue;
			}

			//
			// block endpoints too
			//
			for (auto &dev : port.devices)
			{
				command = dev.cfg.command().raw;
				if (dev.cfg.command().bus_master_enable())
				{
					command &= ~(1 << 2);
					cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, 0x04, command);

					//
					// forced command register
					//
					if (cl::pci::read<WORD>(dev.bus, dev.slot, dev.func, 0x04) == dev.cfg.command().raw)
					{
						port.blk = 2;
						port.blk_info = 23;
						break;
					}
				}
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
				cl::pci::write<WORD>(port.self.bus, port.self.slot, port.self.func, 0x04, command);
			}
			else
			{
				continue;
			}

			//
			// unblock endpoints too
			//
			for (auto &dev : port.devices)
			{
				command = dev.cfg.command().raw;
				if (dev.cfg.command().bus_master_enable())
				{
					cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, 0x04, command);
				}
			}
		}
	}
}

static void scan::check_faceit(PORT_DEVICE_INFO &port)
{
	UNREFERENCED_PARAMETER(port);
	/*
	for (auto& dev : port.devices)
	{
		if (is_xilinx(dev.cfg.raw))
		{
			port.blk_info = 3;
			port.blk = 1;
			break;
		}
	}
	*/
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

BOOL is_interrupt_enabled(config::Pci &cfg)
{
	//
	// legacy
	//
	if (!cfg.command().interrupt_disable())
	{
		return 1;
	}

	//
	// msi
	//
	auto msi = cfg.get_msi();
	if (msi.cap_on && msi.cap.msi_enabled())
	{
		return 1;
	}

	//
	// msix
	//
	auto msix = cfg.get_msix();
	if (msix.cap_on && msix.cap.msix_enabled())
	{
		return 1;
	}
	return 0;
}

static void scan::check_activity(PORT_DEVICE_INFO& port)
{
	BOOL activity = 0;
	BOOL dev_with_ints = 0;

	for (auto& dev : port.devices)
	{
		if (!dev.cfg.command().bus_master_enable())
		{
			continue;
		}

		int interrupts = is_interrupt_enabled(dev.cfg);
		if (!interrupts)
		{
			continue;
		}

		ISRDPCSTATS isr_stats{};
		if (!get_isr_stats(dev, &isr_stats))
		{
			continue;
		}

		dev_with_ints = 1;
		if (isr_stats.IsrCount)
		{
			activity = 1;
			break;
		}
	}

	if (!activity && dev_with_ints)
	{
		port.blk = 1;
		port.blk_info = 24;
	}
}

static void scan::check_hidden(PORT_DEVICE_INFO &port)
{
	if (!port.self.pci_device_object)
	{
		port.blk = 2; port.blk_info = 5;
		return;
	}

	for (auto& dev : port.devices)
	{
		if (!dev.pci_device_object)
		{
			port.blk = 2; port.blk_info = 5;
			break;
		}
	}
}

static void scan::check_gummybear(BOOL advanced, PORT_DEVICE_INFO& port)
{
	UNREFERENCED_PARAMETER(advanced);

	for (auto& dev : port.devices)
	{
		if (!dev.cfg.command().bus_master_enable())
		{
			continue;
		}

		//
		// testing standard default capabilities
		//
		if (dev.cfg.status().capabilities_list())
		{
			for (BYTE cap_id = 0; cap_id < config::MAX_CAPABILITIES; cap_id++)
			{
				BYTE cap = dev.cfg.get_capability_by_id(cap_id);

				if (cap == 0)
				{
					continue;
				}

				//
				// test if everything can be written
				//
				cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, cap, 0);
				if (cl::pci::read<WORD>(dev.bus, dev.slot, dev.func, cap) != *(WORD*)(dev.cfg.raw + cap))
				{
					cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, cap, *(WORD*)(dev.cfg.raw + cap));
					port.blk = 2;
					port.blk_info = 23;
					return;
				}

				if (cap_id == 0x01) // PM (R/W & R/O)
				{
				}

				else if (cap_id == 0x05) // MSI (R/O)
				{
					auto msi = dev.cfg.get_msi();
					BYTE ctrl = msi.cap.msi_cap_64_bit_addr_capable() ?
						(msi.cap.raw & 0xFF) & ~(1 << 7) :
						(msi.cap.raw & 0xFF) | (1 << 7);

					cl::pci::write<BYTE>(dev.bus, dev.slot, dev.func, cap + 0x02, ctrl);
					if (GET_BIT(cl::pci::read<BYTE>(dev.bus, dev.slot, dev.func, cap + 0x02), 7) !=
						msi.cap.msi_cap_64_bit_addr_capable())
					{
						port.blk = 2;
						port.blk_info = 23;
						return;
					}
				}

				else if (cap_id == 0x10) // PCI-X (R/W)
				{
					auto pci = dev.cfg.get_pci();
					BYTE offs = pci.base_ptr + 0x04 + 0x04;

					WORD data = pci.dev.control.dev_ctrl_ur_reporting() ?
						pci.dev.control.raw & ~(1 << 3) : pci.dev.control.raw | (1 << 3);

					cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, offs, data);
					if (cl::pci::read<WORD>(dev.bus, dev.slot, dev.func, offs) == pci.dev.control.raw)
					{
						port.blk = 2;
						port.blk_info = 23;
						return;
					}
					else
					{
						cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, offs, pci.dev.control.raw);
					}

					// risky, risky
					if (!pci.dev.status.unsupported_request_detected()) continue;
					cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, offs + 0x02, pci.dev.status.raw);
					pci.dev.status.raw = cl::pci::read<WORD>(dev.bus, dev.slot, dev.func, offs + 0x02);
					if (pci.dev.status.unsupported_request_detected())
					{
						port.blk = 2;
						port.blk_info = 23;
						return;
					}
				}

				else if (cap_id == 0x11) // msix (R/O) test
				{
					auto msix = dev.cfg.get_msix();
					BYTE msix_val = *(BYTE*)(dev.cfg.raw + msix.base_ptr + 0x02);
					cl::pci::write<BYTE>(dev.bus, dev.slot, dev.func, msix.base_ptr + 0x02, msix_val + 1);
					if (cl::pci::read<BYTE>(dev.bus, dev.slot, dev.func, msix.base_ptr + 0x02) != msix_val)
					{
						cl::pci::write<BYTE>(dev.bus, dev.slot, dev.func, msix.base_ptr + 0x02, msix_val);
						port.blk = 2;
						port.blk_info = 23;
						return;
					}
				}
			}
		}

		//
		// testing extended capabilities
		//
		for (BYTE cap_id = 0; cap_id < config::MAX_EXTENDED_CAPABILITIES; cap_id++)
		{
			WORD cap = dev.cfg.get_ext_capability_by_id(cap_id);

			if (cap == 0)
			{
				continue;
			}

			//
			// test if everything can be written
			//
			cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, cap, 0);
			if (cl::pci::read<WORD>(dev.bus, dev.slot, dev.func, cap) != *(WORD*)(dev.cfg.raw + cap))
			{
				cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, cap, *(WORD*)(dev.cfg.raw + cap));
				port.blk = 2;
				port.blk_info = 23;
				return;
			}

			if (cap_id == 0x01) // AER
			{
			}

			else if (cap_id == 0x02) // VC [R/O] test
			{
				WORD resrc_status = *(WORD*)(dev.cfg.raw + cap + 0x1A);
				cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, cap + 0x1A, resrc_status + 1);
				if (cl::pci::read<WORD>(dev.bus, dev.slot, dev.func, cap + 0x1A) != resrc_status)
				{
					port.blk = 2;
					port.blk_info = 23;
					return;
				}
			}

			else if (cap_id == 0x03) // DSN
			{
				DWORD lower_32bits = *(DWORD*)(dev.cfg.raw + cap + 0x04);
				cl::pci::write<DWORD>(dev.bus, dev.slot, dev.func, cap + 0x04, lower_32bits + 1);
				if (cl::pci::read<DWORD>(dev.bus, dev.slot, dev.func, cap + 0x04) != lower_32bits)
				{
					cl::pci::write<DWORD>(dev.bus, dev.slot, dev.func, cap + 0x04, lower_32bits);
					port.blk = 2;
					port.blk_info = 23;
					return;
				}
			}

			else if (cap_id == 0x0B) // VSEC [R/O]
			{
				WORD vsec_id = *(WORD*)(dev.cfg.raw + cap + 0x04);
				cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, cap + 0x04, vsec_id + 1);
				if (cl::pci::read<WORD>(dev.bus, dev.slot, dev.func, cap + 0x04) != vsec_id)
				{
					cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, cap + 0x04, vsec_id);
					port.blk = 2;
					port.blk_info = 23;
					return;
				}
			}

			else if (cap_id == 0x1E)
			{
			}

			else if (cap_id == 0x18) // Latency Tolerance Reporting (LTR) [R/W]
			{
				BYTE max_snoop_latency = *(BYTE*)(dev.cfg.raw + cap + 0x04);
				cl::pci::write<BYTE>(dev.bus, dev.slot, dev.func, cap + 0x04, max_snoop_latency + 1);
				if (cl::pci::read<BYTE>(dev.bus, dev.slot, dev.func, cap + 0x04) == max_snoop_latency)
				{
					port.blk = 2;
					port.blk_info = 23;
					return;
				}
				else
				{
					cl::pci::write<BYTE>(dev.bus, dev.slot, dev.func, cap + 0x04, max_snoop_latency);
				}
			}
		}
		break;
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

static void validate_network_adapters(PORT_DEVICE_INFO &port, PNP_ADAPTER &pnp)
{
	BOOL  found       = 0;
	BOOL  status      = 0;
	int   count       = 0;

	QWORD table       = wmi::open_table("SELECT * FROM Win32_NetworkAdapter where PNPDeviceID is not NULL and MACAddress is not NULL");
	QWORD table_entry = wmi::next_entry(table, 0);
	while (table_entry)
	{
		std::string pnp_id = wmi::get_string(table_entry, "PNPDeviceID");
		BOOL enabled = wmi::get_bool(table_entry, "NetEnabled");
		if (enabled)
		{
			count++;
		}
		if (pnp_id.size() && !_strcmpi(pnp_id.c_str(), pnp.pnp_id.c_str()))
		{
			found  = 1;
			status = enabled;
		}
		table_entry = wmi::next_entry(table, table_entry);
	}
	wmi::close_table(table);

	if (found == 0)
	{
		LOG_DEBUG("[%d:%d:%d] no mac address found\n", pnp.bus,pnp.slot,pnp.func);
	}

	if (status == 0)
	{
		port.blk_info = 18;
		port.blk  = 1;
		return;
	}

	if (count > 1)
	{
		LOG_DEBUG("multiple network connections\n");
	}
}

static void validate_pnp_device(PORT_DEVICE_INFO &port, DEVICE_INFO &dev, PNP_ADAPTER &pnp)
{
	switch (dev.cfg.class_code())
	{
	//
	// validate network adapters
	//
	case 0x020000:
	case 0x028000:
		validate_network_adapters(port, pnp);
		break;
	//
	// XHCI
	//
	case 0x0C0330:
		// validate_usb_adapters(port, pnp);
		break;
	default:
		break;
	}
}

static void scan::check_features(PORT_DEVICE_INFO &port, std::vector<PNP_ADAPTER> &pnp_adapters)
{
	//
	// check if device is backed by driver
	//
	for (auto& dev : port.devices)
	{
		for (auto& pnp : pnp_adapters)
		{
			if (pnp.bus == dev.bus &&
				pnp.slot == dev.slot &&
				pnp.func == dev.func
				)
			{
				validate_pnp_device(port, dev, pnp);
				break;
			}
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
			PrintPcieConfiguration(dev.cfg.raw, *(DWORD*)(dev.cfg.raw + 0x100) ? 0x1000 : 0x100);
			filter_pci_cfg(dev.cfg);
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
	case 23: return "pcileech";
	case 24: return "card is not breathing";
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

static void scan::filter_pci_cfg(config::Pci &cfg)
{

	printf(
		"\n[General information]\n"
		"---------------------------------------------------------------------\n"
	);
	printf("CFG_VEND_ID | CFG_DEV_ID 			%04X %04X\n", cfg.vendor_id(), cfg.device_id());
	printf("CFG_SUBSYS_VEND_ID | CFG_SUBSYS_ID 		%04X %04X\n", cfg.subsystem_vendor_id(), cfg.subsystem_device_id());
	printf("CFG_REV_ID 					%ld\n", cfg.revision_id());
	printf("HEADER_TYPE 					0x%lx\n", cfg.header().raw);


	int bar_count = 6;
	if (cfg.header().multifunc_device())
	{
		bar_count = 2;
	}

	for (int i = 0; i < bar_count; i++)
		printf("BAR%d 						%lx\n", i, cfg.bar(i));
	

	printf("CLASS_CODE 					%06X\n", cfg.class_code());
	printf("CAPABILITIES_PTR               			0x%x\n", cfg.capabilities_ptr());
	printf("INTERRUPT_LINE                                  %lx\n", cfg.interrupt_line());
	printf("INTERRUPT_PIN                                   %lx\n", cfg.interrupt_pin());
	printf("---------------------------------------------------------------------\n");


	if (cfg.status().capabilities_list())
	{
		for (BYTE i = 0; i < config::MAX_CAPABILITIES; i++)
		{
			BOOL was_printed=0;

			if (0x01 == i)
			{
				auto pm = cfg.get_pm();
				printf(
					"\n[PM Cap]\n"
					"---------------------------------------------------------------------\n"
				);
				printf("PM_CAP_ON 					%d\n", pm.cap_on);
				printf("PM_CAP_BASEPTR                			0x%x\n", pm.base_ptr);
				printf("PM_CAP_NEXTPTR                			0x%x\n", pm.hdr.cap_next_ptr());
				printf("PM_CAP_ID 					%d\n", pm.hdr.cap_id());
				printf("PM_CAP_PME_CLOCK 				%d\n", pm.cap.pm_cap_pme_clock());
				printf("PM_CAP_DSI 					%d\n", pm.cap.pm_cap_dsi());
				printf("PM_CAP_AUXCURRENT 				%d\n", pm.cap.pm_cap_auxcurrent());
				printf("PM_CAP_D1SUPPORT PM_CAP_D2SUPPORT 		%d %d\n", pm.cap.pm_cap_d1support(), pm.cap.pm_cap_d2support());
				printf("PM_CAP_PMESUPPORT 				0x0%x\n", pm.cap.pm_cap_pmesupport());
				printf("PM_CAP_VERSION 					%ld\n", pm.cap.pm_cap_version());
				printf("---------------------------------------------------------------------\n");
				printf(
					"\n[PMCSR]\n"
					"---------------------------------------------------------------------\n"
				);
				printf("PM_CSR_NOSOFTRST 				%ld\n", pm.csr.pm_csr_nosoftrst());
				printf("PMCSR PWR STATE 				%ld\n", pm.csr.pm_csr_power_state());
				printf("PMCSR PMESTATUS 				%ld\n", pm.csr.pm_csr_pme_status());
				printf("PMCSR DATA SCALE 				%ld\n", pm.csr.pm_csr_data_scale());
				printf("PMCSR DATA SELECT 				%ld\n", pm.csr.pm_csr_pme_status());
				printf("PMCSR PME ENABLE 				%ld\n", pm.csr.pm_csr_pme_enabled());
				printf("PMCSR dynamic data 				%ld\n", pm.csr.pm_csr_dynamic_data());
				printf("---------------------------------------------------------------------\n");
				was_printed = 1;
			}
			else if (0x05 == i)
			{
				auto msi = cfg.get_msi();

				if (msi.cap_on)
				{

					printf(
						"\n[MSI CAP]\n"
						"---------------------------------------------------------------------\n"
					);
					printf("MSI_CAP_ON 					%d\n",     msi.cap_on);
					printf("MSI_BASE_PTR                    		0x%x\n",   msi.base_ptr);
					printf("MSI_CAP_NEXTPTR                 		0x%x\n",   msi.hdr.cap_next_ptr());
					printf("MSI_CAP_ID 					0x0%lx\n", msi.hdr.cap_id());
					printf("MSI_CAP_MULTIMSGCAP 				%ld\n",    msi.cap.msi_cap_multimsgcap());
					printf("MSI_CAP_MULTIMSG_EXTENSION 			%ld\n",    msi.cap.msi_cap_multimsg_extension());
					printf("MSI_CAP_64_BIT_ADDR_CAPABLE 			%ld\n",    msi.cap.msi_cap_64_bit_addr_capable());
					printf("MSI_CAP_PER_VECTOR_MASKING_CAPABLE 		%ld\n",    msi.cap.msi_cap_per_vector_masking_capable());
					printf("---------------------------------------------------------------------\n");

				}
				was_printed = 1;
			}
			else if (0x11 == i)
			{
				// msix
				auto msix = cfg.get_msix();

				if (msix.cap_on)
				{

					printf(
						"\n[MSIX CAP]\n"
						"---------------------------------------------------------------------\n"
					);
					printf("MSIX_CAP_ON 					%d\n",     msix.cap_on);
					printf("MSIX_CAP_BASEPTR                 		0x%x\n",   msix.base_ptr);
					printf("MSIX_CAP_NEXTPTR                 		0x%x\n",   msix.hdr.cap_next_ptr());
					printf("MSIX_CAP_ID 					0x0%lx\n", msix.hdr.cap_id());
					printf("MSIX_ENABLED        				%ld\n",    msix.cap.msix_enabled());
					printf("---------------------------------------------------------------------\n");

				}
				was_printed = 1;
			}
			else if (0x10 == i)
			{

				auto pcie = cfg.get_pci();

				if (pcie.cap_on)
				{

					printf(
						"\n[PE CAP]\n"
						"---------------------------------------------------------------------\n"
					);
					printf("PCIE_CAP_ON 					%d\n",    pcie.cap_on);
					printf("PCIE_CAP_BASEPTR               			0x%lx\n", pcie.base_ptr);
					printf("PCIE_CAP_NEXTPTR               			0x%lx\n", pcie.hdr.cap_next_ptr());
					printf("PCIE_CAP_CAPABILITY_ID               		0x%lx\n", pcie.hdr.cap_id());
					printf("PCIE_CAP_CAPABILITY_VERSION 			0x%lx\n", pcie.cap.pcie_cap_capability_version());
					printf("PCIE_CAP_DEVICE_PORT_TYPE 			0x%lx\n", pcie.cap.pcie_cap_device_port_type());
					printf("PCIE_CAP_SLOT_IMPLEMENTED  			0x%lx\n", pcie.cap.pcie_cap_slot_implemented());
					printf("---------------------------------------------------------------------\n");


	
					printf(
						"\n[PCI Express Device Capabilities]\n"
						"---------------------------------------------------------------------\n"
					);
					printf("DEV_CAP_MAX_PAYLOAD_SUPPORTED 			%d\n",  pcie.dev.cap.dev_cap_max_payload_supported());
					printf("DEV_CAP_PHANTOM_FUNCTIONS_SUPPORT 		%ld\n", pcie.dev.cap.dev_cap_phantom_functions_support());
					printf("DEV_CAP_EXT_TAG_SUPPORTED 			%ld\n", pcie.dev.cap.dev_cap_ext_tag_supported());
					printf("DEV_CAP_ENDPOINT_L0S_LATENCY 			%ld\n", pcie.dev.cap.dev_cap_endpoint_l0s_latency());
					printf("DEV_CAP_ENDPOINT_L1_LATENCY 			%ld\n", pcie.dev.cap.dev_cap_endpoint_l1_latency());
					printf("DEV_CAP_ROLE_BASED_ERROR 			%ld\n", pcie.dev.cap.dev_cap_role_based_error());
					printf("DEV_CAP_ENABLE_SLOT_PWR_LIMIT_VALUE 		%ld\n", pcie.dev.cap.dev_cap_enable_slot_pwr_limit_value() != 0);
					printf("DEV_CAP_ENABLE_SLOT_PWR_LIMIT_SCALE 		%ld\n", pcie.dev.cap.dev_cap_enable_slot_pwr_limit_scale());
					printf("DEV_CAP_FUNCTION_LEVEL_RESET_CAPABLE 		%ld\n", pcie.dev.cap.dev_cap_function_level_reset_capable());
					printf("---------------------------------------------------------------------\n");


					printf(
						"\n[Device Control]\n"
						"---------------------------------------------------------------------\n"
					);
					printf("Correctable Error Reporting Enable 		%ld\n", pcie.dev.control.dev_ctrl_corr_err_reporting());
					printf("Non-Fatal Error Reporting Enable 		%ld\n", pcie.dev.control.dev_ctrl_non_fatal_reporting());
					printf("Fatal Error Reporting Enable 			%ld\n", pcie.dev.control.dev_ctrl_fatal_err_reporting());
					printf("Unsupported Request Reporting Enable 		%ld\n", pcie.dev.control.dev_ctrl_ur_reporting());
					printf("Enable Relaxed Ordering 			%ld\n", pcie.dev.control.dev_ctrl_relaxed_ordering());
					printf("Max_Payload_Size 				%ld\n", pcie.dev.control.dev_ctrl_max_payload_size());
					printf("DEV_CONTROL_EXT_TAG_DEFAULT 			%ld\n", pcie.dev.control.dev_ctrl_ext_tag_default());
					printf("Phantom Functions Enable 			%ld\n", pcie.dev.control.dev_ctrl_phantom_func_enable());
					printf("Auxiliary Power PM Enable 			%ld\n", pcie.dev.control.dev_ctrl_aux_power_enable());
					printf("Enable No Snoop 				%ld\n", pcie.dev.control.dev_ctrl_enable_no_snoop());
					printf("Max_Read_Request_Size 				%ld\n", pcie.dev.control.dev_ctrl_max_read_request_size());
					printf("Configuration retry status enable 		%ld\n", pcie.dev.control.dev_ctrl_cfg_retry_status_enable());
					printf("---------------------------------------------------------------------\n");

					printf(
						"\n[PCI Express Link Capabilities]\n"
						"---------------------------------------------------------------------\n"
					);
					printf("LINK_CAP_MAX_LINK_SPEED 			%ld\n", pcie.link.cap.link_cap_max_link_speed());
					printf("LINK_CAP_MAX_LINK_WIDTH 			%ld\n", pcie.link.cap.link_cap_max_link_width());
					printf("LINK_CAP_ASPM_SUPPORT 				%d\n",  pcie.link.cap.link_cap_aspm_support());
					printf("LINK_CAP_L0S_EXIT_LATENCY 			%ld\n", pcie.link.cap.link_cap_l0s_exit_latency());
					printf("LINK_CAP_L1_EXIT_LATENCY 			%ld\n", pcie.link.cap.link_cap_l1_exit_latency());
					printf("LINK_CAP_CLOCK_POWER_MANAGEMENT 		%ld\n", pcie.link.cap.link_cap_clock_power_management());
					printf("LINK_CAP_ASPM_OPTIONALITY 			%ld\n", pcie.link.cap.link_cap_aspm_optionality());
					printf("LINK_CAP_RSVD_23 				%ld\n", pcie.link.cap.link_cap_rsvd_23());
					printf("---------------------------------------------------------------------\n");



					printf(
						"\n[Link Control]\n"
						"---------------------------------------------------------------------\n"
					);
					printf("LINK_CONTROL_RCB  				%ld\n", pcie.link.control.link_control_rcb());
					printf("---------------------------------------------------------------------\n");



					printf(
						"\n[Link Status]\n"
						"---------------------------------------------------------------------\n"
					);
					printf("LINK_STATUS_SLOT_CLOCK_CONFIG	 		%ld\n", pcie.link.status.link_status_slot_clock_config());
					printf("LINK_SPEED                   	 		%ld\n", pcie.link.status.link_status_link_speed());
					printf("LINK_WIDTH                   	 		%ld\n", pcie.link.status.link_status_link_width());
					printf("---------------------------------------------------------------------\n");

					if (pcie.cap.pcie_cap_capability_version() > 1)
					{

					printf(
						"\n[PCI Express Device Capabilities 2]\n"
						"---------------------------------------------------------------------\n"
					);
			
					printf("CPL_TIMEOUT_RANGES_SUPPORTED 			%ld\n", pcie.dev2.cap.cpl_timeout_disable_supported());
					printf("CPL_TIMEOUT_DISABLE_SUPPORTED 			%ld\n", pcie.dev2.cap.cpl_timeout_disable_supported());
					printf("---------------------------------------------------------------------\n");


					printf(
						"\n[Device Control 2]\n"
						"---------------------------------------------------------------------\n"
					);
					printf("Completion Timeout value 			%ld\n", pcie.dev2.control.completion_timeout_value());
					printf("Completion Timeout disable 			%ld\n", pcie.dev2.control.completion_timeout_disable());
					printf("---------------------------------------------------------------------\n");



					printf(
						"\n[PCI Express Link Capabilities 2]\n"
						"---------------------------------------------------------------------\n"
					);
			
					printf("Link speeds supported 				%ld\n", pcie.link2.cap.link_cap2_linkspeedssupported());
					printf("---------------------------------------------------------------------\n");



					printf(
						"\n[Link Control 2]\n"
						"---------------------------------------------------------------------\n"
					);
					printf("LINK_CTRL2_TARGET_LINK_SPEED 			%d\n",  pcie.link2.control.link_ctrl2_target_link_speed());
					printf("LINK_CTRL2_HW_AUTONOMOUS_SPEED_DISABLE 		%ld\n", pcie.link2.control.link_ctrl2_hw_autonomous_speed_disable());
					printf("LINK_CTRL2_DEEMPHASIS 				%ld\n", pcie.link2.control.link_ctrl2_deemphasis());
					printf("Enter Compliance 				%ld\n", pcie.link2.control.link_ctrl2_entercompliance());
					printf("Transmit Margin 				%ld\n", pcie.link2.control.link_ctrl2_transmitmargin());
					printf("Enter Modified Compliance 			%ld\n", pcie.link2.control.link_ctrl2_entermodifiedcompliance());
					printf("Compliance SOS 					%d\n",  pcie.link2.control.link_ctrl2_compliancesos());
					printf("---------------------------------------------------------------------\n");


					printf(
						"\n[Link Status 2]\n"
						"---------------------------------------------------------------------\n"
					);
					printf("Current De-emphasis Level 			%ld\n", pcie.link2.status.link_status2_deemphasislvl());
					printf("---------------------------------------------------------------------\n");
					}
				}
				was_printed = 1;
			}

			if (!was_printed)
			{
				auto empty = cfg.get_empty_cap(i);

				if (empty.cap_on)
				{
					printf(
						"\n[PCI Express Capability - 0x%lx]\n"
						"---------------------------------------------------------------------\n",
						i
					);
					printf("UNK_EXT_CAP_NEXTPTR 				0x%lx\n",  empty.hdr.cap_next_ptr());
					printf("UNK_EXT_CAP_ON 					%ld\n",    empty.cap_on);
					printf("UNK_EXT_CAP_ID 					0x0%lx\n", empty.hdr.cap_id());
					printf("---------------------------------------------------------------------\n");
				}
			}
		}
	}

	for (BYTE i = 0; i < 0x2F; i++)
	{
		auto empty = cfg.get_empty_extended_cap(i);
		if (!empty.cap_on)
			continue;


		if (i == 0x03) // dsn
		{
			auto dsn = cfg.get_dsn();
			printf(
				"\n[PCI DSN Capability - 0x%lx]\n"
				"---------------------------------------------------------------------\n",
				i
			);
			printf("DSN_CAP_NEXTPTR 				0x%lx\n",  dsn.hdr.cap_next_ptr());
			printf("DSN_CAP_ON 					%ld\n",    dsn.cap_on);
			printf("DSN_CAP_ID 					0x0%lx\n", dsn.hdr.cap_id());
			printf("DSN        					0x0%llx\n", dsn.serial);
			printf("---------------------------------------------------------------------\n");

			continue;
		}

		printf(
			"\n[PCI Express Extended Capability - 0x%lx]\n"
			"---------------------------------------------------------------------\n",
			i
		);
		printf("UNK_EXT_CAP_NEXTPTR 				0x%lx\n",  empty.hdr.cap_next_ptr());
		printf("UNK_EXT_CAP_ON 					%ld\n",    empty.cap_on);
		printf("UNK_EXT_CAP_ID 					0x0%lx\n", empty.hdr.cap_id());
		printf("---------------------------------------------------------------------\n");
	}
}

typedef struct {
	DEVICE_INFO data;
	DWORD       device_class;
} RAW_PCIENUM_OBJECT;	

std::vector<RAW_PCIENUM_OBJECT> get_raw_pci_objects()
{
	std::vector<RAW_PCIENUM_OBJECT> objects{};

	using namespace cl;

	//
	// add device objects
	//
	QWORD pci = cl::get_pci_driver_object();
	QWORD pci_dev = vm::read<QWORD>(4, pci + 0x08);
	while (pci_dev)
	{
		QWORD pci_ext = vm::read<QWORD>(4, pci_dev + 0x40);
		if (pci_ext && vm::read<DWORD>(4, pci_ext) == 0x44696350)
		{
			DWORD device_class = cl::get_pci_class_id(pci_ext);

			BYTE bus,slot,func;
			get_pci_location(pci_ext, &bus, &slot, &func);

			QWORD attached_device = cl::vm::read<QWORD>(4, pci_dev + 0x18);
			QWORD device_object = 0;
			while (attached_device)
			{
				device_object = attached_device;
				attached_device = cl::vm::read<QWORD>(4, attached_device + 0x18);
			}

			RAW_PCIENUM_OBJECT object{};
			object.data.bus  = bus;
			object.data.slot = slot;
			object.data.func = func;
			object.data.pci_device_object = pci_dev;
			object.data.drv_device_object = device_object;
			object.device_class = device_class;
			objects.push_back(object);
		}
		pci_dev = vm::read<QWORD>(4, pci_dev + 0x10);
	}
	return objects;
}

std::vector<DEVICE_INFO> get_devices_by_bus(std::vector<RAW_PCIENUM_OBJECT>& pci_devices, BYTE bus)
{
	std::vector<DEVICE_INFO> objects{};
	for (auto& dev : pci_devices) if (dev.data.bus == bus) objects.push_back(dev.data);
	return objects;
}

static void pci_initialize_cfg(DEVICE_INFO &dev)
{
	memset(dev.cfg.raw, 0, sizeof(dev.cfg.raw));

	//
	// legacy (0x00 - 0x100)
	//
	cl::pci::read(dev.bus, dev.slot, dev.func, 0, dev.cfg.raw, 0x100);

	//
	// optimized extended (0x100 - 0x1000)
	//
	WORD optimize_ptr = 0x100;
	WORD max_size     = sizeof(dev.cfg.raw);
	for (WORD i = 0x100; i < max_size; i += 4)
	{
		cl::pci::read(dev.bus, dev.slot, dev.func, i, (PVOID)(dev.cfg.raw + i), 4);
		if (i >= optimize_ptr)
		{
			optimize_ptr = GET_BITS(*(DWORD*)((PBYTE)dev.cfg.raw + optimize_ptr), 31, 20);
			if (!optimize_ptr)
			{
				optimize_ptr = 0x1000;   // disable
				max_size     = i + 0x30; // max data left 0x30

				if (max_size > sizeof(dev.cfg.raw))
				{
					max_size = sizeof(dev.cfg.raw);
				}
			}
		}
	}
}

std::vector<PORT_DEVICE_INFO> scan::get_port_devices(void)
{
	using namespace cl;

	auto pci_devices = get_raw_pci_objects();

	std::vector<PORT_DEVICE_INFO> objects{};

	using namespace cl;

	for (auto &devf : pci_devices)
	{
		auto &dev = devf.data;
		if (devf.device_class != 0x00060400)
		{
			continue;
		}

		DWORD businfo = pci::read<DWORD>(dev.bus, dev.slot, dev.func, 0x18);
		BYTE  bus = ((BYTE*)&businfo)[0];
		BYTE  secondary_bus = ((BYTE*)&businfo)[1];
		BYTE  subordinate_bus = ((BYTE*)&businfo)[2];
		if (dev.bus != bus || dev.bus >= secondary_bus || dev.bus >= subordinate_bus)
			continue;

		BOOL endpoint_port = 0;
		if (secondary_bus == subordinate_bus)
		{
			endpoint_port = 1;
		}

		else if ((secondary_bus + 1) == subordinate_bus)
		{
			if (get_devices_by_bus(pci_devices, subordinate_bus).size() == 0)
			{
				endpoint_port = 1;
			}
		}

		if (!endpoint_port)
		{
			continue;
		}

		PORT_DEVICE_INFO object{};
		object.self    = dev;
		object.devices = get_devices_by_bus(pci_devices, secondary_bus);

		//
		// option 1 BEGIN
		//
		/*
		BOOL is_empty = 0;
		if (object.devices.size() == 0 && pci::read<WORD>(dev.bus, dev.slot, dev.func, 0x04) == 0x404)
		{
			is_empty = 1;
		}

		if (!is_empty)
		{
			objects.push_back(object);
		}
		*/
		//
		// option 1 END
		//
		
		//
		// option 2 BEGIN
		//
		if (object.devices.size() == 0)
		{
			DWORD fixup = pci::read<DWORD>(secondary_bus, 0, 0, 0x04);
			if (fixup != 0 && fixup != 0xffffffff)
			{
				DEVICE_INFO pciobj{};
				pciobj.bus = secondary_bus;
				object.devices.push_back(pciobj);
			}
		}
		objects.push_back(object);
		//
		// option 2 END
		//
	}

	std::vector<PORT_DEVICE_INFO> physical_devices{};
	for (auto &obj : objects)
	{
		pci_initialize_cfg(obj.self);

		//
		// skip non physical ports
		//
		if (obj.self.cfg.get_pci().slot.cap.raw == 0)
		{
			continue;
		}

		//
		// optional: skip non xilinx devices
		//
		if (obj.self.cfg.get_pci().link.status.link_status_link_width() > 4)
		{
			continue;
		}

		for (auto &dev : obj.devices)
		{
			//
			// no driver object, optimize
			//
			if (!dev.drv_device_object)
			{
				memset(dev.cfg.raw, 0, sizeof(dev.cfg.raw));
				*(DWORD*)dev.cfg.raw = cl::pci::read<DWORD>(dev.bus, dev.slot, dev.func, 0);
				continue;
			}
			pci_initialize_cfg(dev);
		}

		physical_devices.push_back(obj);
	}

	return physical_devices;
}

BOOL scan::get_isr_stats(DEVICE_INFO& dev, ISRDPCSTATS* out)
{
	using namespace cl;

	if (!dev.pci_device_object)
		return 0;

	QWORD extension = vm::read<QWORD>(4, dev.pci_device_object + 0x138);
	if (vm::read<QWORD>(4, extension + 0x60) == 0) // interrupt count: 0
	{
		if (vm::read<QWORD>(4, extension + 0x58) != 0) // catch if not compatible driver installed
			return 1;
		return 0;
	}

	QWORD interrupt_context = vm::read<QWORD>(4, extension + 0x58);
	if (!interrupt_context)
		return 0;

	QWORD kinterrupt = get_interrupt_object(vm::read<DWORD>(4, interrupt_context + 0x10));
	if (!kinterrupt)
		return 0;

	BOOL  connected = 0;
	QWORD interrupt_item = kinterrupt + 0x08;
	QWORD list_entry = interrupt_item;

	while (1)
	{
		kinterrupt = (interrupt_item - 0x08);

		if (!connected)
		{
			connected = vm::read<UCHAR>(4, kinterrupt + 0x5F) == 1;
		}

		ISRDPCSTATS stats{};
		vm::read(4, kinterrupt + 0xB0, &stats, sizeof(stats));

		out->IsrCount += stats.IsrCount;

		interrupt_item = vm::read<QWORD>(4, interrupt_item);
		if (interrupt_item == 0 || interrupt_item == list_entry)
		{
			break;
		}
	}
	return connected;
}

