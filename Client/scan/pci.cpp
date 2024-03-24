#include "scan.h"

namespace scan
{
	static void dumpcfg(std::vector<PORT_DEVICE_INFO> &devices);
	static void dumpbar(std::vector<PORT_DEVICE_INFO> &devices);

	static void check_config(PORT_DEVICE_INFO &port);
	static void check_features(PORT_DEVICE_INFO &port, std::vector<PNP_ADAPTER> &pnp_adapters);
	static void check_shadowcfg(PORT_DEVICE_INFO &port);

	static void PrintPcieInfo(PORT_DEVICE_INFO& port);
	static void PrintPcieConfiguration(unsigned char *cfg, int size);
	static void PrintPcieBarSpace(DWORD bar);
	static void PrintPcieCfg(unsigned char *cfg);

	static void validate_pnp_device(PORT_DEVICE_INFO &port, DEVICE_INFO &dev, PNP_ADAPTER &pnp);
	static void validate_usb_adapters(PORT_DEVICE_INFO &port, PNP_ADAPTER &pnp);
	static void validate_network_adapters(PORT_DEVICE_INFO &port, PNP_ADAPTER &pnp);
}

void scan::pci(BOOL disable, BOOL advanced, BOOL dump_cfg, BOOL dump_bar)
{
	using namespace pci;

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

	std::vector<PNP_ADAPTER> pnp_adapters;
	if (advanced)
	{
		pnp_adapters = get_pnp_adapters();
	}

	//
	// check device config
	//
	for (auto &port : port_devices) if (!port.blk) check_config(port);

	//
	// check device features
	//
	if (advanced)
		for (auto &port : port_devices) if (!port.blk) check_features(port, pnp_adapters);

	//
	// check shadow cfg
	//
	for (auto &port : port_devices) if (!port.blk) check_shadowcfg(port);



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
			WORD command = pci::command(port.self.cfg);
			if (GET_BIT(command, 2))
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

			WORD command = pci::command(port.self.cfg);
			if (GET_BIT(command, 2))
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

void scan::check_config(PORT_DEVICE_INFO &port)
{
	using namespace pci;

	BOOL bme_enabled = 0;

	for (auto &dev : port.devices)
	{
		//
		// check that the device has a pointer to the capabilities list (status register bit 4 set to 1)
		//
		if (GET_BIT(status(dev.cfg), 4))
		{
			PVOID pcie = get_pcie(dev.cfg);
			if (pcie != 0)
			{
				//
				// end point device never should be bridge/port
				//
				if (pcie::cap::pcie_cap_device_port_type(pcie) >= PciExpressRootPort)
				{
					port.blk = 2; port.blk_info = 14;
					break;
				}

				//
				// compare data between device data and port
				//
				if (link::status::link_speed(get_link(dev.cfg)) > link::status::link_speed(get_link(port.self.cfg)))
				{
					port.blk = 2; port.blk_info = 15;
					break;
				}

				if (link::status::link_width(get_link(dev.cfg)) > link::status::link_width(get_link(port.self.cfg)))
				{
					port.blk = 2; port.blk_info = 15;
					break;
				}

			}

			//
			// device reports to have capabilities, lets see if we got actually any
			//
			BOOL found = 0;
			for (BYTE i = 0; i < 0x16; i++)
			{
				PVOID cap = get_capability_by_id(dev.cfg, i);
				if (cap == 0)
					continue;

				if (*(DWORD*)cap)
				{
					found = 1;
					break;
				}
			}

			if (!found)
			{
				port.blk = 2; port.blk_info = 6;
				return;
			}
		}

		if (GET_BIT(pci::command(dev.cfg), 2))
		{
			//
			// some device has bus master enabled
			//
			bme_enabled = 1;
		}

		//
		// can be just used to identify xilinx FPGA
		//
		if (is_xilinx(dev.cfg))
		{
			port.blk = 0; port.blk_info = 3;
		}

		if (vendor_id(dev.cfg) == 0x10EE)
		{
			port.blk = 1; port.blk_info = 3;
			break;
		}


		//
		// hidden device, LUL.
		//
		if (device_id(dev.cfg) == 0xFFFF && vendor_id(dev.cfg) == 0xFFFF)
		{
			port.blk  = 2; port.blk_info = 5;
			break;
		}


		//
		// invalid VID/PID
		//
		if (device_id(dev.cfg) == 0x0000 && vendor_id(dev.cfg) == 0x0000)
		{
			port.blk  = 2; port.blk_info = 5;
			break;
		}

		//
		// 1432
		// Header Type: bit 7 (0x80) indicates whether it is a multi-function device,
		// while interesting values of the remaining bits are: 00 = general device, 01 = PCI-to-PCI bridge.
		// src: https://www.khoury.northeastern.edu/~pjd/cs7680/homework/pci-enumeration.html
		//
		if (GET_BIT(header_type(dev.cfg), 7))
		{
			//
			// check if we have any children devices
			//
			if (port.devices.size() < 2)
			{
				port.blk = 2; port.blk_info = 9;
				break;
			}
		}

		if (GET_BITS(header_type(dev.cfg), 6, 0) == 1)
		{
		//
		// Header Type 1 Configuration Space Header is used for Root Port and Upstream Port/Downstream Port of PCIe Switch.
		//
		}
		else if (GET_BITS(header_type(dev.cfg), 6, 0) == 2)
		{
		//
		// Header Type 2 Configuration Space header is used for cardbus bridges
		//
		}
		else if (GET_BITS(header_type(dev.cfg), 6, 0) == 0)
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
			break;
		}
	}

	//
	// not any device has bus master enabled
	// we can safely block the port
	//
	if (bme_enabled == 0 && port.blk == 0)
	{
		port.blk = 1; port.blk_info = 2;
		return;
	}

	for (auto &dev : port.devices)
	for (BYTE i = 0; i < 0x16; i++)
	{
		PVOID cap = get_capability_by_id(dev.cfg, i);

		if (!cap)
			continue;

		if (*(DWORD*)(cap) == 0)
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
	for (WORD i = 0; i < 0x2F; i++)
	{
		PVOID ext_cap = get_ext_capability_by_id(dev.cfg, i);

		if (!ext_cap)
			continue;

		if (*(DWORD*)(ext_cap) == 0)
		{
			//
			// device reports to have next cap, but it's empty (???)
			// i don't have enough data to confirm if this is possible
			//
			port.blk_info = 8;
			port.blk = 2;
			return;
		}
	}
}

static void scan::check_features(PORT_DEVICE_INFO &port, std::vector<PNP_ADAPTER> &pnp_adapters)
{
	using namespace pci;

	//
	// check if device is backed by driver
	//

	BOOL found = 0;
	for (auto& dev : port.devices)
	{
		for (auto& pnp : pnp_adapters)
		{
			if (pnp.bus == dev.bus &&
				pnp.slot == dev.slot &&
				pnp.func == dev.func
				)
			{
				found = 1;
				validate_pnp_device(port, dev, pnp);
				break;
			}
		}
	}

	if (!found)
	{
		for (auto& dev : port.devices)
		{
			//
			// bus master was forcefully enabled(?)
			//
			if (GET_BIT(command(dev.cfg), 2))
			{
				port.blk = 2;
				port.blk_info = 19;
				break;
			}
			else
			{
				port.blk = 1;
				port.blk_info = 16;
				break;
			}
		}
	}
}

static void scan::check_shadowcfg(PORT_DEVICE_INFO &port)
{
	//
	// test shadow cfg (pcileech-fpga 4.11 and lower)
	//
	for (auto& dev : port.devices)
	{
		DWORD tick = GetTickCount();
		cl::pci::write<WORD>(dev.bus, dev.slot, 0xA0, *(WORD*)(dev.cfg + 0xA0));
		tick = GetTickCount() - tick;
		if (tick > 100)
			continue;

		tick = GetTickCount();
		cl::pci::write<WORD>(dev.bus, dev.slot, 0xA8, *(WORD*)(dev.cfg + 0xA8));
		tick = GetTickCount() - tick;
		if (tick > 100)
		{
			port.blk = 2;
			port.blk_info = 1;
			break;
		}
	}
}

static void scan::dumpcfg(std::vector<PORT_DEVICE_INFO> &devices)
{
	for (auto& entry : devices)
	{
		for (auto& dev : entry.devices)
		{
			printf("[%d:%d:%d] [%02X:%02X]", dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02));
			PrintPcieConfiguration(dev.cfg, sizeof(dev.cfg));
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
		if (!GET_BIT(*(WORD*)(dev.cfg + 0x04), 2))
		{
			continue;
		}

		DWORD cnt = 6;
		if (GET_BITS(pci::header_type(dev.cfg), 6, 0) == 1)
		{
			cnt = 2;
		}

		DWORD* bar = (DWORD*)(dev.cfg + 0x10);
		for (DWORD i = 0; i < cnt; i++)
		{
			if (bar[i] > 0x10000000)
			{
				printf("[%d:%d:%d] [%02X:%02X]\n",
					dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg), *(WORD*)(dev.cfg + 0x02));
				PrintPcieBarSpace(bar[i]);
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
	case 4:  return "invalid bridge";
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
	}
	return "OK";
}

inline DWORD get_port_type(unsigned char *cfg)
{
	PVOID pcie = pci::get_pcie(cfg);
	if (pcie == 0)
	{
		return 0;
	}
	return pci::pcie::cap::pcie_cap_device_port_type(pcie);
}

inline PCSTR get_port_type_str(unsigned char *cfg)
{
	switch (get_port_type(cfg))
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
		pci::vendor_id(port.self.cfg), pci::device_id(port.self.cfg), blkinfo(port.blk_info));

	//
	// print device PCIe device information
	//
	for (auto &dev : port.devices)
	{
		printf("	[%s] [%02d:%02d:%02d] [%04X:%04X]\n",
			get_port_type_str(dev.cfg), dev.bus, dev.slot, dev.func, pci::vendor_id(dev.cfg), pci::device_id(dev.cfg));
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

static void scan::PrintPcieCfg(unsigned char *cfg)
{
	using namespace pci;

	printf(
		"\n[General information]\n"
		"---------------------------------------------------------------------\n"
	);
	printf("CFG_VEND_ID | CFG_DEV_ID 			%04X %04X\n", vendor_id(cfg), device_id(cfg));
	printf("CFG_SUBSYS_VEND_ID | CFG_SUBSYS_ID 		%04X %04X\n", subsys_vendor_id(cfg), subsys_id(cfg));
	printf("CFG_REV_ID 					%ld\n", revision_id(cfg));
	printf("HEADER_TYPE 					0x%lx\n", header_type(cfg));
	printf("BAR0 						%lx\n", bar(cfg)[0]);
	printf("CLASS_CODE 					%06X\n", class_code(cfg));
	printf("CAPABILITIES_PTR | PM_BASE_PTR 			0x%x\n", capabilities_ptr(cfg));
	printf("INTERRUPT_LINE                                  %lx\n", interrupt_line(cfg));
	printf("INTERRUPT_PIN                                   %lx\n", interrupt_pin(cfg));
	printf("---------------------------------------------------------------------\n");

	PVOID pm = get_pm(cfg);

	if (pm != 0)
	{	
		printf(
			"\n[PM Cap]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("PM_CAP_ON 					%d\n", pm::cap::pm_cap_on(pm));
		printf("PM_CAP_NEXTPTR | MSI_BASE_PTR 			0x%x\n", pm::cap::pm_cap_next_ptr(pm));
		printf("PM_CAP_ID 					%d\n",pm::cap::pm_cap_id(pm));
		printf("PM_CAP_PME_CLOCK 				%d\n", pm::cap::pm_cap_pme_clock(pm));
		printf("PM_CAP_DSI 					%d\n", pm::cap::pm_cap_dsi(pm));
		printf("PM_CAP_AUXCURRENT 				%d\n", pm::cap::pm_cap_auxcurrent(pm));
		printf("PM_CAP_D1SUPPORT PM_CAP_D2SUPPORT 		%d %d\n", pm::cap::pm_cap_d1support(pm), pm::cap::pm_cap_d2support(pm));
		printf("PM_CAP_PMESUPPORT 				0x0%x\n", pm::cap::pm_cap_pmesupport(pm));
		printf("PM_CAP_RSVD_04 					%ld\n", pm::cap::pm_cap_rsvd_04(pm));
		printf("PM_CAP_VERSION 					%ld\n", pm::cap::pm_cap_version(pm));
		printf("---------------------------------------------------------------------\n");

		printf(
			"\n[PMCSR]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("PM_CSR_NOSOFTRST 				%ld\n", pm::csr::pm_csr_nosoftrst(pm));
		printf("PM_CSR_BPCCEN    				%ld\n", pm::csr::pm_csr_bpccen(pm));
		printf("PM_CSR_B2B3S     				%ld\n", pm::csr::pm_csr_b2b3s(pm));
		printf("PMCSR PWR STATE 				%ld\n", pm::csr::pm_csr_power_state(pm));
		printf("PMCSR PMESTATUS 				%ld\n", pm::csr::pm_csr_pme_status(pm));
		printf("PMCSR DATA SCALE 				%ld\n", pm::csr::pm_csr_data_scale(pm));
		printf("PMCSR DATA SELECT 				%ld\n", pm::csr::pm_csr_pme_status(pm));
		printf("PMCSR PME ENABLE 				%ld\n", pm::csr::pm_csr_pme_enabled(pm));
		printf("PMCSR reserved 					%ld\n", pm::csr::pm_csr_reserved(pm));
		printf("PMCSR dynamic data 				%ld\n", pm::csr::pm_csr_dynamic_data(pm));
		printf("---------------------------------------------------------------------\n");
	}
	PVOID msi = get_msi(cfg);

	if (msi != 0)
	{
		printf(
			"\n[MSI CAP]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("MSI_CAP_ON 					%d\n", msi::cap::msi_cap_on(msi));
		printf("MSI_CAP_NEXTPTR | PCIE_BASE_PTR 		0x%x\n", msi::cap::msi_cap_nextptr(msi));
		printf("MSI_CAP_ID 					0x0%lx\n", msi::cap::msi_cap_id(msi));
		printf("MSI_CAP_MULTIMSGCAP 				%ld\n", msi::cap::msi_cap_multimsgcap(msi));
		printf("MSI_CAP_MULTIMSG_EXTENSION 			%ld\n", msi::cap::msi_cap_multimsg_extension(msi));
		printf("MSI_CAP_64_BIT_ADDR_CAPABLE 			%ld\n", msi::cap::msi_cap_64_bit_addr_capable(msi));
		printf("MSI_CAP_PER_VECTOR_MASKING_CAPABLE 		%ld\n", msi::cap::msi_cap_per_vector_masking_capable(msi));
		printf("---------------------------------------------------------------------\n");
	}
	PVOID pcie = get_pcie(cfg);

	if (pcie != 0)
	{
		printf(
			"\n[PE CAP]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("PCIE_CAP_ON 					%d\n", pcie::cap::pcie_cap_on(pcie));
		printf("PCIE_CAP_NEXTPTR               			0x%lx\n", pcie::cap::pcie_cap_nextptr(pcie));
		printf("PCIE_CAP_CAPABILITY_ID               		0x%lx\n", pcie::cap::pcie_cap_capability_id(pcie));
		printf("PCIE_CAP_CAPABILITY_VERSION 			0x%lx\n", pcie::cap::pcie_cap_capability_version(pcie));
		printf("PCIE_CAP_DEVICE_PORT_TYPE 			0x%lx\n", pcie::cap::pcie_cap_device_port_type(pcie));
		printf("PCIE_CAP_SLOT_IMPLEMENTED  			0x%lx\n", pcie::cap::pcie_cap_slot_implemented(pcie));
		printf("---------------------------------------------------------------------\n");

		PVOID dev = get_dev(cfg);

	
		printf(
			"\n[PCI Express Device Capabilities]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("DEV_CAP_MAX_PAYLOAD_SUPPORTED 			%d\n", dev::cap::dev_cap_max_payload_supported(dev));
		printf("DEV_CAP_PHANTOM_FUNCTIONS_SUPPORT 		%ld\n", dev::cap::dev_cap_phantom_functions_support(dev));
		printf("DEV_CAP_EXT_TAG_SUPPORTED 			%ld\n", dev::cap::dev_cap_ext_tag_supported(dev));
		printf("DEV_CAP_ENDPOINT_L0S_LATENCY 			%ld\n", dev::cap::dev_cap_endpoint_l0s_latency(dev));
		printf("DEV_CAP_ENDPOINT_L1_LATENCY 			%ld\n", dev::cap::dev_cap_endpoint_l1_latency(dev));
		printf("DEV_CAP_ROLE_BASED_ERROR 			%ld\n", dev::cap::dev_cap_role_based_error(dev));
		printf("DEV_CAP_ENABLE_SLOT_PWR_LIMIT_VALUE 		%ld\n", dev::cap::dev_cap_enable_slot_pwr_limit_value(dev));
		printf("DEV_CAP_ENABLE_SLOT_PWR_LIMIT_SCALE 		%ld\n", dev::cap::dev_cap_enable_slot_pwr_limit_scale(dev));
		printf("DEV_CAP_FUNCTION_LEVEL_RESET_CAPABLE 		%ld\n", dev::cap::dev_cap_function_level_reset_capable(dev));
		printf("---------------------------------------------------------------------\n");


		printf(
			"\n[Device Control]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("Correctable Error Reporting Enable 		%ld\n", dev::ctrl::dev_ctrl_corr_err_reporting(dev));
		printf("Non-Fatal Error Reporting Enable 		%ld\n", dev::ctrl::dev_ctrl_non_fatal_reporting(dev));
		printf("Fatal Error Reporting Enable 			%ld\n", dev::ctrl::dev_ctrl_fatal_err_reporting(dev));
		printf("Unsupported Request Reporting Enable 		%ld\n", dev::ctrl::dev_ctrl_ur_reporting(dev));
		printf("Enable Relaxed Ordering 			%ld\n", dev::ctrl::dev_ctrl_relaxed_ordering(dev));
		printf("Max_Payload_Size 				%ld\n", dev::ctrl::dev_ctrl_max_payload_size(dev));
		printf("DEV_CONTROL_EXT_TAG_DEFAULT 			%ld\n", dev::ctrl::dev_ctrl_ext_tag_default(dev));
		printf("Phantom Functions Enable 			%ld\n", dev::ctrl::dev_ctrl_phantom_func_enable(dev));
		printf("Auxiliary Power PM Enable 			%ld\n", dev::ctrl::dev_ctrl_aux_power_enable(dev));
		printf("Enable No Snoop 				%ld\n", dev::ctrl::dev_ctrl_enable_no_snoop(dev));
		printf("Max_Read_Request_Size 				%ld\n", dev::ctrl::dev_ctrl_max_read_request_size(dev));
		printf("Configuration retry status enable 		%ld\n", dev::ctrl::dev_ctrl_cfg_retry_status_enable(dev));
		printf("---------------------------------------------------------------------\n");
		
		PVOID link = get_link(cfg);

		printf(
			"\n[PCI Express Link Capabilities]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("LINK_CAP_MAX_LINK_SPEED 			%ld\n", link::cap::link_cap_max_link_speed(link));
		printf("LINK_CAP_MAX_LINK_WIDTH 			%ld\n", link::cap::link_cap_max_link_width(link));
		printf("LINK_CAP_ASPM_SUPPORT 				%d\n",  link::cap::link_cap_aspm_support(link));
		printf("LINK_CAP_L0S_EXIT_LATENCY 			%ld\n", link::cap::link_cap_l0s_exit_latency(link));
		printf("LINK_CAP_L1_EXIT_LATENCY 			%ld\n", link::cap::link_cap_l1_exit_latency(link));
		printf("LINK_CAP_CLOCK_POWER_MANAGEMENT 		%ld\n", link::cap::link_cap_clock_power_management(link));
		printf("LINK_CAP_ASPM_OPTIONALITY 			%ld\n", link::cap::link_cap_aspm_optionality(link));
		printf("LINK_CAP_RSVD_23 				%ld\n", link::cap::link_cap_rsvd_23(link));
		printf("---------------------------------------------------------------------\n");



		printf(
			"\n[Link Control]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("LINK_CONTROL_RCB  				%ld\n", link::ctrl::link_control_rcb(link));
		printf("---------------------------------------------------------------------\n");



		printf(
			"\n[Link Status]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("LINK_STATUS_SLOT_CLOCK_CONFIG	 		%ld\n", link::status::link_status_slot_clock_config(link));
		printf("---------------------------------------------------------------------\n");


		printf(
			"\n[PCI Express Device Capabilities 2]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("CPL_TIMEOUT_RANGES_SUPPORTED 			%ld\n", dev::cap2::cpl_timeout_disable_supported(dev));
		printf("CPL_TIMEOUT_DISABLE_SUPPORTED 			%ld\n", dev::cap2::cpl_timeout_disable_supported(dev));
		printf("---------------------------------------------------------------------\n");


		printf(
			"\n[Device Control 2]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("Completion Timeout value 			%ld\n", dev::ctrl2::completiontimeoutvalue(dev));
		printf("Completion Timeout disable 			%ld\n", dev::ctrl2::completiontimeoutdisable(dev));
		printf("---------------------------------------------------------------------\n");



		printf(
			"\n[PCI Express Link Capabilities 2]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("Link speeds supported 				%ld\n", link::cap2::linkspeedssupported(link));
		printf("---------------------------------------------------------------------\n");



		printf(
			"\n[Link Control 2]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("LINK_CTRL2_TARGET_LINK_SPEED 			%d\n",  link::ctrl2::link_ctrl2_target_link_speed(link));
		printf("LINK_CTRL2_HW_AUTONOMOUS_SPEED_DISABLE 		%ld\n", link::ctrl2::link_ctrl2_hw_autonomous_speed_disable(link));
		printf("LINK_CTRL2_DEEMPHASIS 				%ld\n", link::ctrl2::link_ctrl2_deemphasis(link));
		printf("Enter Compliance 				%ld\n", link::ctrl2::entercompliance(link));
		printf("Transmit Margin 				%ld\n", link::ctrl2::transmitmargin(link));
		printf("Enter Modified Compliance 			%ld\n", link::ctrl2::entermodifiedcompliance(link));
		printf("Compliance SOS 					%d\n",  link::ctrl2::compliancesos(link));
		printf("---------------------------------------------------------------------\n");


		printf(
			"\n[Link Status 2]\n"
			"---------------------------------------------------------------------\n"
		);
		printf("Compliance Preset/De-emphasis 			%ld\n", link::status2::deemphasis(link));
		printf("Current De-emphasis Level 			%ld\n", link::status2::deemphasislvl(link));
		printf("Equalization Complete 				%ld\n", link::status2::equalizationcomplete(link));
		printf("Equalization Phase 1 Successful 		%ld\n", link::status2::equalizationphase1successful(link));
		printf("Equalization Phase 2 Successful 		%ld\n", link::status2::equalizationphase2successful(link));
		printf("Equalization Phase 3 Successful 		%ld\n", link::status2::equalizationphase3successful(link));
		printf("Link Equalization Request 			%ld\n", link::status2::linkequalizationrequest(link));
		printf("---------------------------------------------------------------------\n");
	}

	for (WORD i = 0; i < 0x2F; i++)
	{
		PVOID ext_cap = get_ext_capability_by_id(cfg, i);

		if (ext_cap == 0)
			continue;

		//
		// extended capabilities
		//
		if (i == 0x03) // DSN
		{
			printf(
				"\n[PCI Express Extended Capability - DSN]\n"
				"---------------------------------------------------------------------\n"
			);
			printf("DSN_BASE_PTR    				0x%lx\n", (DWORD)((PBYTE)ext_cap - cfg));
			printf("DSN_CAP_NEXTPTR 				0x%lx\n", dsn::dsn_cap_nextptr(ext_cap));
			printf("DSN_CAP_ON 					%ld\n", dsn::dsn_cap_on(ext_cap));
			printf("DSN 1st						%lX\n", *(DWORD*)((PBYTE)ext_cap + sizeof(DWORD)));
			printf("DSN 2nd						%lX\n", *(DWORD*)((PBYTE)ext_cap + sizeof(QWORD)));
			printf("---------------------------------------------------------------------\n");
		}
		else
		{
			std::string cap_name = "CAP_" + std::to_string(i);

			std::string title =
				"\n[PCI Express Extended Capability - " + 
				cap_name +
				"]\n"
				"---------------------------------------------------------------------\n";
			printf(title.c_str());
			std::string tmp = cap_name + "_BASE_PTR   				0x%lx\n";
			printf(tmp.c_str(), (DWORD)((PBYTE)ext_cap - cfg));
			tmp = cap_name + "_CAP_NEXTPTR				0x%lx\n";
			printf(tmp.c_str(), dsn::dsn_cap_nextptr(ext_cap));
			tmp = cap_name + "_CAP_ON     				%ld\n";
			printf(tmp.c_str(), dsn::dsn_cap_on(ext_cap));
			printf("---------------------------------------------------------------------\n");
		}
	}
}

static void scan::validate_network_adapters(PORT_DEVICE_INFO &port, PNP_ADAPTER &pnp)
{
	using namespace pci;

	BOOL  found       = 0;
	BOOL  status      = 0;

	QWORD table       = wmi::open_table("SELECT * FROM Win32_NetworkAdapter where PNPDeviceID is not NULL and MACAddress is not NULL");
	QWORD table_entry = wmi::next_entry(table, 0);
	while (table_entry)
	{
		std::string pnp_id = wmi::get_string(table_entry, "PNPDeviceID");
		if (pnp_id.size() && !_strcmpi(pnp_id.c_str(), pnp.pnp_id.c_str()))
		{
			found  = 1;
			status = wmi::get_bool(table_entry, "NetEnabled");
			break;
		}
		table_entry = wmi::next_entry(table, table_entry);
	}
	wmi::close_table(table);


	if (found == 0)
	{
		//
		// sus
		//
		port.blk_info = 17;
		port.blk  = 2;
		return;
	}

	if (status == 0)
	{
		port.blk_info = 18;
		port.blk  = 1;
		return;
	}
}

static void scan::validate_usb_adapters(PORT_DEVICE_INFO &port, PNP_ADAPTER &pnp)
{
	using namespace pci;

	BOOL  found = 0;
	QWORD table = wmi::open_table("SELECT DeviceID FROM Win32_USBController where DeviceID is not NULL");
	QWORD table_entry = wmi::next_entry(table, 0);
	while (table_entry)
	{
		std::string DeviceID = wmi::get_string(table_entry, "DeviceID");
		if (!_strcmpi(DeviceID.c_str(), pnp.pnp_id.c_str()))
		{
			found = 1;
			break;
		}
		table_entry = wmi::next_entry(table, table_entry);
	}
	wmi::close_table(table);

	if (!found)
	{
		port.blk_info = 20;
		port.blk  = 2;
		return;
	}

	found           = 0;
	table           = wmi::open_table("SELECT Antecedent FROM Win32_USBControllerDevice where Antecedent is not NULL");
	table_entry     = wmi::next_entry(table, 0);
	while (table_entry)
	{
		std::string Antecedent = wmi::get_string(table_entry, "Antecedent");

		for (size_t pos = Antecedent.find("\\\\"); pos != std::string::npos; pos = Antecedent.find("\\\\", pos + 1)) {
			Antecedent.replace(pos, 2, "\\");
		}
		if (strstr(Antecedent.c_str(), pnp.pnp_id.c_str()))
		{
			found = 1;
			break;
		}
		table_entry = wmi::next_entry(table, table_entry);
	}
	wmi::close_table(table);

	if (found == 0)
	{
		port.blk_info = 21;
		port.blk = 1;
		return;
	}
}

static void scan::validate_pnp_device(PORT_DEVICE_INFO &port, DEVICE_INFO &dev, PNP_ADAPTER &pnp)
{
	using namespace pci;

	switch (class_code(dev.cfg))
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
		validate_usb_adapters(port, pnp);
		break;
	default:
		break;
	}
}

