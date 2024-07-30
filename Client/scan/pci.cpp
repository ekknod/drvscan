#include "scan.h"

namespace scan
{
	static void dumpcfg(std::vector<PORT_DEVICE_INFO> &devices);

	static void check_faceit(PORT_DEVICE_INFO &port);
	static void check_driver(PORT_DEVICE_INFO &port);
	static void check_hidden(PORT_DEVICE_INFO &port);
	static void check_gummybear(BOOL advanced, PORT_DEVICE_INFO &port);
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

BOOL is_xilinx(config::Pci &cfg)
{
	config::pci::PCIE pci = cfg.get_pci();

	if (!pci.cap_on)
		return 0;

	return (pci.link.cap.link_cap_l0s_exit_latency() + pci.link.cap.link_cap_l1_exit_latency() + pci.link.cap.link_cap_aspm_support()) == 15;
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
		}
	}
}

static void scan::check_faceit(PORT_DEVICE_INFO &port)
{
	for (auto& dev : port.devices)
	{
		if (is_xilinx(dev.cfg))
		{
			port.blk_info = 3;
			port.blk = 1;
			break;
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
	for (auto& dev : port.devices)
	{
		//
		// test if device has forced command register
		// it's under advanced flag because its really risky.
		// https://github.com/ufrisk/pcileech-fpga/blob/master/PCIeSquirrel/src/pcileech_pcie_cfg_a7.sv#L210C1-L210C16
		//
		if (advanced)
		{
			auto pci = dev.cfg.get_pci();

			BOOL can_do_test=0;
			if (pci.cap_on)
			{
				if (pci.link.status.link_status_link_width() <= 4)
				{
					can_do_test = 1;
				}
			}

			if (!can_do_test && !pci.cap_on)
			{
				auto pci2 = port.self.cfg.get_pci();

				if (pci2.link.status.link_status_link_width() <= 4)
				{
					can_do_test = 1;
				}
			}


			if (can_do_test)
			{
				auto cmd = dev.cfg.command();

				if (!cmd.serr_enable())
				{
					WORD temp_data = cmd.raw | (1 << 8);

					cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, 0x04, temp_data);

					if (cl::pci::read<WORD>(dev.bus, dev.slot, dev.func, 0x04) == temp_data)
					{
						cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, 0x04, cmd.raw);
					}
					else
					{
						port.blk = 2;
						port.blk_info = 23;
						return;
					}
				}
			}
		
		}

		//
		// test shadow cfg CFGTLP PCIE WRITE ENABLE == 0
		// by writing config space [R/W] register dev_ctrl_ur_reporting
		//
		auto pci = dev.cfg.get_pci();
		BOOL rw_tst = 0;
		if (pci.cap_on)
		{
			rw_tst = 1;
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
		}

		//
		// test [R/W] from non PCI capabilities by enabling/or disabling PME
		// potentially dangerous, need find better approach.
		//
		auto pm = dev.cfg.get_pm();
		if (!rw_tst && pm.cap_on && pm.cap.pm_cap_pmesupport())
		{
			WORD data = pm.csr.pm_csr_pme_enabled() ?
				pm.csr.raw & ~(1 << 8) :
				pm.csr.raw | (1 << 8);

			cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, pm.base_ptr + 0x04, data);
			if (cl::pci::read<WORD>(dev.bus, dev.slot, dev.func, pm.base_ptr + 0x04) == data)
			{
				cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, pm.base_ptr + 0x04, pm.csr.raw);
			}
			else
			{
				port.blk = 2;
				port.blk_info = 23;
				return;
			}
		}

		//
		// test shadow cfg CFGTLP PCIE WRITE ENABLE == 1
		// by writing config space [RO] cap headers
		//
		BOOL ro_test = 0;
		if (dev.cfg.status().capabilities_list())
		{
			ro_test = 1;
			BYTE off = cl::pci::read<BYTE>(dev.bus, dev.slot, dev.func, 0x34);
			BOOL found = 0;
			while (1)
			{
				if (off == 0)
					break;

				config::pci::CapHdr cap{};
				cap.raw = cl::pci::read<WORD>(dev.bus, dev.slot, dev.func, off);

				if (cap.raw == 0)
				{
					break;
				}


				cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, off, 0);
				if (cl::pci::read<WORD>(dev.bus, dev.slot, dev.func, off) != cap.raw)
				{
					cl::pci::write<WORD>(dev.bus, dev.slot, dev.func, off, cap.raw);
					found = 1;
					break;
				}

				BYTE next = cap.cap_next_ptr();
				if (next == 0)
				{
					break;
				}

				off = next;
			}

			//
			// shadow cfg caps found
			//
			if (found)
			{
				port.blk = 2;
				port.blk_info = 23;
				return;
			}
		}

		//
		// test shadow cfg CFGTLP PCIE WRITE ENABLE == 1
		// by writing config space [RO] ext cap headers
		//
		if (!ro_test)
		{
			BOOL found = 0;
			WORD off = 0x100;
			while (1)
			{
				config::pci::CapExtHdr cap{};
				cap.raw = cl::pci::read<DWORD>(dev.bus, dev.slot, dev.func, off);

				if (cap.raw == 0)
				{
					break;
				}

				cl::pci::write<DWORD>(dev.bus, dev.slot, dev.func, off, 0);
				if (cl::pci::read<DWORD>(dev.bus, dev.slot, dev.func, off) != cap.raw)
				{
					cl::pci::write<DWORD>(dev.bus, dev.slot, dev.func, off, cap.raw);
					found = 1;
					break;
				}

				WORD next = cap.cap_next_ptr();
				if (next == 0)
				{
					break;
				}
				off = next;
			}

			//
			// shadow cfg caps found
			//
			if (found)
			{
				port.blk = 2;
				port.blk_info = 23;
				return;
			}
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

// void filter_pci_cfg(config::Pci &cfg);;
static void scan::dumpcfg(std::vector<PORT_DEVICE_INFO> &devices)
{
	for (auto& entry : devices)
	{
		for (auto& dev : entry.devices)
		{
			printf("[%d:%d:%d] [%02X:%02X]", dev.bus, dev.slot, dev.func, *(WORD*)(dev.cfg.raw), *(WORD*)(dev.cfg.raw + 0x02));
			BYTE config[0x1000];
			memcpy(config, dev.cfg.raw, sizeof(dev.cfg.raw));
			cl::pci::read(dev.bus, dev.slot, dev.func, 0x100, config + 0x100, 0xF00);
			PrintPcieConfiguration(config, sizeof(config));

			// auto full = config::Pci{};
			// memcpy(full.raw, config, 0x1000);
			// filter_pci_cfg(full);

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

/*
void filter_pci_cfg(config::Pci &cfg)
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

*/

