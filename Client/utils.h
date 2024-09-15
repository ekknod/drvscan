#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
#include <stdlib.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <iostream>

#define PAGE_SHIFT 12l
#define PAGE_SIZE  0x1000
#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))

typedef ULONG_PTR QWORD;

typedef struct {
	std::string             path;
	std::string             name;
	QWORD                   base;
	QWORD                   size;
} FILE_INFO ;

typedef struct {
	DWORD                  id;
	std::string            name;
	std::vector<FILE_INFO> modules;
} PROCESS_INFO;

typedef struct {
	QWORD                  address;
	QWORD                  length;
	DWORD                  tag;
} BIGPOOL_INFO;

typedef struct {
	DWORD                  pid;
	BYTE                   object_type;
	BYTE                   flags;
	QWORD                  handle;
	QWORD                  object;
	ACCESS_MASK            access_mask;
} HANDLE_INFO;

#define GET_BIT(data, bit) ((data >> bit) & 1)
#define GET_BITS(data, high, low) ((data >> low) & ((1 << (high - low + 1)) - 1))
namespace pe
{
	inline QWORD get_nt_headers(QWORD image)
	{
		return *(DWORD*)(image + 0x03C) + image;
	}

	namespace nt
	{
		inline WORD get_section_count(QWORD nt)
		{
			return *(WORD*)(nt + 0x06);
		}

		inline BOOL is_wow64(QWORD nt)
		{
			return *(WORD*)(nt + 0x4) == 0x014c;
		}

		inline PIMAGE_SECTION_HEADER get_image_sections(QWORD nt)
		{
			return is_wow64(nt) ? (PIMAGE_SECTION_HEADER)(nt + 0x00F8) :
				(PIMAGE_SECTION_HEADER)(nt + 0x0108);
		}

		inline PIMAGE_SECTION_HEADER get_image_section(QWORD nt, PCSTR name)
		{
			PIMAGE_SECTION_HEADER section = get_image_sections(nt);
			for (WORD i = 0; i < get_section_count(nt); i++)
			{
				if (!_strcmpi((const char *)section[i].Name, name))
					return &section[i];
			}
			return 0;
		}

		inline QWORD get_optional_header(QWORD nt)
		{
			return nt + 0x18;
		}
	}


	namespace optional
	{
		inline DWORD get_entry_point(QWORD opt)
		{
			return *(DWORD*)(opt + 0x10);
		}

		inline DWORD get_image_size(QWORD opt)
		{
			return *(DWORD*)(opt + 0x38);
		}

		inline DWORD get_headers_size(QWORD opt)
		{
			return *(DWORD*)(opt + 0x3C);
		}

		inline DWORD get_checksum(QWORD opt)
		{
			return *(DWORD*)(opt + 0x40);
		}

		inline QWORD get_image_base(QWORD opt)
		{
			QWORD nt = opt - 0x18;
			return nt::is_wow64(nt) ? *(DWORD*)(opt + 0x1C) : *(QWORD*)(opt + 0x18);
		}

		inline IMAGE_DATA_DIRECTORY *get_data_directory(QWORD opt, int index)
		{
			QWORD nt = opt - 0x18;
			return nt::is_wow64(nt) ?
				(IMAGE_DATA_DIRECTORY*)(opt + 0x60 + (index * sizeof(IMAGE_DATA_DIRECTORY))) :
				(IMAGE_DATA_DIRECTORY*)(opt + 0x70 + (index * sizeof(IMAGE_DATA_DIRECTORY)));
		}
	}
}



namespace config {
	const BYTE MAX_CAPABILITIES = 0x16;
	const BYTE MAX_EXTENDED_CAPABILITIES = 0x2F;

	namespace pci {

		struct Command {
			WORD raw;
			BYTE memory_space_enable( )                   { return GET_BIT(raw, 1); };
			BYTE bus_master_enable( )                     { return GET_BIT(raw, 2); };
			BYTE special_cycle_enable( )                  { return GET_BIT(raw, 3); };
			BYTE memory_write( )                          { return GET_BIT(raw, 4); };
			BYTE vga_enable( )                            { return GET_BIT(raw, 5); };
			BYTE parity_err_enable( )                     { return GET_BIT(raw, 6); };
			BYTE serr_enable( )                           { return GET_BIT(raw, 8); };
			BYTE b2b_enable( )                            { return GET_BIT(raw, 9); };
			BYTE interrupt_disable( )                     { return GET_BIT(raw, 10); };
		};

		struct Status {
			WORD raw;
			BYTE parity_error( )                          { return GET_BIT(raw, 15); }
			BYTE signaled_error( )                        { return GET_BIT(raw, 14); }
			BYTE master_abort( )                          { return GET_BIT(raw, 13); }
			BYTE target_abort( )                          { return GET_BIT(raw, 12); }
			BYTE signaled_abort( )                        { return GET_BIT(raw, 11); }
			BYTE devsel_timing( )                         { return GET_BITS(raw, 10, 9); }
			BYTE master_parity_error( )                   { return GET_BIT(raw, 8); }
			BYTE fast_b2b_capable( )                      { return GET_BIT(raw, 7); }
			BYTE c66_capable( )                           { return GET_BIT(raw, 5); }
			BYTE capabilities_list( )                     { return GET_BIT(raw, 4); }
			BYTE interrupt_status( )                      { return GET_BIT(raw, 3); }
		};

		struct HeaderType {
			BYTE raw;
			//
			// multifunc_device = multiple devices under same bus
			//
			BYTE multifunc_device()                       { return GET_BIT(raw, 7); }
			//
			// 0: endpoint, 1: port, 2: card reader, ?: invalid
			//
			BYTE type()                                   { return GET_BITS(raw, 6, 0); }
		};

		struct CapHdr {
			WORD raw;
			BYTE cap_id()                                 { return GET_BITS(raw, 7, 0); }
			BYTE cap_next_ptr()                           { return GET_BITS(raw, 15, 8); }
		};

		struct CapExtHdr {
			DWORD raw;
			BYTE cap_id()                                 { return GET_BITS(raw, 7, 0); }
			WORD cap_next_ptr()                           { return GET_BITS(raw, 31, 20); }
		};

		struct PmCap {
			WORD raw;
			BYTE pm_cap_version()                         { return GET_BITS(raw, 2, 0); }
			BYTE pm_cap_pme_clock()                       { return GET_BIT(raw, 3); }
			BYTE pm_cap_dsi()                             { return GET_BIT(raw, 5); }
			BYTE pm_cap_auxcurrent()                      { return GET_BITS(raw, 8, 6); }
			BYTE pm_cap_d1support()                       { return GET_BIT(raw, 9); }
			BYTE pm_cap_d2support()                       { return GET_BIT(raw, 10); }
			BYTE pm_cap_pmesupport()                      { return GET_BITS(raw, 15, 11); }
		};

		struct PmCsr {
			WORD raw;
			BYTE pm_csr_power_state()                     { return GET_BITS(raw, 1, 0); }
			BYTE pm_csr_nosoftrst()                       { return GET_BIT(raw, 3); }
			BYTE pm_csr_dynamic_data()                    { return GET_BIT(raw, 4); }
			BYTE pm_csr_pme_enabled()                     { return GET_BIT(raw, 8); }
			BYTE pm_csr_data_select()                     { return GET_BITS(raw, 12, 9); }
			BYTE pm_csr_data_scale()                      { return GET_BITS(raw, 14, 13); }
			BYTE pm_csr_pme_status()                      { return GET_BIT(raw, 15); }
		};

		struct MsiCap {
			WORD raw;
			BYTE msi_enabled()                            { return GET_BIT(raw, 0); }
			BYTE msi_cap_multimsgcap()                    { return GET_BITS(raw, 3, 1); }
			BYTE msi_cap_multimsg_extension()             { return GET_BITS(raw, 6, 4); }
			BYTE msi_cap_64_bit_addr_capable()            { return GET_BIT(raw, 7); }
			BYTE msi_cap_per_vector_masking_capable()     { return GET_BIT(raw, 8); }
		};

		struct MsixCap {
			WORD raw;
			BYTE msix_enabled()                            { return GET_BIT(raw, 15); }
		};

		struct PciCap {
			WORD raw;
			BYTE pcie_cap_capability_version()            { return GET_BITS(raw, 3, 0); }
			BYTE pcie_cap_device_port_type()              { return GET_BITS(raw, 7, 4); }
			BYTE pcie_cap_slot_implemented()              { return GET_BIT(raw, 8); }
			BYTE pcie_cap_interrupt_message_number()      { return GET_BITS(raw, 13, 9); }
		};

		struct DevCap {
			DWORD raw;
			BYTE dev_cap_max_payload_supported ()         { return GET_BITS(raw, 2, 0); }
			BYTE dev_cap_phantom_functions_support ()     { return GET_BITS(raw, 4, 3); }
			BYTE dev_cap_ext_tag_supported ()             { return GET_BIT(raw, 5); }
			BYTE dev_cap_endpoint_l0s_latency ()          { return GET_BITS(raw, 8, 6); }
			BYTE dev_cap_endpoint_l1_latency ()           { return GET_BITS(raw, 11, 9); }
			BYTE dev_cap_role_based_error ()              { return GET_BIT(raw, 15); }
			BYTE dev_cap_enable_slot_pwr_limit_value ()   { return GET_BITS(raw, 25, 18); }
			BYTE dev_cap_enable_slot_pwr_limit_scale ()   { return GET_BITS(raw, 27, 26); }
			BYTE dev_cap_function_level_reset_capable ()  { return GET_BIT(raw, 28); }
		};

		struct DevCap2 {
			DWORD raw;
			BYTE cpl_timeout_ranges_supported()           { return GET_BITS(raw, 3, 0); }
			BYTE cpl_timeout_disable_supported()          { return GET_BIT(raw, 4); }
			BYTE ltr_mechanism_supported()                { return GET_BIT(raw, 11); }
		};

		struct LinkCap {
			DWORD raw;
			BYTE link_cap_max_link_speed()                { return GET_BITS(raw, 3, 0); }
			BYTE link_cap_max_link_width()                { return GET_BITS(raw, 9, 4); }
			BYTE link_cap_aspm_support()                  { return GET_BITS(raw, 11, 10); }
			BYTE link_cap_l0s_exit_latency()              { return GET_BITS(raw, 14, 12); }
			BYTE link_cap_l1_exit_latency()               { return GET_BITS(raw, 17, 15); }
			BYTE link_cap_clock_power_management()        { return GET_BITS(raw, 19, 18); }
			BYTE link_cap_aspm_optionality()              { return GET_BIT(raw, 22); }
			BYTE link_cap_rsvd_23()                       { return GET_BITS(raw, 23, 19); }
		};

		struct SlotCap {
			DWORD raw;
			BYTE attention_button_present()               { return GET_BIT(raw, 0); }
			BYTE power_controller_present()               { return GET_BIT(raw, 1); }
			BYTE mrl_sensor_present()                     { return GET_BIT(raw, 2); }
			BYTE attention_indicator_present()            { return GET_BIT(raw, 3); }
			BYTE power_indicator_present  ()              { return GET_BIT(raw, 4); }
			BYTE hot_plug_surprise()                      { return GET_BIT(raw, 5); }
			BYTE hot_plug_capable()                       { return GET_BIT(raw, 6); }
			BYTE slot_power_limit()                       { return GET_BITS(raw, 14, 7); }
			BYTE slot_power_scale()                       { return GET_BITS(raw, 16, 15); }
			BYTE electromechanical_lock_present()         { return GET_BIT(raw, 17); }
			BYTE no_command_completed_support()           { return GET_BIT(raw, 18); }
			WORD physical_slot_number()                   { return GET_BITS(raw, 31, 19); }

		};

		struct DevControl {
			WORD raw;
			BYTE dev_ctrl_corr_err_reporting()            { return GET_BIT(raw, 0); }
			BYTE dev_ctrl_non_fatal_reporting()           { return GET_BIT(raw, 1); }
			BYTE dev_ctrl_fatal_err_reporting()           { return GET_BIT(raw, 2); }
			BYTE dev_ctrl_ur_reporting()                  { return GET_BIT(raw, 3); }
			BYTE dev_ctrl_relaxed_ordering()              { return GET_BIT(raw, 4); }
			BYTE dev_ctrl_max_payload_size()              { return GET_BITS(raw, 7, 5); }
			BYTE dev_ctrl_ext_tag_default()               { return GET_BIT(raw, 8); }
			BYTE dev_ctrl_phantom_func_enable()           { return GET_BIT(raw, 9); }
			BYTE dev_ctrl_aux_power_enable()              { return GET_BIT(raw, 10); }
			BYTE dev_ctrl_enable_no_snoop()               { return GET_BIT(raw, 11); }
			BYTE dev_ctrl_max_read_request_size()         { return GET_BITS(raw, 14, 12); }
			BYTE dev_ctrl_cfg_retry_status_enable()       { return GET_BIT(raw, 15); }
		};

		struct DevStatus {
			WORD raw;
			BYTE correctable_error_detected()             { return GET_BIT(raw, 0); }
			BYTE non_fatal_error_detected()               { return GET_BIT(raw, 1); }
			BYTE fatal_error_detected()                   { return GET_BIT(raw, 2); }
			BYTE unsupported_request_detected()           { return GET_BIT(raw, 3); }
			BYTE aux_power_detected()                     { return GET_BIT(raw, 4); }
			BYTE transactions_pending()                   { return GET_BIT(raw, 5); }
		};

		struct DevControl2 {
			WORD raw;
			BYTE obff_enable()                            { return GET_BIT(raw, 0); }
			BYTE latency_tolerance_reporting()            { return GET_BIT(raw, 1); }
			BYTE completion_timeout_disable()             { return GET_BIT(raw, 2); }
			BYTE completion_timeout_value()               { return GET_BIT(raw, 3); }
		};

		struct DevStatus2 {
			WORD raw;
			BYTE correctable_error_detected()             { return GET_BIT(raw, 0); }
			BYTE non_fatal_error_detected()               { return GET_BIT(raw, 1); }
			BYTE fatal_error_detected()                   { return GET_BIT(raw, 2); }
			BYTE unsupported_request_detected()           { return GET_BIT(raw, 3); }
			BYTE aux_power_detected()                     { return GET_BIT(raw, 4); }
			BYTE transactions_pending()                   { return GET_BIT(raw, 5); }
		};

		struct LinkStatus {
			WORD raw;
			BYTE link_status_link_speed()                 { return GET_BITS(raw, 3, 0); }
			BYTE link_status_link_width()                 { return GET_BITS(raw, 9, 4); }
			BYTE link_status_slot_clock_config()          { return GET_BIT(raw, 12); }
		};

		struct LinkControl {
			WORD raw;
			BYTE link_aspmc()                             { return GET_BIT(raw, 1); }
			BYTE link_control_rcb()                       { return GET_BIT(raw, 3); }
			BYTE link_disable()                           { return GET_BIT(raw, 4); }
			BYTE link_retrain()                           { return GET_BIT(raw, 5); }
			BYTE link_common_control_configuration()      { return GET_BIT(raw, 6); }
			BYTE link_extended_synch()                    { return GET_BIT(raw, 7); }
			BYTE link_enable_clock_power_management()     { return GET_BIT(raw, 8); }
			BYTE link_hardware_autonomous_width_disable() { return GET_BIT(raw, 9); }
		};

		struct SlotStatus {
			WORD raw;
		};

		struct SlotControl {
			WORD raw;
		};

		struct LinkCap2 {
			DWORD raw;
			BYTE link_cap2_linkspeedssupported()          { return GET_BITS(raw, 3, 1); }
		};

		struct LinkControl2 {
			WORD raw;
			BYTE link_ctrl2_target_link_speed()           { return GET_BITS(raw, 3, 0); }
			BYTE link_ctrl2_entercompliance()             { return GET_BIT(raw, 4); }
			BYTE link_ctrl2_hw_autonomous_speed_disable() { return GET_BIT(raw, 5); }
			BYTE link_ctrl2_deemphasis()                  { return GET_BIT(raw, 6); }
			BYTE link_ctrl2_transmitmargin()              { return GET_BIT(raw, 7); }
			BYTE link_ctrl2_entermodifiedcompliance()     { return GET_BIT(raw, 10); }
			BYTE link_ctrl2_compliancesos()               { return GET_BIT(raw, 11); }
		};

		struct LinkStatus2 {
			WORD raw;
			BYTE link_status2_deemphasislvl() { return GET_BIT(raw, 0); }
		};

		struct PM {
			BOOL   cap_on;
			BYTE   base_ptr;
			CapHdr hdr;
			PmCap  cap;
			PmCsr  csr;
		};

		struct MSI {
			BOOL cap_on;
			BYTE base_ptr;
			CapHdr hdr;
			MsiCap cap;
		};

		struct MSIX {
			BOOL cap_on;
			BYTE base_ptr;
			CapHdr hdr;
			MsixCap cap;
		};

		struct DEV {
			DevCap cap;
			DevControl control;
			DevStatus status;
		};

		struct DEV2 {
			DevCap2 cap;
			DevControl2 control;
			DevStatus2 status;
		};

		struct LINK {
			LinkCap cap;
			LinkControl control;
			LinkStatus status;
		};

		struct SLOT {
			SlotCap cap;
			SlotControl control;
			SlotStatus status;
		};

		struct LINK2 {
			LinkCap2 cap;
			LinkControl2 control;
			LinkStatus2 status;
		};

		struct PCIE {
			BOOL cap_on;
			BYTE base_ptr;
			CapHdr hdr;
			PciCap cap;
			DEV dev;
			DEV2 dev2;
			LINK link;
			SLOT slot;
			LINK2 link2;
		};

		struct DSN {
			BOOL cap_on;
			WORD base_ptr;
			CapExtHdr hdr;
			UINT64    serial;
		};

		struct EmtpyExtPcieCap {
			BOOL cap_on;
			WORD base_ptr;
			CapExtHdr hdr;
		};

		struct EmtpyPcieCap {
			BOOL cap_on;
			BYTE base_ptr;
			CapHdr hdr;
		};
	}

	struct Pci {
		unsigned char raw[0x1000];
		Pci() { memset(raw, 0, sizeof(raw)); }

		Pci(unsigned char *buffer, int size)
		{
			if (size > sizeof(raw)) size = sizeof(raw);
			memcpy(raw, buffer, size);
		}

		auto vendor_id() -> WORD { return *(WORD*)(raw + 0x00); }
		auto device_id() -> WORD { return *(WORD*)(raw + 0x02); }

		auto subsystem_vendor_id() -> WORD { return *(WORD*)(raw + 0x2C); }
		auto subsystem_device_id() -> WORD { return *(WORD*)(raw + 0x2E); }

		auto command() -> pci::Command { return *(pci::Command*)(raw + 0x04); }
		auto status() -> pci::Status { return  *(pci::Status*)(raw + 0x06); }
		auto header() -> pci::HeaderType { return  *(pci::HeaderType*)(raw + 0x0E); }

		auto bar(int index) -> DWORD {
			auto ptr = (DWORD*)(raw + 0x10);

			if (index > 6)
			{
				return 0;
			}

			if (header().type() == 1 && index > 2)
			{
				return 0;
			}

			return ptr[index];
		}

		//
		// type1
		//
		auto bus_number() -> BYTE {
			if ( header().type() == 0 ) return 0;
			return *(unsigned char*)(raw + 0x18);
		}

		auto secondary_bus() -> BYTE {
			if ( header().type() == 0 ) return 0;
			return *(unsigned char*)(raw + 0x19);
		}

		auto subordinate_bus() -> BYTE {
			if ( header().type() == 0 ) return 0;
			return *(unsigned char*)(raw + 0x1A);
		}

		auto revision_id() -> BYTE { return *(BYTE*)(raw + 0x08); }
		auto class_code() -> DWORD { return ( *(BYTE*)(raw + 0x09 + 2) << 16 ) | ( *(BYTE*)(raw + 0x09 + 1) << 8 ) | *(BYTE*)(raw + 0x09); }
		auto interrupt_line() -> BYTE { return *(BYTE*)(raw + 0x3C); }
		auto interrupt_pin() -> BYTE { return *(BYTE*)(raw + 0x3D); }
		auto capabilities_ptr() -> BYTE { return *(BYTE*)(raw + 0x34); }

		auto get_capability_by_id(BYTE id) -> BYTE
		{
			BYTE off = capabilities_ptr();
			if (off == 0)
			{
				return 0;
			}

			while (1)
			{
				auto cap = *(pci::CapHdr*)((raw + off));

				if (cap.raw == 0)
				{
					break;
				}

				if (cap.cap_id() == id)
				{
					return off;
				}

				BYTE next = cap.cap_next_ptr();
				if (next == 0)
				{
					break;
				}

				off = next;
			}
			return 0;
		}

		auto get_pm() -> pci::PM {
			auto cap = get_capability_by_id(0x01);
			auto res = pci::PM{};
			if (cap != 0)
			{
				UINT64 val = *(UINT64*)(raw + cap);
				res.cap_on   = val != 0;
				res.base_ptr = cap;
				res.hdr.raw  = val & 0xFFFF;
				res.cap.raw  = (val >> 16) & 0xFFFF;
				res.csr.raw  = (val >> 32) & 0xFFFF;
			}
			return res;
		}

		auto get_msi() -> pci::MSI {
			auto cap = get_capability_by_id(0x05);
			auto res = pci::MSI{};
			if (cap != 0)
			{
				DWORD val = *(DWORD*)(raw + cap);
				res.cap_on   = val != 0;
				res.base_ptr = cap;
				res.hdr.raw  = val & 0xFFFF;
				res.cap.raw  = (val >> 16) & 0xFFFF;
			}
			return res;
		}

		auto get_msix() -> pci::MSIX {
			auto cap = get_capability_by_id(0x11);
			auto res = pci::MSIX{};
			if (cap != 0)
			{
				DWORD val = *(DWORD*)(raw + cap);
				res.cap_on   = val != 0;
				res.base_ptr = cap;
				res.hdr.raw  = val & 0xFFFF;
				res.cap.raw  = (val >> 16) & 0xFFFF;
			}
			return res;
		}

		auto get_pci() -> pci::PCIE {
			auto cap = get_capability_by_id(0x10);
			auto res = pci::PCIE{};
			if (cap != 0)
			{
				DWORD pci              = *(DWORD*)(raw + cap);
				QWORD dev              = *(QWORD*)(raw + cap + 0x04);
				QWORD link             = *(QWORD*)(raw + cap + 0x0C);

				res.cap_on            = pci != 0;
				res.base_ptr          = cap;
				res.hdr.raw           = (pci & 0xFFFF);
				res.cap.raw           = (pci >> 16) & 0xFFFF;

				res.dev.cap.raw       = (dev & 0xFFFFFFFF);
				res.dev.control.raw   = (dev >> 32) & 0xFFFF;
				res.dev.status.raw    = (dev >> 48) & 0xFFFF;

				res.link.cap.raw      = (link & 0xFFFFFFFF);
				res.link.control.raw  = (link >> 32) & 0xFFFF;
				res.link.status.raw   = (link >> 48) & 0xFFFF;

				if (res.cap.pcie_cap_capability_version() > 1)
				{
					QWORD slot =  *(QWORD*)(raw + cap + 0x0C + 0x08);
					QWORD dev2 =  *(QWORD*)(raw + cap + 0x04 + 0x20);
					QWORD link2 = *(QWORD*)(raw + cap + 0x0C + 0x20);

					res.dev2.cap.raw = (dev2 & 0xFFFFFFFF);
					res.dev2.control.raw = (dev2 >> 32) & 0xFFFF;
					res.dev2.status.raw = (dev2 >> 48) & 0xFFFF;

					res.slot.cap.raw = (slot & 0xFFFFFFFF);
					res.slot.control.raw = (slot >> 32) & 0xFFFF;
					res.slot.status.raw = (slot >> 48) & 0xFFFF;

					res.link2.cap.raw = (link2 & 0xFFFFFFFF);
					res.link2.control.raw = (link2 >> 32) & 0xFFFF;
					res.link2.status.raw = (link2 >> 48) & 0xFFFF;
				}
			}
			return res;
		}

		auto get_ext_capability_by_id(BYTE id) -> WORD
		{
			WORD off = 0x100;
			while (1)
			{
				auto cap = *(pci::CapExtHdr*)((raw + off));

				if (cap.raw == 0)
				{
					break;
				}

				if (cap.cap_id() == id)
				{
					return off;
				}

				WORD next = cap.cap_next_ptr();
				if (next == 0)
				{
					break;
				}
				off = next;
			}
			return 0;
		}

		auto get_dsn() -> pci::DSN {
			auto cap = get_ext_capability_by_id(0x03);
			auto res = pci::DSN{};
			if (cap != 0)
			{
				auto hdr = *(DWORD*)(raw + cap);
				res.cap_on   = hdr != 0;
				res.base_ptr = cap;
				res.hdr.raw  = hdr;
				res.serial   = *(UINT64*)(raw + cap + 0x04);
			}
			return res;
		}

		auto get_empty_extended_cap(BYTE id) -> pci::EmtpyExtPcieCap {
			auto cap = get_ext_capability_by_id(id);
			auto res = pci::EmtpyExtPcieCap{};
			if (cap != 0)
			{
				auto hdr = *(DWORD*)(raw + cap);
				res.cap_on   = hdr != 0;
				res.base_ptr = cap;
				res.hdr.raw  = hdr;
			}
			return res;
		}

		auto get_empty_cap(BYTE id) -> pci::EmtpyPcieCap {
			auto cap = get_capability_by_id(id);
			auto res = pci::EmtpyPcieCap{};
			if (cap != 0)
			{
				auto hdr = *(WORD*)(raw + cap);
				res.cap_on   = hdr != 0;
				res.base_ptr = cap;
				res.hdr.raw  = hdr;
			}
			return res;
		}
	} ;
}

typedef enum {
    PciExpressEndpoint = 0,
    PciExpressLegacyEndpoint,
    PciExpressRootPort = 4,
    PciExpressUpstreamSwitchPort,
    PciExpressDownstreamSwitchPort,
    PciExpressToPciXBridge,
    PciXToExpressBridge,
    PciExpressRootComplexIntegratedEndpoint,
    PciExpressRootComplexEventCollector
} PCI_EXPRESS_DEVICE_TYPE;

std::vector<FILE_INFO>    get_kernel_modules(void);
std::vector<FILE_INFO>    get_user_modules(DWORD pid);
std::vector<PROCESS_INFO> get_system_processes();
std::vector<BIGPOOL_INFO> get_kernel_allocations(void);
std::vector<HANDLE_INFO>  get_system_handle_information(void);

PVOID LoadFileEx(PCSTR path, DWORD *out_len);
PVOID LoadImageEx(PCSTR path, DWORD *out_len, QWORD current_base = 0, QWORD memory_image=0);
void  FreeImageEx(PVOID ImageBase);

typedef struct
{
	unsigned char bus, slot, func;
	std::string   pnp_id;
} PNP_ADAPTER;

namespace wmi
{
	QWORD                    open_table(PCSTR name);
	void                     close_table(QWORD table);
	QWORD                    next_entry(QWORD table, QWORD prev);

	std::string              get_string(QWORD table_entry, PCSTR value);
	int                      get_int(QWORD table_entry, PCSTR value);
	bool                     get_bool(QWORD table_entry, PCSTR value);
}

std::vector<PNP_ADAPTER> get_pnp_adapters();

#endif /* UTILS_H */

