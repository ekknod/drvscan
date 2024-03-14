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

typedef ULONG_PTR QWORD;

#pragma pack(push, 1)
typedef struct {
	std::string             path;
	std::string             name;
	QWORD                   base;
	QWORD                   size;
} FILE_INFO ;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	DWORD                  process_id;
	std::vector<FILE_INFO> process_modules;
} PROCESS_INFO;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	QWORD                  address;
	QWORD                  length;
	DWORD                  tag;
} BIGPOOL_INFO;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	DWORD                  pid;
	BYTE                   object_type;
	BYTE                   flags;
	QWORD                  handle;
	QWORD                  object;
	ACCESS_MASK            access_mask;
} HANDLE_INFO;
#pragma pack(pop)

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

namespace pci
{
	inline WORD vendor_id(PVOID cfg)         { return *(WORD*)((PBYTE)cfg + 0x00); }
	inline WORD device_id(PVOID cfg)         { return *(WORD*)((PBYTE)cfg + 0x02); }
	inline WORD command(PVOID cfg)           { return *(WORD*)((PBYTE)cfg + 0x04); }
	inline WORD status(PVOID cfg)            { return *(WORD*)((PBYTE)cfg + 0x04 + 0x02); }
	inline BYTE revision_id(PVOID cfg)       { return *(BYTE*)((PBYTE)cfg + 0x08); }
	inline DWORD* bar(PVOID cfg)             { return (DWORD*)((PBYTE)cfg + 0x10); }
	inline BYTE header_type(PVOID cfg)       { return *(BYTE*)((PBYTE)cfg + 0x0E); }

	//
	// bridge stuff
	//
	namespace type1
	{
		inline BYTE bus_number(PVOID cfg) { return *(BYTE*)((PBYTE)cfg + 0x18); }
		inline BYTE secondary_bus_number(PVOID cfg) { return *(BYTE*)((PBYTE)cfg + 0x18 + 1); }
		inline BYTE subordinate_bus_number(PVOID cfg) { return *(BYTE*)((PBYTE)cfg + 0x18 + 2); }
	}

	//
	// printf("%06X\n", classcode);
	//
	inline DWORD class_code(PVOID cfg)
	{
		BYTE *cc = (BYTE*)((PBYTE)cfg + 0x09);

		DWORD dw = 0;
		((unsigned char*)&dw)[0] = cc[0];
		((unsigned char*)&dw)[1] = cc[1];
		((unsigned char*)&dw)[2] = cc[2];

		return dw;
	}

	inline WORD subsys_vendor_id(PVOID cfg) { return *(WORD*)((PBYTE)cfg + 0x2C); }
	inline WORD subsys_id(PVOID cfg) { return *(WORD*)((PBYTE)cfg + 0x2C + 0x02); }
	inline BYTE capabilities_ptr(PVOID cfg) { return *(BYTE*)((PBYTE)cfg + 0x34); }
	inline BYTE interrupt_line(PVOID cfg) { return *(BYTE*)((PBYTE)cfg + 0x3C); }
	inline BYTE interrupt_pin(PVOID cfg) { return *(BYTE*)((PBYTE)cfg + 0x3C+1); }

	namespace pm
	{
		namespace cap
		{
		inline BYTE pm_cap_on(PVOID pm) { return ((DWORD*)pm)[0] != 0; }
		inline BYTE pm_cap_next_ptr(PVOID pm) { return ((unsigned char*)(pm))[1]; }
		inline BYTE pm_cap_id(PVOID pm) { return GET_BITS(((DWORD*)pm)[0], 7, 0); }
		inline BYTE pm_cap_version(PVOID pm) { return GET_BITS(((DWORD*)pm)[0], 18, 16); }
		inline BYTE pm_cap_pme_clock(PVOID pm) { return GET_BIT(((DWORD*)pm)[0], 19); }
		inline BYTE pm_cap_rsvd_04(PVOID pm) { return GET_BIT(((DWORD*)pm)[0], 20); }
		inline BYTE pm_cap_dsi(PVOID pm) { return GET_BIT(((DWORD*)pm)[0], 21); }
		inline BYTE pm_cap_auxcurrent(PVOID pm) { return GET_BITS(((DWORD*)pm)[0], 24, 22); }
		inline BYTE pm_cap_d1support(PVOID pm) { return GET_BIT(((DWORD*)pm)[0], 25); }
		inline BYTE pm_cap_d2support(PVOID pm) { return GET_BIT(((DWORD*)pm)[0], 26); }
		inline BYTE pm_cap_pmesupport(PVOID pm) { return GET_BITS(((DWORD*)pm)[0], 31, 27); }
		}

		namespace csr
		{
		inline BYTE pm_csr_nosoftrst(PVOID pm) { return GET_BITS(((DWORD*)pm)[1], 3, 2)!=0; }
		inline BYTE pm_csr_bpccen(PVOID pm) { return GET_BIT(((DWORD*)pm)[1], 23); }
		inline BYTE pm_csr_b2b3s(PVOID pm) { return GET_BIT(((DWORD*)pm)[1], 22); }

		inline BYTE pm_csr_power_state(PVOID pm) { return GET_BITS(((DWORD*)pm)[1], 1, 0); }
		inline BYTE pm_csr_dynamic_data(PVOID pm) { return GET_BIT(((DWORD*)pm)[1], 4); }
		inline BYTE pm_csr_reserved(PVOID pm) { return GET_BITS(((DWORD*)pm)[1], 7, 5); }
		inline BYTE pm_csr_pme_enabled(PVOID pm) { return GET_BIT(((DWORD*)pm)[1], 8); }
		inline BYTE pm_csr_data_select(PVOID pm) { return GET_BITS(((DWORD*)pm)[1], 12, 9); }
		inline BYTE pm_csr_data_scale(PVOID pm) { return GET_BITS(((DWORD*)pm)[1], 14, 13); }
		inline BYTE pm_csr_pme_status(PVOID pm) { return GET_BIT(((DWORD*)pm)[1], 15); }
		}
	}

	namespace msi
	{
		namespace cap
		{
		inline BYTE msi_cap_on(PVOID msi) { return ((DWORD*)msi)[0] != 0; }
		inline BYTE msi_cap_nextptr(PVOID msi) { return ((unsigned char*)(msi))[1]; }
		inline BYTE msi_cap_id(PVOID msi) { return GET_BITS(((DWORD*)msi)[0], 7, 0); }
		inline BYTE msi_cap_multimsgcap(PVOID msi) { return GET_BITS(((DWORD*)msi)[0], 19, 17); }
		inline BYTE msi_cap_multimsg_extension(PVOID msi) { return GET_BITS(((DWORD*)msi)[0], 22, 20); }
		inline BYTE msi_cap_64_bit_addr_capable(PVOID msi) { return GET_BIT(((DWORD*)msi)[0], 23); }
		inline BYTE msi_cap_per_vector_masking_capable(PVOID msi) { return GET_BIT(((DWORD*)msi)[0], 24); }
		}
	}

	namespace pcie
	{
		namespace cap
		{
		inline BYTE pcie_cap_on(PVOID pcie) { return ((DWORD*)pcie)[0] != 0; }
		inline BYTE pcie_cap_capability_id(PVOID pcie) { return GET_BITS(((DWORD*)pcie)[0], 7, 0); }
		inline BYTE pcie_cap_nextptr(PVOID pcie) { return GET_BITS(((DWORD*)pcie)[0], 15, 8); }
		inline BYTE pcie_cap_capability_version(PVOID pcie) { return GET_BITS(((DWORD*)pcie)[0], 19, 16); }
		inline BYTE pcie_cap_device_port_type(PVOID pcie) { return GET_BITS(((DWORD*)pcie)[0], 23, 20); }
		inline BYTE pcie_cap_slot_implemented(PVOID pcie) { return GET_BIT(((DWORD*)pcie)[0], 24); }
		inline BYTE pcie_cap_interrupt_message_number(PVOID pcie) { return GET_BITS(((DWORD*)pcie)[0], 29,25); }
		}
	}

	namespace dev
	{
		namespace cap
		{
		inline BYTE dev_cap_max_payload_supported(PVOID dev) { return GET_BITS(((DWORD*)dev)[0], 2, 0); }
		inline BYTE dev_cap_phantom_functions_support(PVOID dev) { return GET_BITS(((DWORD*)dev)[0], 4, 3); }
		inline BYTE dev_cap_ext_tag_supported(PVOID dev) { return GET_BIT(((DWORD*)dev)[0], 5); }
		inline BYTE dev_cap_endpoint_l0s_latency(PVOID dev) { return GET_BITS(((DWORD*)dev)[0], 8, 6); }
		inline BYTE dev_cap_endpoint_l1_latency(PVOID dev) { return GET_BITS(((DWORD*)dev)[0], 11, 9); }
		inline BYTE dev_cap_role_based_error(PVOID dev) { return GET_BIT(((DWORD*)dev)[0], 15); }
		inline BYTE dev_cap_enable_slot_pwr_limit_value(PVOID dev) { return GET_BITS(((DWORD*)dev)[0], 25, 18); }
		inline BYTE dev_cap_enable_slot_pwr_limit_scale(PVOID dev) { return GET_BITS(((DWORD*)dev)[0], 27, 26); }
		inline BYTE dev_cap_function_level_reset_capable(PVOID dev) { return GET_BIT(((DWORD*)dev)[0], 28); }
		}
		namespace ctrl
		{
		inline BYTE dev_ctrl_corr_err_reporting(PVOID dev) { return GET_BIT(((DWORD*)dev)[1], 0); }
		inline BYTE dev_ctrl_non_fatal_reporting(PVOID dev) { return GET_BIT(((DWORD*)dev)[1], 1); }
		inline BYTE dev_ctrl_fatal_err_reporting(PVOID dev) { return GET_BIT(((DWORD*)dev)[1], 2); }
		inline BYTE dev_ctrl_ur_reporting(PVOID dev) { return GET_BIT(((DWORD*)dev)[1], 3); }
		inline BYTE dev_ctrl_relaxed_ordering(PVOID dev) { return GET_BIT(((DWORD*)dev)[1], 4); }
		inline BYTE dev_ctrl_max_payload_size(PVOID dev) { return GET_BITS(((DWORD*)dev)[1], 7, 5); }
		inline BYTE dev_ctrl_ext_tag_default(PVOID dev) { return GET_BIT(((DWORD*)dev)[1], 8); }
		inline BYTE dev_ctrl_phantom_func_enable(PVOID dev) { return GET_BIT(((DWORD*)dev)[1], 9); }
		inline BYTE dev_ctrl_aux_power_enable(PVOID dev) { return GET_BIT(((DWORD*)dev)[1], 10); }
		inline BYTE dev_ctrl_enable_no_snoop(PVOID dev) { return GET_BIT(((DWORD*)dev)[1], 11); }
		inline BYTE dev_ctrl_max_read_request_size(PVOID dev) { return GET_BITS(((DWORD*)dev)[1], 14, 12); }
		inline BYTE dev_ctrl_cfg_retry_status_enable(PVOID dev) { return GET_BIT(((DWORD*)dev)[1], 15); }
		}

		namespace cap2
		{
			inline BYTE cpl_timeout_ranges_supported(PVOID dev) { return GET_BITS(((DWORD*)dev)[8], 3, 0); }
			inline BYTE cpl_timeout_disable_supported(PVOID dev) { return GET_BIT(((DWORD*)dev)[8], 4); }
		}

		namespace ctrl2
		{
			inline BYTE completiontimeoutvalue(PVOID dev) { return GET_BITS(((DWORD*)dev)[9], 3, 0); }
			inline BYTE completiontimeoutdisable(PVOID dev) { return GET_BIT(((DWORD*)dev)[9], 4); }
		}
	}

	namespace link
	{
		namespace cap
		{
		inline BYTE link_cap_max_link_speed(PVOID link)         { return GET_BITS(((DWORD*)link)[0], 3, 0); }
		inline BYTE link_cap_max_link_width(PVOID link)         { return GET_BITS(((DWORD*)link)[0], 9, 4); }
		inline BYTE link_cap_aspm_support(PVOID link)           { return GET_BITS(((DWORD*)link)[0], 11, 10); }
		inline BYTE link_cap_l0s_exit_latency(PVOID link)       { return GET_BITS(((DWORD*)link)[0], 14, 12); }
		inline BYTE link_cap_l1_exit_latency(PVOID link)        { return GET_BITS(((DWORD*)link)[0], 17, 15); }
		inline BYTE link_cap_clock_power_management(PVOID link) { return GET_BITS(((DWORD*)link)[0], 19, 18); }
		inline BYTE link_cap_aspm_optionality(PVOID link)       { return GET_BIT(((DWORD*)link)[0], 22); }
		inline BYTE link_cap_rsvd_23(PVOID link)                { return GET_BITS(((DWORD*)link)[0], 23, 19); }
		}

		namespace ctrl
		{
		inline BYTE link_control_rcb(PVOID link)                { return GET_BIT(((DWORD*)link)[1], 3); }
		}

		namespace status
		{
		inline PVOID __status(PVOID link) { return (PVOID)((PBYTE)link+sizeof(DWORD)+sizeof(WORD)); }

		typedef union _PCI_EXPRESS_LINK_STATUS_REGISTER {

		    struct {

			USHORT LinkSpeed:4;
			USHORT LinkWidth:6;
			USHORT Undefined:1;
			USHORT LinkTraining:1;
			USHORT SlotClockConfig:1;
			USHORT DataLinkLayerActive:1;
			USHORT Rsvd:2;
		    } DUMMYSTRUCTNAME;

		    USHORT AsUSHORT;

		} PCI_EXPRESS_LINK_STATUS_REGISTER, *PPCI_EXPRESS_LINK_STATUS_REGISTER;

		inline WORD link_status_slot_clock_config(PVOID link)
		{
			PVOID link_status = __status(link);
			return ((PPCI_EXPRESS_LINK_STATUS_REGISTER)link_status)->SlotClockConfig;
		}

		inline WORD link_speed(PVOID link)
		{
			PVOID link_status = __status(link);
			return ((PPCI_EXPRESS_LINK_STATUS_REGISTER)link_status)->LinkSpeed;
		}

		inline WORD link_width(PVOID link)
		{
			PVOID link_status = __status(link);
			return ((PPCI_EXPRESS_LINK_STATUS_REGISTER)link_status)->LinkWidth;
		}

		}

		namespace cap2
		{
			inline BYTE linkspeedssupported(PVOID link) { return GET_BITS(((DWORD*)link)[8], 3, 1); }
		}

		namespace ctrl2
		{
		inline BYTE link_ctrl2_target_link_speed(PVOID link) { return GET_BITS(((DWORD*)link)[9], 3, 0); }
		inline BYTE entercompliance(PVOID link) { return GET_BIT(((DWORD*)link)[9], 4); }
		inline BYTE link_ctrl2_hw_autonomous_speed_disable(PVOID link) { return GET_BIT(((DWORD*)link)[9], 5); }
		inline BYTE link_ctrl2_deemphasis(PVOID link) { return GET_BIT(((DWORD*)link)[9], 6); }
		inline BYTE transmitmargin(PVOID link) { return GET_BITS(((DWORD*)link)[9], 9, 7); }
		inline BYTE entermodifiedcompliance(PVOID link) { return GET_BIT(((DWORD*)link)[9], 10); }
		inline BYTE compliancesos(PVOID link) { return GET_BIT(((DWORD*)link)[9], 11); }
		}

		namespace status2
		{
		inline BYTE deemphasis(PVOID link) { return GET_BITS(((DWORD*)link)[9], 15, 12); }
		inline BYTE deemphasislvl(PVOID link) { return GET_BIT(((DWORD*)link)[9], 16); }
		inline BYTE equalizationcomplete(PVOID link) { return GET_BIT(((DWORD*)link)[9], 17); }
		inline BYTE equalizationphase1successful(PVOID link) { return GET_BIT(((DWORD*)link)[9], 18); }
		inline BYTE equalizationphase2successful(PVOID link) { return GET_BIT(((DWORD*)link)[9], 19); }
		inline BYTE equalizationphase3successful(PVOID link) { return GET_BIT(((DWORD*)link)[9], 20); }
		inline BYTE linkequalizationrequest(PVOID link) { return GET_BIT(((DWORD*)link)[9], 21); }
		}
	}

	namespace dsn
	{
		inline BYTE dsn_cap_on(PVOID dsn) { return *(DWORD*)(dsn) != 0; }
		inline WORD dsn_cap_nextptr(PVOID dsn) { return ((WORD*)dsn)[1] >> 4; }
		inline BYTE dsn_cap_id(PVOID dsn) { return *(BYTE*)(dsn) ; }
	}

	inline PVOID get_capabilities(PVOID cfg)
	{
		if (capabilities_ptr(cfg) == 0)
		{
			return 0;
		}
		return (PVOID)((PBYTE)cfg + capabilities_ptr(cfg));
	}

	inline PVOID get_pm(PVOID cfg)
	{
		PVOID cap_ptr = get_capabilities(cfg);

		if (cap_ptr == 0)
		{
			return 0;
		}
		while (1)
		{
			if (pm::cap::pm_cap_id(cap_ptr) == 0x01)
			{
				break;
			}
			if (pm::cap::pm_cap_next_ptr(cap_ptr) == 0)
			{
				return 0;
			}
			cap_ptr = (PVOID)((PBYTE)cfg + pm::cap::pm_cap_next_ptr(cap_ptr));
		}
		return cap_ptr;

	}
	inline PVOID get_msi(PVOID cfg)
	{
		PVOID cap_ptr = get_capabilities(cfg);
		if (cap_ptr == 0)
		{
			return 0;
		}
		while (1)
		{
			if (msi::cap::msi_cap_id(cap_ptr) == 0x05)
			{
				break;
			}
			if (msi::cap::msi_cap_nextptr(cap_ptr) == 0)
			{
				return 0;
			}
			cap_ptr = (PVOID)((PBYTE)cfg + msi::cap::msi_cap_nextptr(cap_ptr));
		}
		return cap_ptr;
	}
	inline PVOID get_pcie(PVOID cfg)
	{
		PVOID cap_ptr = get_capabilities(cfg);

		if (cap_ptr == 0)
		{
			return 0;
		}
		while (1)
		{
			if (pcie::cap::pcie_cap_capability_id(cap_ptr) == 0x10)
			{
				break;
			}
			if (pcie::cap::pcie_cap_nextptr(cap_ptr) == 0)
			{
				return 0;
			}
			cap_ptr = (PVOID)((PBYTE)cfg + pcie::cap::pcie_cap_nextptr(cap_ptr));
		}
		return cap_ptr;
	}
	inline PVOID get_dev(PVOID cfg)
	{
		PVOID pcie = get_pcie(cfg);
		if (pcie == 0)
		{
			return 0;
		}
		return (PVOID)((PBYTE)pcie + sizeof(DWORD));
	}
	inline PVOID get_link(PVOID cfg)
	{
		PVOID pcie = get_pcie(cfg);
		if (pcie == 0)
		{
			return 0;
		}
		return (PVOID)((PBYTE)pcie + 0xC);
	}
	inline PVOID get_dsn(PVOID cfg) { return (PVOID)((PBYTE)cfg + 0x100); }
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


namespace wmi
{
	QWORD                    open_table(PCSTR name);
	void                     close_table(QWORD table);
	QWORD                    next_entry(QWORD table, QWORD prev);

	std::string              get_string(QWORD table_entry, PCSTR value);
	int                      get_int(QWORD table_entry, PCSTR value);
	bool                     get_bool(QWORD table_entry, PCSTR value);
}

typedef struct
{
	unsigned char bus, slot, func;
	std::string   pnp_id;
} PNP_ADAPTER;

std::vector<PNP_ADAPTER> get_pnp_adapters();


#endif /* UTILS_H */

