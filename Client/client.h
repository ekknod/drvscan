#ifndef KM_H
#define KM_H

#include "utils.h"

inline void FontColor(WORD color=0x07) { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color); }

#define LOG_RED(...) \
printf("[drvscan] "); \
FontColor(4); \
printf(__VA_ARGS__); \
FontColor(7); \

#define LOG_YELLOW(...) \
printf("[drvscan] "); \
FontColor(14); \
printf(__VA_ARGS__); \
FontColor(7); \

#define PRINT_RED(...) \
FontColor(4); \
printf(__VA_ARGS__); \
FontColor(7); \

#define PRINT_GREEN(...) \
FontColor(2); \
printf(__VA_ARGS__); \
FontColor(7); \

#define PRINT_BLUE(...) \
FontColor(3); \
printf(__VA_ARGS__); \
FontColor(7); \


#define LOG_DEBUG(...) \
FontColor(3); \
printf("[debug] "); \
FontColor(7); \
printf(__VA_ARGS__); \

#define DEBUG
#define LOG(...) printf("[drvscan] "  __VA_ARGS__)
#ifdef DEBUG
#define DEBUG_LOG(...) printf("[drvscan] " __VA_ARGS__)
#else
#define DEBUG_LOG(...) // __VA_ARGS__
#endif

typedef struct {
	QWORD                 Type;
	QWORD                 PhysicalStart;
	QWORD                 VirtualStart;
	UINT64                NumberOfPages;
	UINT64                Attribute;
} EFI_MEMORY_DESCRIPTOR;

namespace cl
{
	class client
	{
	public:
		//
		// initialize object
		//
		virtual BOOL  initialize(void) = 0;
		virtual BOOL  read_kernel(QWORD address, PVOID buffer, QWORD length) = 0;
		virtual BOOL  write_kernel(QWORD address, PVOID buffer, QWORD length) = 0;
	};
}


typedef struct
{
	QWORD PhysicalStart;
	QWORD NumberOfPages;
} EFI_PAGE_TABLE_ALLOCATION;

typedef struct {
	QWORD virtual_address;
	QWORD physical_address;
	DWORD size;
} EFI_MODULE_INFO;

namespace cl
{
	BOOL initialize(void);
	void terminate(void);

	QWORD get_physical_address(QWORD virtual_address);
	QWORD get_virtual_address(QWORD physical_address);

	QWORD get_pci_driver_object(void);
	QWORD get_acpi_driver_object(void);

	QWORD get_interrupt_object(DWORD index);

	namespace vm
	{
		BOOL read(DWORD pid, QWORD address, PVOID buffer, QWORD length);
		BOOL write(DWORD pid, QWORD address, PVOID buffer, QWORD length);
		template <typename t>
		t read(DWORD pid, QWORD address)
		{
			t b;
			if (!read(pid, address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}
		template <typename t>
		BOOL write(DWORD pid, QWORD address, t value)
		{
			return write(pid, address, &value, sizeof(t));
		}

		inline QWORD get_relative_address(DWORD pid, QWORD address, INT offset, INT instruction_size)
		{
			return (address + instruction_size) + vm::read<INT>(pid, address + offset);
		}
	}

	namespace km
	{
		BOOL read(QWORD address, PVOID buffer, QWORD length);
		BOOL write(QWORD address, PVOID buffer, QWORD length);

		template <typename t>
		t read(QWORD address)
		{
			t b;
			if (!read(address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}
		template <typename t>
		BOOL write(QWORD address, t value)
		{
			return write(address, &value, sizeof(t));
		}

		QWORD call(QWORD kernel_address, QWORD r1 = 0, QWORD r2 = 0, QWORD r3 = 0, QWORD r4 = 0, QWORD r5 = 0, QWORD r6 = 0, QWORD r7 = 0);
	}

	namespace io
	{
		BOOL read(QWORD address, PVOID buffer, QWORD length);
		BOOL write(QWORD address, PVOID buffer, QWORD length);

		template <typename t>
		t read(QWORD address)
		{
			t b;
			if (!read(address, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}
		template <typename t>
		BOOL write(QWORD address, t value)
		{
			return write(address, &value, sizeof(t));
		}
	}

	namespace pci
	{
		QWORD get_physical_address(ULONG bus, ULONG slot);
		BOOL  read(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD size);
		BOOL  write(BYTE bus, BYTE slot, BYTE func, DWORD offset, PVOID buffer, DWORD size);

		template <typename t>
		t read(BYTE bus, BYTE slot, BYTE func, DWORD offset)
		{
			t b;
			if (!read(bus, slot, func, offset, &b, sizeof(b)))
			{
				b = 0;
			}
			return b;
		}

		template <typename t>
		BOOL write(BYTE bus, BYTE slot, BYTE func, DWORD offset, t value)
		{
			return write(bus, slot,func, offset, &value, sizeof(t));
		}
	}

	namespace efi
	{
		//
		// get runtime pages allocated from efi
		//
		std::vector<EFI_MEMORY_DESCRIPTOR> get_memory_map();

		//
		// get list of efi runtime functions
		//
		std::vector<QWORD> get_runtime_table(void);
	}

	extern BOOL  kernel_access;
	extern QWORD ntoskrnl_base;
	extern std::vector<QWORD> global_export_list;

	extern QWORD kernel_memcpy_table;
	extern QWORD kernel_swapfn_table;
}

class DLL_EXPORT
{
	QWORD address;
public:
	DLL_EXPORT(QWORD address) : address(address)
	{
		cl::global_export_list.push_back((QWORD)&this->address);
	}
	operator QWORD () const { return address; }

};

#define NTOSKRNL_EXPORT(export_name) \
DLL_EXPORT export_name((QWORD)#export_name);

#define EXTERN_NTOSKRNL_EXPORT(export_name) \
extern DLL_EXPORT export_name;

#endif /* KM_H */

