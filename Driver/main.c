#include <intrin.h>
#include <ntifs.h>

typedef ULONG_PTR QWORD;

#define IOCTL_READMEMORY 0xECAC00
#define IOCTL_READMEMORY_PROCESS 0xECAC02

PDRIVER_OBJECT gDriverObject;
PDEVICE_OBJECT gDeviceObject;
UNICODE_STRING gDeviceName;
UNICODE_STRING gDosDeviceName;

#pragma pack(1)
typedef struct {
	PVOID src;
	PVOID dst;
	ULONG_PTR length;
	ULONG virtual_memory;
} DRIVER_READMEMORY;

#pragma pack(1)
typedef struct {
	PVOID src;
	PVOID dst;
	ULONG_PTR length;
	ULONG pid;
} DRIVER_READMEMORY_PROCESS;

NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);


#pragma warning (disable: 4996)

NTSTATUS IoControl(PDEVICE_OBJECT DriverObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(DriverObject);

	//
	// irp->IoStatus.Information : WE NEED CHANGE THIS DEPENDING ON CONTEXT
	//

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	VOID *buffer = (VOID*)irp->AssociatedIrp.SystemBuffer;

	if (!stack)
		goto E0;

	ULONG ioctl_code = stack->Parameters.DeviceIoControl.IoControlCode;

	if (ioctl_code == IOCTL_READMEMORY)
	{
		DRIVER_READMEMORY *mem = (DRIVER_READMEMORY*)buffer;

		MM_COPY_ADDRESS va;

		va.VirtualAddress = mem->src;


		PVOID virtual_buffer = ExAllocatePool(NonPagedPool, mem->length);


		__try {
			irp->IoStatus.Status = MmCopyMemory( virtual_buffer, va, mem->length, mem->virtual_memory + 1, &mem->length);
		} __except (1)
		{
			//
			// do nothing
			//
			irp->IoStatus.Status = STATUS_INVALID_ADDRESS;
		}

		if (irp->IoStatus.Status == STATUS_SUCCESS)
		{
			memcpy(mem->dst, virtual_buffer, mem->length);
		}

		ExFreePool(virtual_buffer);

		irp->IoStatus.Information = sizeof(DRIVER_READMEMORY);


	}

	else if (ioctl_code == IOCTL_READMEMORY_PROCESS)
	{
		DRIVER_READMEMORY_PROCESS *mem = (DRIVER_READMEMORY_PROCESS*)buffer;

		__try {
			PEPROCESS eprocess;
			irp->IoStatus.Status = PsLookupProcessByProcessId((HANDLE)mem->pid, &eprocess);
			if (irp->IoStatus.Status == 0)
			{
				irp->IoStatus.Status = MmCopyVirtualMemory( eprocess, mem->src, PsGetCurrentProcess(), mem->dst, mem->length, KernelMode, &mem->length);
			}
		} __except (1)
		{
			//
			// do nothing
			//
			irp->IoStatus.Status = STATUS_INVALID_ADDRESS;
		}

		irp->IoStatus.Information = sizeof(DRIVER_READMEMORY_PROCESS);
	}
E0:
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


VOID
DriverUnload(
	_In_ struct _DRIVER_OBJECT* DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);

	IoDeleteSymbolicLink(&gDosDeviceName);
	IoDeleteDevice(gDeviceObject);
}

NTSTATUS dummy_io(PDEVICE_OBJECT DriverObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(DriverObject);
	irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	gDriverObject = DriverObject;

	RtlInitUnicodeString(&gDeviceName, L"\\Device\\memdriver");
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &gDeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &gDeviceObject);
	if (status != STATUS_SUCCESS)
		return status;

	RtlInitUnicodeString(&gDosDeviceName, L"\\DosDevices\\memdriver");
	status = IoCreateSymbolicLink(&gDosDeviceName, &gDeviceName);
	if (status != STATUS_SUCCESS)
	{
		IoDeleteDevice( gDeviceObject );
		return status;
	}
	SetFlag(gDeviceObject->Flags, DO_BUFFERED_IO);
	for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
	{
		DriverObject->MajorFunction[t] = dummy_io;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	DriverObject->DriverUnload = DriverUnload;
	ClearFlag(gDeviceObject->Flags, DO_DEVICE_INITIALIZING);
	return status;
}
