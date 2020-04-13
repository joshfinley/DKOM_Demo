#include "KernelObjectHelpers.h"

PLIST_ENTRY FindKernelModule(_In_ PDRIVER_OBJECT DriverObject, _In_ UNICODE_STRING DriverName) {
	// Logic can be similarly used for finding the PsLoadedModuleList head. ntoskrnl.exe is always the head
	PKLDR_DATA_TABLE_ENTRY pThisModule = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	PLIST_ENTRY KModEntry = { nullptr };

	// https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/find-kernel-module-address-todo
	// Get PsLoadedModuleList address
	for (PLIST_ENTRY pListEntry = pThisModule->InLoadOrderLinks.Flink;
		pListEntry != &pThisModule->InLoadOrderLinks; pListEntry = pListEntry->Flink)
	{
		PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
			pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (RtlEqualUnicodeString(&DriverName, &pEntry->BaseDllName, true)) {
			// Ntoskrnl is always the first entry in the list
			// so the previous entry is the PsLoadedModuleList
			// check if the found pointer belongs to Ntoskrnl module
			KModEntry = pListEntry;
		}
	}

	return KModEntry;
}